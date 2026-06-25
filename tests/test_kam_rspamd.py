import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

import kam_rspamd


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "sample.cf"


class ConversionTests(unittest.TestCase):
    def test_convert_generates_lua_with_flags_headers_and_meta(self):
        converted, report = kam_rspamd.convert(
            FIXTURE.read_bytes(),
            "fixture://sample.cf",
            min_bytes=1,
            min_rules=1,
            external_symbols={"R_SPF_ALLOW"},
        )
        text = converted.decode()

        self.assertIn("local rules = {", text)
        self.assertIn("expression = [=[/foo[A-Za-z]/is]=]", text)
        self.assertIn("header = [=[Subject]=]", text)
        self.assertIn("expression = [=[(SAMPLE_BODY && SAMPLE_HEADER)]=]", text)
        self.assertIn("rspamd_expression.create", text)
        self.assertIn("rspamd_regexp.create", text)
        self.assertNotIn("register_regexp", text)
        self.assertNotIn("UNSUPPORTED", text)
        self.assertEqual(report["converted_rule_count"], 3)
        self.assertEqual(report["omitted_directives"], {"askdns": 1})
        self.assertIn("group = 'KAM'", text)

    def test_rejects_unbalanced_conditionals(self):
        with self.assertRaises(kam_rspamd.ConversionError):
            kam_rspamd.convert(b"ifplugin Example\nbody X /x/\n", "test", 1, 1)

    def test_drops_meta_with_unresolved_dependency(self):
        source = (
            b"body LOCAL /x/\n"
            b"meta GOOD (LOCAL && SPF_PASS)\n"
            b"meta BAD (LOCAL && MISSING)\n"
        )
        converted, report = kam_rspamd.convert(
            source,
            "test",
            min_bytes=1,
            min_rules=1,
            external_symbols={"R_SPF_ALLOW"},
        )
        text = converted.decode()

        self.assertIn('["GOOD"]', text)
        self.assertNotIn('["BAD"]', text)
        self.assertIn("[=[R_SPF_ALLOW]=]", text)
        self.assertIn(
            "rspamd_config:register_dependency('KAM_RULES_MODULE', dependency)",
            text,
        )
        self.assertEqual(report["external_dependencies"], ["R_SPF_ALLOW"])
        self.assertEqual(report["dropped_metas"], {"BAD": ["MISSING"]})

    def test_emits_body_subject_flags_and_global_hit_cap(self):
        source = (
            b"body WITH_SUBJECT /subject/\n"
            b"body WITHOUT_SUBJECT /body/\n"
            b"tflags WITHOUT_SUBJECT nosubject\n"
            b"uri COUNTED /example/\n"
            b"tflags COUNTED multiple maxhits=2\n"
        )
        converted, _ = kam_rspamd.convert(source, "test", 1, 1)
        text = converted.decode()

        with_subject = next(line for line in text.splitlines() if '["WITH_SUBJECT"]' in line)
        without_subject = next(line for line in text.splitlines() if '["WITHOUT_SUBJECT"]' in line)
        self.assertNotIn("nosubject = true", with_subject)
        self.assertIn("nosubject = true", without_subject)
        self.assertIn("local function add_matches", text)
        self.assertIn("rule.maxhits - total", text)

    def test_drops_rule_name_with_lua_metacharacters(self):
        source = (
            b'body FOO"]=os.execute(\'id\')--  /x/\n'
            b"body GOOD_RULE /y/\n"
            b"score GOOD_RULE 1.0\n"
        )
        converted, report = kam_rspamd.convert(source, "test", 1, 1)
        text = converted.decode()

        self.assertNotIn("os.execute", text)
        self.assertIn('["GOOD_RULE"]', text)
        self.assertEqual(report["omitted_directives"].get("invalid_name"), 1)

    def test_if_plugin_conditions(self):
        source = (
            b"if plugin(Mail::SpamAssassin::Plugin::FreeMail)\n"
            b"body IF_KNOWN /a/\nscore IF_KNOWN 1.0\nendif\n"
            b"if plugin(Mail::SpamAssassin::Plugin::Nope)\n"
            b"body IF_UNKNOWN /b/\nscore IF_UNKNOWN 1.0\nendif\n"
            b"if !plugin(Mail::SpamAssassin::Plugin::Nope)\n"
            b"body IF_NOTUNKNOWN /c/\nscore IF_NOTUNKNOWN 1.0\nendif\n"
        )
        converted, _ = kam_rspamd.convert(source, "test", 1, 1)
        text = converted.decode()

        self.assertIn('["IF_KNOWN"]', text)
        self.assertIn('["IF_NOTUNKNOWN"]', text)
        self.assertNotIn('["IF_UNKNOWN"]', text)

    def test_cli_writes_matching_report(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "kam.lua"
            report_path = Path(directory) / "report.json"
            subprocess.run(
                [
                    "python3",
                    str(ROOT / "kam_rspamd.py"),
                    "--input",
                    str(FIXTURE),
                    "--url",
                    "fixture://sample.cf",
                    "--output",
                    str(output),
                    "--report",
                    str(report_path),
                    "--min-bytes",
                    "1",
                    "--min-rules",
                    "1",
                ],
                check=True,
            )
            report = json.loads(report_path.read_text())
            self.assertEqual(hashlib.sha256(output.read_bytes()).hexdigest(), report["output_sha256"])
            self.assertEqual(output.stat().st_mode & 0o777, 0o644)
            self.assertEqual(report_path.stat().st_mode & 0o777, 0o644)

    def test_expected_sha256_rejects_wrong_source(self):
        source = b"body GOOD /x/\n"
        with self.assertRaisesRegex(kam_rspamd.ConversionError, "SHA-256 mismatch"):
            kam_rspamd.convert(source, "test", 1, 1, expected_sha256="0" * 64)

    def test_local_rules_merged_into_output(self):
        source = b"body UPSTREAM /up/\nscore UPSTREAM 1\n"
        local = b"rawbody LOCAL_RULE /(?:<br\\/?>){8}/mi\nscore LOCAL_RULE 2.0\n"
        converted, report = kam_rspamd.convert(
            source, "test", min_bytes=1, min_rules=2, local_rules=local
        )
        text = converted.decode()
        self.assertIn("UPSTREAM", text)
        self.assertIn("LOCAL_RULE", text)
        self.assertEqual(report["converted_rule_count"], 2)
        self.assertIsNotNone(report["local_rules_sha256"])

    def test_local_rules_excluded_from_source_sha_gate(self):
        # SHA gate must verify the pristine upstream source only, so the local
        # supplement never trips update-if-changed.sh's upstream-change check.
        source = b"body UPSTREAM /up/\nscore UPSTREAM 1\n"
        local = b"rawbody LOCAL_RULE /x/\nscore LOCAL_RULE 1\n"
        digest = hashlib.sha256(source).hexdigest()
        converted, report = kam_rspamd.convert(
            source, "test", min_bytes=1, min_rules=2,
            expected_sha256=digest, local_rules=local,
        )
        self.assertEqual(report["source_sha256"], digest)
        self.assertIn("LOCAL_RULE", converted.decode())

    def test_local_rules_none_leaves_report_field_null(self):
        _, report = kam_rspamd.convert(b"body X /x/\nscore X 1\n", "test", 1, 1)
        self.assertIsNone(report["local_rules_sha256"])

    def test_generated_runtime_disables_failed_regexps(self):
        converted, _ = kam_rspamd.convert(b"body BAD /(/\nscore BAD 1\n", "test", 1, 1)
        text = converted.decode()

        self.assertIn("if not data or not rule.re or rule.disabled then return 0 end", text)
        self.assertIn("rule.disabled = true", text)

    def test_header_modes_and_negation(self):
        source = (
            b"header ADDR_RULE From:addr =~ /evil/i\nscore ADDR_RULE 1.0\n"
            b"header NEG_RULE Subject !~ /ok/\nscore NEG_RULE 1.0\n"
        )
        converted, _ = kam_rspamd.convert(source, "test", 1, 1)
        text = converted.decode()

        addr = next(line for line in text.splitlines() if '["ADDR_RULE"]' in line)
        neg = next(line for line in text.splitlines() if '["NEG_RULE"]' in line)
        self.assertIn("header = [=[From]=]", addr)
        self.assertIn("header_mode = [=[addr]=]", addr)
        self.assertNotIn("negate = true", addr)
        self.assertIn("header = [=[Subject]=]", neg)
        self.assertIn("negate = true", neg)

    def test_multiple_tflag_emitted(self):
        source = b"body M /x/\ntflags M multiple\nscore M 1\n"
        converted, _ = kam_rspamd.convert(source, "test", 1, 1)
        line = next(l for l in converted.decode().splitlines() if '["M"]' in l)
        self.assertIn("multiple = true", line)

    def test_min_bytes_threshold(self):
        with self.assertRaisesRegex(kam_rspamd.ConversionError, "unexpectedly small"):
            kam_rspamd.convert(b"body X /x/\n", "test", min_bytes=10_000, min_rules=1)

    def test_min_rules_threshold(self):
        with self.assertRaisesRegex(kam_rspamd.ConversionError, "too few converted rules"):
            kam_rspamd.convert(b"# only a comment\n", "test", min_bytes=1, min_rules=3)

    def test_expected_sha256_rejects_malformed(self):
        # Distinct from the mismatch case: a non-hex / wrong-length value is
        # rejected before any comparison.
        with self.assertRaisesRegex(kam_rspamd.ConversionError, "64 hexadecimal"):
            kam_rspamd.convert(b"body X /x/\n", "test", 1, 1, expected_sha256="nothex")

    def test_generated_lua_carries_kam_license_and_credits(self):
        converted, _ = kam_rspamd.convert(FIXTURE.read_bytes(), "test", 1, 1)
        text = converted.decode()

        self.assertIn(
            "Copyright (c) 2022 Kevin A. McGrail and The McGrail Foundation", text
        )
        self.assertIn("Apache License, Version 2.0", text)
        self.assertIn("Karsten Bräckelmann", text)
        self.assertIn("Wolfgang Breyha", text)
        self.assertIn("The converter itself (rspamd-kam-rules) is MIT-licensed.", text)

    def test_generated_lua_carries_generation_date(self):
        converted, _ = kam_rspamd.convert(FIXTURE.read_bytes(), "test", 1, 1)
        text = converted.decode()
        self.assertRegex(text, r"-- Generated: \d{4}-\d{2}-\d{2} \(UTC\)")


class LuaStringTests(unittest.TestCase):
    """The injection defense: rule/symbol text is emitted as Lua long-bracket
    strings, and the bracket level must escalate past any closing sequence the
    value itself contains so embedded `]=]` can never break out of the string."""

    def test_plain_value_uses_single_level(self):
        self.assertEqual(kam_rspamd.lua_string("abc"), "[=[abc]=]")

    def test_escalates_when_value_contains_closing_sequence(self):
        self.assertEqual(kam_rspamd.lua_string("a]=]b"), "[==[a]=]b]==]")

    def test_does_not_escalate_for_a_harmless_longer_bracket(self):
        # "]==]" does not contain the level-1 closer "]=]", so level 1 is safe.
        self.assertEqual(kam_rspamd.lua_string("a]==]b"), "[=[a]==]b]=]")

    def test_escalates_past_multiple_levels(self):
        self.assertEqual(kam_rspamd.lua_string("]=]]==]"), "[===[]=]]==]]===]")


class HelperFunctionTests(unittest.TestCase):
    def test_read_symbol_file_skips_comments_and_blanks(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "symbols.txt"
            path.write_text(
                "# leading comment\nR_SPF_ALLOW\n  R_DKIM_ALLOW  \n\n#another\nKAM_FOO\n"
            )
            self.assertEqual(
                kam_rspamd.read_symbol_file(path),
                {"R_SPF_ALLOW", "R_DKIM_ALLOW", "KAM_FOO"},
            )

    def test_read_symbol_file_missing_path_is_empty(self):
        self.assertEqual(
            kam_rspamd.read_symbol_file(Path("/nonexistent/symbols.txt")), set()
        )

    def test_extract_regex_delimiters_and_flags(self):
        self.assertEqual(kam_rspamd.extract_regex("/foo/i"), "/foo/i")
        self.assertEqual(kam_rspamd.extract_regex("/a/ trailing"), "/a/")
        self.assertEqual(kam_rspamd.extract_regex("m|bar|is"), "m|bar|is")
        self.assertEqual(kam_rspamd.extract_regex("m,baz,"), "m,baz,")
        self.assertEqual(kam_rspamd.extract_regex(r"/a\/b/"), r"/a\/b/")
        self.assertIsNone(kam_rspamd.extract_regex("plain text"))
        self.assertIsNone(kam_rspamd.extract_regex(""))

    def test_meta_dependencies_extracts_symbols_only(self):
        self.assertEqual(
            kam_rspamd.meta_dependencies("( A && B || __C1 )"), {"A", "B", "__C1"}
        )
        self.assertEqual(kam_rspamd.meta_dependencies("(X + 2 >= 3)"), {"X"})

    def test_atomic_write_sets_mode_creates_parents_and_overwrites(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sub" / "out.bin"
            kam_rspamd.atomic_write(path, b"hello", 0o600)
            self.assertEqual(path.read_bytes(), b"hello")
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

            kam_rspamd.atomic_write(path, b"world")  # default 0o644, overwrite
            self.assertEqual(path.read_bytes(), b"world")
            self.assertEqual(path.stat().st_mode & 0o777, 0o644)
            # No leftover temp files from the atomic rename.
            self.assertEqual(list(path.parent.glob(".out.bin.*")), [])


if __name__ == "__main__":
    unittest.main()
