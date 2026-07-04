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


def map_header(mapdata: bytes) -> dict:
    """The jsonl map's first line: replacements + external_dependencies."""
    return json.loads(mapdata.decode().splitlines()[0])


def map_rules(mapdata: bytes) -> dict:
    """Index every rule object in the jsonl map by its symbol name. Rule data
    moved out of the Lua plugin into this map, so the converter's data-shape
    assertions check here; the Lua side only carries the static runtime."""
    rules = {}
    for line in mapdata.decode().splitlines()[1:]:
        if line.strip():
            obj = json.loads(line)
            rules[obj["name"]] = obj
    return rules


class ConversionTests(unittest.TestCase):
    def test_convert_generates_lua_with_flags_headers_and_meta(self):
        converted, mapdata, report = kam_rspamd.convert(
            FIXTURE.read_bytes(),
            "fixture://sample.cf",
            min_bytes=1,
            min_rules=1,
            external_symbols={"R_SPF_ALLOW"},
        )
        text = converted.decode()
        rules = map_rules(mapdata)

        # Rule data now lives in the map …
        self.assertEqual(rules["SAMPLE_BODY"]["expression"], "/foo[A-Za-z]/is")
        self.assertEqual(rules["SAMPLE_HEADER"]["header"], "Subject")
        self.assertEqual(rules["SAMPLE_META"]["expression"], "(SAMPLE_BODY && SAMPLE_HEADER)")
        # … while the thin plugin carries only the static runtime.
        self.assertIn("rspamd_expression.create", text)
        self.assertIn("rspamd_regexp.create", text)
        # Native fast path: regexps register into the combined Hyperscan DB and
        # are scanned via task:process_regexp.
        self.assertIn("register_regexp", text)
        self.assertIn("task:process_regexp", text)
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
        converted, mapdata, report = kam_rspamd.convert(
            source,
            "test",
            min_bytes=1,
            min_rules=1,
            external_symbols={"R_SPF_ALLOW"},
        )
        text = converted.decode()
        rules = map_rules(mapdata)

        self.assertIn("GOOD", rules)
        self.assertNotIn("BAD", rules)
        self.assertIn("R_SPF_ALLOW", map_header(mapdata)["external_dependencies"])
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
        converted, mapdata, _ = kam_rspamd.convert(source, "test", 1, 1)
        text = converted.decode()
        rules = map_rules(mapdata)

        # SA `nosubject` is a no-op under rspamd (sabody already excludes the
        # Subject), so it is intentionally NOT carried into the map.
        self.assertNotIn("nosubject", rules["WITH_SUBJECT"])
        self.assertNotIn("nosubject", rules["WITHOUT_SUBJECT"])
        self.assertTrue(rules["COUNTED"]["multiple"])
        self.assertEqual(rules["COUNTED"]["maxhits"], 2)
        # maxhits/multiple are applied via the regexp's max-hits cap, fed into
        # the combined-DB scan rather than counted in Lua.
        self.assertIn("set_max_hits", text)
        self.assertIn("rule.maxhits", text)

    def test_drops_rule_name_with_lua_metacharacters(self):
        source = (
            b'body FOO"]=os.execute(\'id\')--  /x/\n'
            b"body GOOD_RULE /y/\n"
            b"score GOOD_RULE 1.0\n"
        )
        converted, mapdata, report = kam_rspamd.convert(source, "test", 1, 1)
        rules = map_rules(mapdata)

        self.assertNotIn("os.execute", mapdata.decode())
        self.assertIn("GOOD_RULE", rules)
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
        _, mapdata, _ = kam_rspamd.convert(source, "test", 1, 1)
        rules = map_rules(mapdata)

        self.assertIn("IF_KNOWN", rules)
        self.assertIn("IF_NOTUNKNOWN", rules)
        self.assertNotIn("IF_UNKNOWN", rules)

    def test_cli_writes_matching_report(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "kam.lua"
            map_path = Path(directory) / "kam_rules.map"
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
                    "--map",
                    str(map_path),
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
            self.assertEqual(hashlib.sha256(map_path.read_bytes()).hexdigest(), report["map_sha256"])
            self.assertEqual(output.stat().st_mode & 0o777, 0o644)
            self.assertEqual(map_path.stat().st_mode & 0o777, 0o644)
            self.assertEqual(report_path.stat().st_mode & 0o777, 0o644)

    def test_expected_sha256_rejects_wrong_source(self):
        source = b"body GOOD /x/\n"
        with self.assertRaisesRegex(kam_rspamd.ConversionError, "SHA-256 mismatch"):
            kam_rspamd.convert(source, "test", 1, 1, expected_sha256="0" * 64)

    def test_local_rules_merged_into_output(self):
        source = b"body UPSTREAM /up/\nscore UPSTREAM 1\n"
        local = b"rawbody LOCAL_RULE /(?:<br\\/?>){8}/mi\nscore LOCAL_RULE 2.0\n"
        _, mapdata, report = kam_rspamd.convert(
            source, "test", min_bytes=1, min_rules=2, local_rules=local
        )
        rules = map_rules(mapdata)
        self.assertIn("UPSTREAM", rules)
        self.assertIn("LOCAL_RULE", rules)
        self.assertEqual(report["converted_rule_count"], 2)
        self.assertIsNotNone(report["local_rules_sha256"])

    def test_local_rules_excluded_from_source_sha_gate(self):
        # SHA gate must verify the pristine upstream source only, so the local
        # supplement never trips update-if-changed.sh's upstream-change check.
        source = b"body UPSTREAM /up/\nscore UPSTREAM 1\n"
        local = b"rawbody LOCAL_RULE /x/\nscore LOCAL_RULE 1\n"
        digest = hashlib.sha256(source).hexdigest()
        _, mapdata, report = kam_rspamd.convert(
            source, "test", min_bytes=1, min_rules=2,
            expected_sha256=digest, local_rules=local,
        )
        self.assertEqual(report["source_sha256"], digest)
        self.assertIn("LOCAL_RULE", map_rules(mapdata))

    def test_local_rules_none_leaves_report_field_null(self):
        _, _, report = kam_rspamd.convert(b"body X /x/\nscore X 1\n", "test", 1, 1)
        self.assertIsNone(report["local_rules_sha256"])

    def test_generated_runtime_disables_failed_regexps(self):
        converted, _, _ = kam_rspamd.convert(b"body BAD /(/\nscore BAD 1\n", "test", 1, 1)
        text = converted.decode()

        # A regexp that fails to compile is flagged disabled (never registered
        # into the DB) and scores nothing.
        self.assertIn("rule.disabled = true", text)
        self.assertIn("elseif rule.disabled then", text)

    def test_header_modes_and_negation(self):
        source = (
            b"header ADDR_RULE From:addr =~ /evil/i\nscore ADDR_RULE 1.0\n"
            b"header NEG_RULE Subject !~ /ok/\nscore NEG_RULE 1.0\n"
        )
        _, mapdata, _ = kam_rspamd.convert(source, "test", 1, 1)
        rules = map_rules(mapdata)

        self.assertEqual(rules["ADDR_RULE"]["header"], "From")
        self.assertEqual(rules["ADDR_RULE"]["header_mode"], "addr")
        self.assertNotIn("negate", rules["ADDR_RULE"])
        self.assertEqual(rules["NEG_RULE"]["header"], "Subject")
        self.assertTrue(rules["NEG_RULE"]["negate"])

    def test_multiple_tflag_emitted(self):
        source = b"body M /x/\ntflags M multiple\nscore M 1\n"
        _, mapdata, _ = kam_rspamd.convert(source, "test", 1, 1)
        self.assertTrue(map_rules(mapdata)["M"]["multiple"])

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

    def test_map_header_carries_kam_license_and_credits(self):
        # The KAM.cf credits + Apache notice travel WITH the rules, in the map
        # header (the data file users download), not baked into the lua runtime.
        _, mapdata, _ = kam_rspamd.convert(FIXTURE.read_bytes(), "test", 1, 1)
        header = json.loads(mapdata.decode().splitlines()[0])
        credits = "\n".join(header["_kam_credits"])
        license_text = "\n".join(header["_kam_license"])

        self.assertIn(
            "Copyright (c) 2022 Kevin A. McGrail and The McGrail Foundation", credits
        )
        self.assertIn("Karsten Bräckelmann", credits)
        self.assertIn("Wolfgang Breyha", credits)
        self.assertIn("Apache License, Version 2.0", license_text)
        self.assertIn("rspamd-kam-rules) itself is MIT-licensed.", license_text)

    def test_generated_lua_points_at_map_license(self):
        # The lua keeps only a short pointer, no baked rule provenance.
        converted, _, _ = kam_rspamd.convert(FIXTURE.read_bytes(), "test", 1, 1)
        text = converted.decode()
        self.assertIn("kam_rules.map header", text)
        self.assertIn("The converter itself (rspamd-kam-rules) is MIT-licensed.", text)

    def test_generated_lua_carries_project_header(self):
        converted, _, _ = kam_rspamd.convert(FIXTURE.read_bytes(), "test", 1, 1)
        text = converted.decode()
        self.assertIn(kam_rspamd.PROJECT_COPYRIGHT, text)
        self.assertIn(kam_rspamd.PROJECT_HOMEPAGE, text)
        # Pointer to our other Rspamd modules.
        self.assertIn(kam_rspamd.PROJECT_OVERVIEW, text)
        # Mini-howto travels in the file.
        self.assertIn("Quick start:", text)
        self.assertIn("systemctl reload rspamd", text)


class MapAndPluginSplitTests(unittest.TestCase):
    """The thin-plugin / data-map split: rule bodies live in the jsonl map, the
    Lua plugin reads it at config load to register symbols + compile the native
    combined-Hyperscan DB. A download-only HTTP watch refreshes the cache copy;
    applying it still needs a full reload (registration is config-load-only)."""

    def test_committed_lua_matches_generator(self):
        # The static dist/kam.lua must equal generate_lua() for its pinned source.
        # The daily CI regens map+report WITHOUT --emit-lua by design, so a
        # LUA_RUNTIME edit that forgets to re-emit would leave a stale committed
        # plugin and runtime tests would still pass against it. Guard the invariant.
        report = json.loads((ROOT / "dist" / "report.json").read_text())
        regenerated = kam_rspamd.generate_lua(
            report["source_url"], report["source_sha256"]
        )
        committed = (ROOT / "dist" / "kam.lua").read_bytes()
        self.assertEqual(
            committed, regenerated,
            "dist/kam.lua is stale — run `python3 kam_rspamd.py --emit-lua`",
        )
        self.assertEqual(report["output_sha256"], hashlib.sha256(committed).hexdigest())

    def test_map_header_carries_replacements_and_deps(self):
        _, mapdata, _ = kam_rspamd.convert(
            b"body LOCAL /x/\nmeta GOOD (LOCAL && SPF_PASS)\n",
            "test", 1, 1, external_symbols={"R_SPF_ALLOW"},
        )
        header = map_header(mapdata)
        self.assertEqual(header["_kam"], 1)
        # SPF_PASS -> R_SPF_ALLOW remap must travel in the map header, not the Lua.
        self.assertEqual(header["replacements"]["SPF_PASS"], "R_SPF_ALLOW")
        self.assertIn("R_SPF_ALLOW", header["external_dependencies"])

    def test_map_header_carries_project_metadata(self):
        _, mapdata, _ = kam_rspamd.convert(b"body A /a/\nscore A 1\n", "test", 1, 1)
        header = map_header(mapdata)
        self.assertEqual(header["_copyright"], kam_rspamd.PROJECT_COPYRIGHT)
        self.assertEqual(header["_homepage"], kam_rspamd.PROJECT_HOMEPAGE)
        self.assertEqual(header["_overview"], kam_rspamd.PROJECT_OVERVIEW)
        # Source provenance lives in the map (the file that tracks KAM.cf).
        self.assertEqual(header["_source_url"], "test")
        self.assertRegex(header["_source_sha256"], r"^[0-9a-f]{64}$")
        # Mini-howto carried as a list of lines.
        self.assertIn("Quick start:", header["_howto"])

    def test_map_is_jsonl_with_one_object_per_rule(self):
        _, mapdata, report = kam_rspamd.convert(
            b"body A /a/\nscore A 1\nbody B /b/\nscore B 1\n", "test", 1, 1
        )
        lines = [l for l in mapdata.decode().splitlines() if l.strip()]
        # header + one line per rule, every line a standalone JSON object.
        self.assertEqual(len(lines), 1 + report["converted_rule_count"])
        for line in lines:
            json.loads(line)

    def test_plugin_reads_bundled_map_at_config_load(self):
        converted, _, _ = kam_rspamd.convert(b"body A /a/\nscore A 1\n", "test", 1, 1)
        text = converted.decode()
        # Synchronous init load (registration + native DB compile is config-load-only).
        # Refactored into a read_file() helper; init prefers the cache copy then
        # falls back to the seed.
        self.assertIn("local function read_file(path)", text)
        self.assertIn("io.open(path, 'r')", text)
        self.assertIn("read_file(kam_cache_path)", text)
        self.assertIn("read_file(kam_map_path)", text)
        # C1 self-update: add_map watch is back, but DOWNLOAD-ONLY — it writes the
        # cache and never re-registers (which it can't post-load).
        self.assertIn("add_map", text)
        self.assertIn("type = 'callback'", text)
        self.assertIn("url = kam_map_url", text)
        # Atomic write: tmp + rename, never a direct write to the live cache path.
        self.assertIn("os.rename(tmp, kam_cache_path)", text)
        # All three paths/url overridable via the kam {} config block.
        self.assertIn("opts.map_path or", text)
        self.assertIn("opts.cache_path or", text)
        self.assertIn("opts.map_url or", text)
        # Plugin declares an empty rules table that the map fills — no baked data.
        self.assertIn("local rules = {}", text)

    def test_self_update_watch_is_download_only(self):
        converted, _, _ = kam_rspamd.convert(b"body A /a/\nscore A 1\n", "test", 1, 1)
        text = converted.decode()
        watch = text.split("add_map", 1)[1]
        # The watch callback must NOT register/compile rules — registration is
        # config-load-only, so a post-load register_regexp/register_symbol in the
        # callback would be a bug.
        callback = watch.split("callback = function(content)", 1)[1].split("})", 1)[0]
        self.assertNotIn("register_regexp", callback)
        self.assertNotIn("register_symbol", callback)
        self.assertNotIn("compile_rule", callback)
        # It writes the rspamd-writable cache, never the read-only seed.
        self.assertIn("kam_cache_path", callback)
        self.assertNotIn("kam_map_path", callback)
        # Default cache lives under /var/lib/rspamd (DBDIR, rspamd-user writable);
        # /etc/rspamd is root-owned and would EACCES.
        self.assertIn("/var/lib/rspamd/kam_rules.map", text)
        # Default map_url points at the published map.
        self.assertIn("/dist/kam_rules.map", text)

    def test_map_rule_names_restricted_to_symbol_charset(self):
        # The Lua loader re-validates names, but the emitter must never put a
        # name outside [A-Za-z0-9_] into the map in the first place.
        source = b'body FOO"]=os.execute(\'id\')--  /x/\nbody GOOD /y/\nscore GOOD 1\n'
        _, mapdata, _ = kam_rspamd.convert(source, "test", 1, 1)
        for name in map_rules(mapdata):
            self.assertRegex(name, r"\A[A-Za-z0-9_]+\Z")


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
        # Perl paired-bracket delimiters (m{} m() m[] m<>) close with a
        # different char and may nest (quantifiers like {2}); must not be
        # silently dropped by single-char-delimiter scanning.
        self.assertEqual(kam_rspamd.extract_regex("m{spam}i"), "m{spam}i")
        self.assertEqual(kam_rspamd.extract_regex("m{a{2}b}s"), "m{a{2}b}s")
        self.assertEqual(kam_rspamd.extract_regex("m(x)"), "m(x)")
        self.assertEqual(kam_rspamd.extract_regex("m[y]x"), "m[y]x")
        self.assertEqual(kam_rspamd.extract_regex("m<z> rest"), "m<z>")

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

    def test_active_lines_else_branch_and_comment_skip(self):
        # An inactive `if` block flips active in its `else`; comments/blanks drop.
        text = (
            "# comment\n"
            "\n"
            "if !plugin(Mail::SpamAssassin::Plugin::FreeMail)\n"
            "body INACTIVE /x/\n"
            "else\n"
            "body ACTIVE /y/\n"
            "endif\n"
        )
        names = [line.split()[1] for _, line in kam_rspamd.active_lines(text)]
        self.assertEqual(names, ["ACTIVE"])

    def test_active_lines_version_gates(self):
        # `if (version >= X)` evaluates against SA_VERSION (4.0): the modern
        # branch converts, the legacy `else` branch drops — and vice versa for
        # a future version gate. `if can(...)` stays a conservative drop.
        text = (
            "if (version >= 3.004002)\n"
            "body MODERN /x/\n"
            "else\n"
            "body LEGACY /y/\n"
            "endif\n"
            "if (version >= 4.000000)\n"
            "body SA4 /z/\n"
            "endif\n"
            "if (version > 4.000000)\n"
            "body FUTURE /f/\n"
            "else\n"
            "body CURRENT /c/\n"
            "endif\n"
            "if can(Mail::SpamAssassin::Plugin::OLEVBMacro::has_olemacro)\n"
            "body CAPGATED /g/\n"
            "endif\n"
        )
        names = [line.split()[1] for _, line in kam_rspamd.active_lines(text)]
        self.assertEqual(names, ["MODERN", "SA4", "CURRENT"])

    def test_active_lines_widened_plugin_gates(self):
        # DKIM/SPF gated blocks now convert their plain-regex rules and metas
        # (evals inside still drop individually at the rule parser).
        text = (
            "ifplugin Mail::SpamAssassin::Plugin::DKIM\n"
            "ifplugin Mail::SpamAssassin::Plugin::SPF\n"
            "body GATED /x/\n"
            "endif\n"
            "endif\n"
            "ifplugin Mail::SpamAssassin::Plugin::RaptorOnly\n"
            "body APPLIANCE /y/\n"
            "endif\n"
        )
        names = [line.split()[1] for _, line in kam_rspamd.active_lines(text)]
        self.assertEqual(names, ["GATED"])

    def test_header_exists_rule(self):
        # SA `header NAME exists:Hdr` converts to a `^` presence regex on that
        # header; the form is header-only (mimeheader exists stays unsupported).
        rules, omitted, _, _ = kam_rspamd.parse_rules(
            b"header __HAS_TO exists:To\n"
            b"mimeheader __MH_EXISTS exists:Content-Type\n",
            set(),
            set(),
        )
        rule = rules["__HAS_TO"]
        self.assertEqual((rule.kind, rule.header, rule.expression), ("header", "To", "^"))
        self.assertFalse(rule.negate)
        self.assertNotIn("__MH_EXISTS", rules)
        self.assertEqual(omitted["unsupported_mimeheader"], 1)

    def test_builtin_evals_satisfy_metas_without_external_deps(self):
        # A meta over a builtin-eval atom (HTML_MESSAGE et al) survives without
        # the symbol being external, and the atom is NOT an external dependency
        # (no symbol exists to register a dependency on — eval_atom computes it).
        source = (
            b"body LOCAL /x/\n"
            b"meta USES_BUILTIN (LOCAL && HTML_MESSAGE && __KAM_BODY_LENGTH_LT_128)\n"
            b"score USES_BUILTIN 1.0\n"
        )
        converted, mapdata, report = kam_rspamd.convert(source, "test", 1, 1)
        self.assertIn("USES_BUILTIN", map_rules(mapdata))
        self.assertEqual(report["external_dependencies"], [])
        header = map_header(mapdata)
        self.assertEqual(header["_builtin_evals"], sorted(kam_rspamd.PLUGIN_EVAL_SYMBOLS))
        # The Lua runtime carries the builtin implementations.
        text = converted.decode()
        self.assertIn("local builtin_evals", text)
        for symbol in kam_rspamd.PLUGIN_EVAL_SYMBOLS:
            self.assertIn(symbol, text)

    def test_report_flags_unexpanded_tag_rules(self):
        # A regex rule whose <tag> is never expanded (not in replace_rules) keeps
        # the literal tag, fails to compile at load, and is disabled silently;
        # the report must surface it so a parse regression is visible in CI.
        source = (
            b"body GOOD /plain/\n"
            b"score GOOD 1\n"
            b"body TAGGED /<UNDEFINED>/\n"
            b"score TAGGED 1\n"
        )
        _, _, report = kam_rspamd.convert(source, "test", 1, 1)
        self.assertEqual(report["unexpanded_tag_rules"], ["TAGGED"])
        self.assertEqual(report["unexpanded_tag_rule_count"], 1)

    def test_report_carries_shared_generated_date(self):
        # The map header date and the report date come from one shared value, so
        # the artifacts never disagree on the ruleset version. (The lua runtime is
        # static and intentionally carries no date — it lives in the map.)
        _, mapdata, report = kam_rspamd.convert(b"body X /x/\n", "test", 1, 1)
        date = report["generated_date"]
        header = json.loads(mapdata.decode().splitlines()[0])
        self.assertEqual(header["_generated"], date)

    def test_external_meta_dependencies_maps_through_replacements(self):
        # A meta atom that isn't a local rule but resolves (directly or via
        # SYMBOL_REPLACEMENTS) to an external symbol is reported as a dependency;
        # a local atom or an unknown one is not.
        rules = {
            "LOCAL": kam_rspamd.Rule("LOCAL", "body", "/x/"),
            "M": kam_rspamd.Rule("M", "meta", "(LOCAL && DKIM_VALID && UNKNOWN)"),
        }
        deps = kam_rspamd.external_meta_dependencies(rules, {"R_DKIM_ALLOW"})
        # DKIM_VALID -> R_DKIM_ALLOW (a replacement) is external; LOCAL is local;
        # UNKNOWN resolves to nothing external.
        self.assertEqual(deps, {"R_DKIM_ALLOW"})


if __name__ == "__main__":
    unittest.main()
