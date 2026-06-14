import hashlib
import json
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
            b"meta GOOD (LOCAL && R_SPF_ALLOW)\n"
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
        self.assertEqual(report["dropped_metas"], {"BAD": ["MISSING"]})

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


if __name__ == "__main__":
    unittest.main()
