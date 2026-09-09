"""Run: python tests/test_cli.py

Exercises the real CLI entry point against the real pcap fixture (see
test_pcap.py's docstring for its provenance) -- not a mocked
extract_domains().
"""
from __future__ import annotations

import contextlib
import io
import json
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))

from drift.cli import main

FIXTURE = str(pathlib.Path(__file__).parent / "fixtures" / "http.cap")


class TestCli(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.claims_path = pathlib.Path(self.tmp.name) / "claims.yaml"

    def tearDown(self):
        self.tmp.cleanup()

    def test_real_pcap_with_an_undeclared_domain_fails(self):
        self.claims_path.write_text(
            "devices:\n"
            "  - id: '145.254.160.237'\n"
            "    name: test workstation\n"
            "    allowed_domains: [www.ethereal.com]\n"
        )
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = main(["check", FIXTURE, str(self.claims_path)])
        self.assertEqual(code, 1)
        self.assertIn("pagead2.googlesyndication.com", buf.getvalue())
        self.assertIn("[XX]", buf.getvalue())

    def test_real_pcap_with_both_domains_declared_passes(self):
        self.claims_path.write_text(
            "devices:\n"
            "  - id: '145.254.160.237'\n"
            "    allowed_domains: [www.ethereal.com, pagead2.googlesyndication.com]\n"
        )
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = main(["check", FIXTURE, str(self.claims_path)])
        self.assertEqual(code, 0)
        self.assertIn("1/1 pass", buf.getvalue())

    def test_unknown_device_in_the_capture_is_unverified_not_a_fail(self):
        self.claims_path.write_text("devices:\n  - id: '10.0.0.99'\n    allowed_domains: []\n")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = main(["check", FIXTURE, str(self.claims_path)])
        self.assertEqual(code, 0)
        self.assertIn("[??]", buf.getvalue())

    def test_missing_pcap_is_a_clean_error_not_a_traceback(self):
        self.claims_path.write_text("devices:\n  - id: x\n    allowed_domains: []\n")
        with self.assertRaises(SystemExit) as ctx:
            main(["check", "/no/such/file.pcap", str(self.claims_path)])
        self.assertIn("drift:", str(ctx.exception))

    def test_bad_claims_file_is_a_clean_error_not_a_traceback(self):
        self.claims_path.write_text("not: a valid claims file\n")
        with self.assertRaises(SystemExit) as ctx:
            main(["check", FIXTURE, str(self.claims_path)])
        self.assertIn("drift:", str(ctx.exception))

    def test_not_actually_a_pcap_file_is_a_clean_error(self):
        bad_pcap = pathlib.Path(self.tmp.name) / "not_a_pcap.pcap"
        bad_pcap.write_text("this is definitely not packet capture data")
        self.claims_path.write_text("devices:\n  - id: x\n    allowed_domains: []\n")
        with self.assertRaises(SystemExit) as ctx:
            main(["check", str(bad_pcap), str(self.claims_path)])
        self.assertIn("drift:", str(ctx.exception))

    def test_json_flag_prints_the_full_report(self):
        self.claims_path.write_text(
            "devices:\n  - id: '145.254.160.237'\n    allowed_domains: [www.ethereal.com]\n"
        )
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            main(["check", FIXTURE, str(self.claims_path), "--json"])
        report = json.loads(buf.getvalue())
        self.assertEqual(report[0]["status"], "fail")


if __name__ == "__main__":
    unittest.main()
