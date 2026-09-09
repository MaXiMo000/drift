"""Run: python tests/test_claims.py"""
from __future__ import annotations

import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))

from drift.claims import ClaimsError, load_claims


class TestLoadClaims(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = pathlib.Path(self.tmp.name) / "claims.yaml"

    def tearDown(self):
        self.tmp.cleanup()

    def _write(self, text: str) -> str:
        self.path.write_text(text, encoding="utf-8")
        return str(self.path)

    def test_valid_claims(self):
        p = self._write(
            "devices:\n  - id: '10.0.0.5'\n    name: bulb\n    allowed_domains: [Vendor.com]\n"
        )
        claims = load_claims(p)
        self.assertEqual(claims, {"10.0.0.5": {"name": "bulb", "allowed_domains": ["vendor.com"]}})

    def test_domain_normalization_lowercases_and_strips_trailing_dot(self):
        p = self._write("devices:\n  - id: x\n    allowed_domains: ['Example.COM.']\n")
        claims = load_claims(p)
        self.assertEqual(claims["x"]["allowed_domains"], ["example.com"])

    def test_name_defaults_to_id_when_absent(self):
        p = self._write("devices:\n  - id: x\n    allowed_domains: []\n")
        claims = load_claims(p)
        self.assertEqual(claims["x"]["name"], "x")

    def test_missing_file_is_a_claims_error_not_a_crash(self):
        with self.assertRaises(ClaimsError):
            load_claims(str(self.path))

    def test_not_yaml_is_a_claims_error(self):
        p = self._write("not: valid: yaml: at: all:::")
        with self.assertRaises(ClaimsError):
            load_claims(p)

    def test_missing_devices_key_is_rejected(self):
        p = self._write("something_else: true\n")
        with self.assertRaises(ClaimsError) as ctx:
            load_claims(p)
        self.assertIn("devices", str(ctx.exception))

    def test_device_missing_id_is_rejected(self):
        p = self._write("devices:\n  - name: x\n")
        with self.assertRaises(ClaimsError) as ctx:
            load_claims(p)
        self.assertIn("id", str(ctx.exception))

    def test_duplicate_device_ids_are_rejected(self):
        p = self._write("devices:\n  - id: x\n  - id: x\n")
        with self.assertRaises(ClaimsError):
            load_claims(p)

    def test_allowed_domains_defaults_to_empty_list(self):
        p = self._write("devices:\n  - id: x\n")
        claims = load_claims(p)
        self.assertEqual(claims["x"]["allowed_domains"], [])


if __name__ == "__main__":
    unittest.main()
