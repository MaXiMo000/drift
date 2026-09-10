"""Run: python tests/test_check.py"""
from __future__ import annotations

import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))

from drift.check import FAIL, PASS, UNVERIFIED, check_device, check_pcap


class TestCheckDevice(unittest.TestCase):
    def test_no_claims_is_unverified_never_a_silent_pass(self):
        r = check_device("10.0.0.5", {"dns": ["vendor.com"], "http": []}, claims=None)
        self.assertEqual(r["status"], UNVERIFIED)

    def test_an_undeclared_devices_observed_domains_still_appear_in_the_report(self):
        """Privacy-relevant, documented in README: a device with no claims
        entry (a housemate's phone caught in a shared-network capture, not
        just an undeclared IoT device) still gets its full domain list
        included in the output -- 'unverified' doesn't mean 'omitted'."""
        r = check_device("10.0.0.9", {"dns": ["some-random-site.example"], "http": []}, claims=None)
        self.assertEqual(r["observed_domains"], ["some-random-site.example"])

    def test_only_declared_domains_is_pass(self):
        claims = {"name": "bulb", "allowed_domains": ["vendor.com"]}
        r = check_device("10.0.0.5", {"dns": ["vendor.com"], "http": []}, claims)
        self.assertEqual(r["status"], PASS)

    def test_an_undeclared_domain_is_fail_and_named(self):
        claims = {"name": "bulb", "allowed_domains": ["vendor.com"]}
        r = check_device("10.0.0.5", {"dns": ["vendor.com", "ads.example.com"], "http": []}, claims)
        self.assertEqual(r["status"], FAIL)
        self.assertIn("ads.example.com", r["unexpected_domains"])
        self.assertIn("ads.example.com", r["detail"])

    def test_dns_and_http_observations_are_merged_and_deduplicated(self):
        claims = {"name": "bulb", "allowed_domains": ["vendor.com"]}
        r = check_device("10.0.0.5", {"dns": ["vendor.com"], "http": ["vendor.com"]}, claims)
        self.assertEqual(r["observed_domains"], ["vendor.com"])

    def test_case_and_trailing_dot_do_not_cause_a_false_mismatch(self):
        claims = {"name": "bulb", "allowed_domains": ["vendor.com"]}
        r = check_device("10.0.0.5", {"dns": ["Vendor.com."], "http": []}, claims)
        self.assertEqual(r["status"], PASS)

    def test_no_observations_at_all_with_claims_is_a_clean_pass(self):
        claims = {"name": "bulb", "allowed_domains": ["vendor.com"]}
        r = check_device("10.0.0.5", {"dns": [], "http": []}, claims)
        self.assertEqual(r["status"], PASS)
        self.assertEqual(r["observed_domains"], [])


class TestCheckPcap(unittest.TestCase):
    def test_multiple_devices_evaluated_independently_and_sorted(self):
        observed = {
            "10.0.0.2": {"dns": ["ads.example.com"], "http": []},
            "10.0.0.1": {"dns": ["vendor.com"], "http": []},
        }
        claims = {"10.0.0.1": {"name": "a", "allowed_domains": ["vendor.com"]}}
        results = check_pcap(observed, claims)
        self.assertEqual([r["device_id"] for r in results], ["10.0.0.1", "10.0.0.2"])
        self.assertEqual(results[0]["status"], PASS)
        self.assertEqual(results[1]["status"], UNVERIFIED)  # 10.0.0.2 has no claims entry


if __name__ == "__main__":
    unittest.main()
