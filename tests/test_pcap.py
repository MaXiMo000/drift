"""Run: python tests/test_pcap.py

Against a real packet capture (tests/fixtures/http.cap, downloaded from
Wireshark's own official SampleCaptures wiki -- see
tests/fixtures/PROVENANCE.md), not a synthetic one. Real traffic from
2004: a client hitting www.ethereal.com that also pulled in a Google
AdSense ad from pagead2.googlesyndication.com, both via a real DNS query
and a real HTTP request -- exactly the "declared one thing, actually did
another" shape this whole tool exists to catch, found in genuine traffic,
not constructed to make a point.
"""
from __future__ import annotations

import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))

from drift.pcap import extract_domains

FIXTURE = str(pathlib.Path(__file__).parent / "fixtures" / "http.cap")


class TestExtractDomains(unittest.TestCase):
    def test_the_one_real_device_in_the_capture_is_found(self):
        result = extract_domains(FIXTURE)
        self.assertIn("145.254.160.237", result)

    def test_the_real_dns_query_is_extracted(self):
        result = extract_domains(FIXTURE)
        self.assertIn("pagead2.googlesyndication.com", result["145.254.160.237"]["dns"])

    def test_the_real_http_host_headers_are_extracted(self):
        result = extract_domains(FIXTURE)
        http_hosts = result["145.254.160.237"]["http"]
        self.assertIn("www.ethereal.com", http_hosts)
        self.assertIn("pagead2.googlesyndication.com", http_hosts)

    def test_results_are_sorted_and_deduplicated(self):
        result = extract_domains(FIXTURE)
        http_hosts = result["145.254.160.237"]["http"]
        self.assertEqual(http_hosts, sorted(set(http_hosts)))

    def test_a_nonexistent_pcap_path_raises_an_os_error(self):
        with self.assertRaises(OSError):
            extract_domains("/no/such/file.pcap")


if __name__ == "__main__":
    unittest.main()
