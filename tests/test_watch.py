"""Run: python tests/test_watch.py

`drift watch`'s loop, fed the real packets of tests/fixtures/http.cap one
window at a time through a stand-in for scapy's sniff().
"""
from __future__ import annotations

import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))

from drift.watch import CaptureError, watch

FIXTURE = pathlib.Path(__file__).parent / "fixtures" / "http.cap"
DEVICE = "145.254.160.237"


def _packets():
    from scapy.all import rdpcap
    return list(rdpcap(str(FIXTURE)))


def replaying(windows):
    """A sniff() that delivers one list of packets per call."""
    windows = iter(windows)

    def sniff(iface, prn, store, timeout):
        for pkt in next(windows, []):
            prn(pkt)
    return sniff


def claims(allowed):
    return {DEVICE: {"name": "test workstation", "allowed_domains": allowed, "allowed_ips": []}}


class TestWatch(unittest.TestCase):
    def run_watch(self, claims_, windows, rounds):
        lines = []
        found = watch(claims_, iface="test0", window=1, rounds=rounds, out=lines.append,
                      sniff=replaying(windows), clock=lambda fmt: "12:00:00")
        return found, lines

    def test_a_violation_is_reported_once_not_every_window(self):
        packets = _packets()
        found, lines = self.run_watch(claims(["www.ethereal.com"]), [packets, packets, []], rounds=3)
        self.assertEqual(found, 1)
        self.assertEqual(lines, ["12:00:00 [XX] 145.254.160.237: contacted pagead2.googlesyndication.com, "
                                 "outside its declared allow-list"])

    def test_evidence_accumulates_across_windows(self):
        packets = _packets()
        half = len(packets) // 2
        found, lines = self.run_watch(claims(["www.ethereal.com"]), [packets[:half], packets[half:]], rounds=2)
        self.assertEqual(found, 1)
        self.assertEqual(len(lines), 1)

    def test_an_allowed_device_prints_nothing(self):
        found, lines = self.run_watch(
            claims(["www.ethereal.com", "pagead2.googlesyndication.com"]), [_packets()], rounds=1)
        self.assertEqual((found, lines), (0, []))

    def test_an_unclaimed_device_is_mentioned_once(self):
        found, lines = self.run_watch({}, [_packets(), _packets()], rounds=2)
        self.assertEqual(found, 0)
        self.assertEqual(lines, ["12:00:00 [??] 145.254.160.237: no claims for this device yet"])

    def test_no_capture_permission_is_a_clear_error(self):
        def denied(**kw):
            raise PermissionError("Operation not permitted")
        with self.assertRaises(CaptureError) as caught:
            watch(claims([]), iface="eth0", window=1, rounds=1, out=lambda s: None, sniff=denied)
        self.assertIn("CAP_NET_RAW", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
