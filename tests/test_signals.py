"""Run: python tests/test_signals.py

TLS SNI, direct-IP contacts, MAC-keyed devices, allowed_ips, RFC 8520 MUD
files and `drift learn`.

The ClientHello here is a real one: produced by this machine's own
OpenSSL through Python's ssl module, not hand-assembled bytes. The capture
around it is generated with scapy (a real device's traffic can't be
committed to a public repo), with the ClientHello deliberately split
across two TCP segments -- a modern ClientHello (post-quantum key share)
often doesn't fit in one, and SNI can sit in the second half.
"""
from __future__ import annotations

import contextlib
import io
import json
import pathlib
import ssl
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))

from drift.check import FAIL, PASS, check_pcap
from drift.claims import load_claims, mud_domains
from drift.cli import main
from drift.pcap import extract_domains, parse_client_hello_sni

DEVICE_IP, DEVICE_MAC = "192.168.1.42", "aa:bb:cc:00:11:22"
RESOLVED_IP = "93.184.215.14"       # handed out by a DNS answer in the capture
HARDCODED_IP = "8.8.4.4"            # contacted with no lookup and no name
QUIC_IP = "142.250.64.78"           # UDP/443, never resolved


def real_client_hello(server_name: str) -> bytes:
    ctx = ssl.create_default_context()
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    tls = ctx.wrap_bio(incoming, outgoing, server_hostname=server_name)
    with contextlib.suppress(ssl.SSLWantReadError):
        tls.do_handshake()
    return outgoing.read()


def write_capture(path: str) -> None:
    from scapy.all import DNS, DNSQR, DNSRR, IP, TCP, UDP, Ether, Raw, wrpcap

    eth = Ether(src=DEVICE_MAC, dst="11:22:33:44:55:66")
    hello = real_client_hello("telemetry.vendor.example")
    half = len(hello) // 2
    pkts = [
        eth / IP(src=DEVICE_IP, dst="192.168.1.1") / UDP(sport=5353, dport=53)
        / DNS(id=1, qr=0, qd=DNSQR(qname="api.vendor.example")),
        Ether() / IP(src="192.168.1.1", dst=DEVICE_IP) / UDP(sport=53, dport=5353)
        / DNS(id=1, qr=1, qd=DNSQR(qname="api.vendor.example"),
              an=DNSRR(rrname="api.vendor.example", type="A", rdata=RESOLVED_IP)),
        # TLS to the resolved address, SNI split across two segments.
        eth / IP(src=DEVICE_IP, dst=RESOLVED_IP) / TCP(sport=50000, dport=443, flags="S"),
        eth / IP(src=DEVICE_IP, dst=RESOLVED_IP) / TCP(sport=50000, dport=443, flags="PA") / Raw(hello[:half]),
        eth / IP(src=DEVICE_IP, dst=RESOLVED_IP) / TCP(sport=50000, dport=443, flags="PA") / Raw(hello[half:]),
        # A server's reply must never make the server a "device".
        Ether() / IP(src=RESOLVED_IP, dst=DEVICE_IP) / TCP(sport=443, dport=50000, flags="SA"),
        # Hardcoded IP: no DNS, no SNI, no Host header.
        eth / IP(src=DEVICE_IP, dst=HARDCODED_IP) / TCP(sport=50001, dport=8883, flags="S"),
        # QUIC: UDP/443 to an address never resolved.
        eth / IP(src=DEVICE_IP, dst=QUIC_IP) / UDP(sport=50002, dport=443) / Raw(b"\xc3" + b"\0" * 40),
        # Local traffic is never a direct-IP finding.
        eth / IP(src=DEVICE_IP, dst="192.168.1.20") / TCP(sport=50003, dport=80, flags="S"),
    ]
    wrpcap(path, pkts)


class TestSni(unittest.TestCase):
    def test_a_real_openssl_client_hello(self):
        self.assertEqual(parse_client_hello_sni(real_client_hello("Example.COM")), "example.com")

    def test_truncated_or_non_hello_bytes_are_none_not_a_crash(self):
        hello = real_client_hello("example.com")
        for junk in (b"", hello[:20], b"\x16\x03\x01\x00\x05\x02abcd", b"GET / HTTP/1.1\r\n"):
            self.assertIsNone(parse_client_hello_sni(junk))


class TestCapture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.pcap = str(pathlib.Path(cls.tmp.name) / "device.pcap")
        write_capture(cls.pcap)
        cls.observed = extract_domains(cls.pcap)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def _claims(self, text: str) -> dict:
        p = pathlib.Path(self.tmp.name) / "claims.yaml"
        p.write_text(text, encoding="utf-8")
        return load_claims(str(p))

    def test_only_the_device_is_a_device(self):
        self.assertEqual(list(self.observed), [DEVICE_IP])

    def test_sni_from_a_hello_split_across_segments(self):
        self.assertEqual(self.observed[DEVICE_IP]["sni"], ["telemetry.vendor.example"])

    def test_direct_ips_are_the_unresolved_unnamed_public_ones(self):
        self.assertEqual(self.observed[DEVICE_IP]["direct_ips"], sorted([HARDCODED_IP, QUIC_IP]))

    def test_mac_is_recorded(self):
        self.assertEqual(self.observed[DEVICE_IP]["mac"], DEVICE_MAC)

    def test_a_domain_seen_only_via_sni_is_checked(self):
        claims = self._claims(f"devices:\n  - id: '{DEVICE_IP}'\n    allowed_domains: [api.vendor.example]\n"
                              f"    allowed_ips: ['{HARDCODED_IP}', '{QUIC_IP}']\n")
        r = check_pcap(self.observed, claims)[0]
        self.assertEqual(r["status"], FAIL)
        self.assertEqual(r["unexpected_domains"], ["telemetry.vendor.example"])
        self.assertEqual(r["unexpected_ips"], [])

    def test_direct_ips_fail_unless_allowed_including_by_cidr(self):
        base = f"devices:\n  - id: '{DEVICE_IP}'\n    allowed_domains: ['*.vendor.example', api.vendor.example]\n"
        r = check_pcap(self.observed, self._claims(base))[0]
        self.assertEqual(r["status"], FAIL)
        self.assertEqual(r["unexpected_ips"], sorted([HARDCODED_IP, QUIC_IP]))
        r = check_pcap(self.observed, self._claims(base + "    allowed_ips: ['8.8.4.0/24', '142.250.0.0/16']\n"))[0]
        self.assertEqual(r["status"], PASS, r["detail"])

    def test_a_device_can_be_named_by_mac(self):
        claims = self._claims("devices:\n  - id: 'AA:BB:CC:00:11:22'\n    name: bulb\n"
                              "    allowed_domains: ['*.vendor.example', api.vendor.example]\n"
                              "    allowed_ips: ['0.0.0.0/0']\n")
        r = check_pcap(self.observed, claims)[0]
        self.assertEqual(r["status"], PASS)
        self.assertIn("bulb", r["detail"])

    def test_learn_writes_claims_that_then_pass(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(main(["learn", self.pcap, "--by-mac"]), 0)
        learned = pathlib.Path(self.tmp.name) / "learned.yaml"
        learned.write_text(out.getvalue(), encoding="utf-8")
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(["check", self.pcap, str(learned)]), 0)
        self.assertIn(DEVICE_MAC, out.getvalue())


# The shape of RFC 8520's own example (Appendix A): device-to-cloud ACLs
# naming the manufacturer's servers by DNS name.
MUD_FILE = {
    "ietf-mud:mud": {
        "mud-version": 1, "mud-url": "https://vendor.example/bulb.json",
        "last-update": "2026-01-01T00:00:00+00:00", "cache-validity": 48,
        "is-supported": True, "systeminfo": "Example smart bulb",
        "from-device-policy": {"access-lists": {"access-list": [{"name": "from-ipv4-bulb"}]}},
        "to-device-policy": {"access-lists": {"access-list": [{"name": "to-ipv4-bulb"}]}},
    },
    "ietf-access-control-list:acls": {"acl": [
        {"name": "from-ipv4-bulb", "type": "ipv4-acl-type", "aces": {"ace": [
            {"name": "cl0-frdev", "matches": {"ipv4": {"ietf-acldns:dst-dnsname": "api.vendor.example"}},
             "actions": {"forwarding": "accept"}},
            {"name": "cl1-frdev", "matches": {"ipv4": {"ietf-acldns:dst-dnsname": "telemetry.vendor.example."}},
             "actions": {"forwarding": "accept"}}]}},
        {"name": "to-ipv4-bulb", "type": "ipv4-acl-type", "aces": {"ace": [
            {"name": "cl0-todev", "matches": {"ipv4": {"ietf-acldns:src-dnsname": "api.vendor.example"}},
             "actions": {"forwarding": "accept"}}]}},
    ]},
}


class TestMud(unittest.TestCase):
    def test_dns_names_come_out_of_the_acls(self):
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d) / "bulb.json"
            p.write_text(json.dumps(MUD_FILE), encoding="utf-8")
            self.assertEqual(mud_domains(p), ["api.vendor.example", "telemetry.vendor.example"])

    def test_a_claims_entry_can_point_at_a_mud_file(self):
        with tempfile.TemporaryDirectory() as d:
            (pathlib.Path(d) / "bulb.json").write_text(json.dumps(MUD_FILE), encoding="utf-8")
            claims = pathlib.Path(d) / "claims.yaml"
            claims.write_text("devices:\n  - id: bulb-1\n    mud: bulb.json\n", encoding="utf-8")
            self.assertEqual(load_claims(str(claims))["bulb-1"]["allowed_domains"],
                             ["api.vendor.example", "telemetry.vendor.example"])

    def test_a_non_mud_json_is_a_clear_error(self):
        from drift.claims import ClaimsError
        with tempfile.TemporaryDirectory() as d:
            (pathlib.Path(d) / "x.json").write_text("{}", encoding="utf-8")
            claims = pathlib.Path(d) / "claims.yaml"
            claims.write_text("devices:\n  - id: a\n    mud: x.json\n", encoding="utf-8")
            with self.assertRaisesRegex(ClaimsError, "not a MUD file"):
                load_claims(str(claims))


if __name__ == "__main__":
    unittest.main()
