"""Run: python tests/test_zeek.py

The same small traffic written as Zeek's two log formats -- tab-separated
with a #fields header, and JSON lines -- must read identically. Against
the real WRCCDC sample logs (171 devices, about 3,000 DNS names) the two
formats also came out identical; these fixtures pin the rules that made
that true.
"""
from __future__ import annotations

import contextlib
import gzip
import io
import json
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))

from drift.cli import main
from drift.notify import send, summary
from drift.zeek import ZeekError, extract_zeek

CAM, LAPTOP = "192.168.1.20", "192.168.1.30"

# (log, fields, rows). None is an unset field; [] an empty vector.
TRAFFIC = {
    "dns": (["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "query", "answers"], [
        [1.0, "C1", CAM, 5353, "192.168.1.1", 53, "cloud.camvendor.example", ["cdn.camvendor.example", "93.184.215.10"]],
        [2.0, "C2", CAM, 5354, "192.168.1.1", 53, "10.1.168.192.in-addr.arpa", None],
        [3.0, "C3", LAPTOP, 5355, "192.168.1.1", 53, "news.example.org", []],
    ]),
    "ssl": (["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "server_name"], [
        [4.0, "C4", CAM, 40000, "93.184.215.10", 443, "cloud.camvendor.example"],
        [5.0, "C5", LAPTOP, 40001, "93.184.215.20", 443, "Mail.Example.org"],
        [6.0, "C6", LAPTOP, 40002, "93.184.215.21", 443, None],
    ]),
    "http": (["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "host"], [
        [7.0, "C7", CAM, 40003, "93.184.215.11", 80, "firmware.camvendor.example:8080"],
    ]),
    "conn": (["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto"], [
        [4.0, "C4", CAM, 40000, "93.184.215.10", 443, "tcp"],    # resolved and named
        [7.0, "C7", CAM, 40003, "93.184.215.11", 80, "tcp"],     # named by Host
        [8.0, "C8", CAM, 40004, "45.33.32.156", 8443, "tcp"],   # never looked up, never named
        [9.0, "C9", CAM, 123, "93.184.215.30", 123, "udp"],    # NTP: never a direct contact
        [10.0, "C10", LAPTOP, 40005, "192.168.1.40", 445, "tcp"],  # local: never counted
        [11.0, "C11", LAPTOP, 40006, "93.184.215.21", 443, "tcp"],  # TLS with no SNI
    ]),
}


def write_tsv(folder: pathlib.Path) -> None:
    for name, (fields, rows) in TRAFFIC.items():
        lines = ["#separator \\x09", "#set_separator\t,", "#empty_field\t(empty)", "#unset_field\t-",
                 f"#path\t{name}", "#fields\t" + "\t".join(fields)]
        for row in rows:
            cells = ["-" if v is None else "(empty)" if v == [] else ",".join(v) if isinstance(v, list)
                     else str(v) for v in row]
            lines.append("\t".join(cells))
        lines.append("#close\t2026-10-15-12-00-00")
        text = "\n".join(lines) + "\n"
        if name == "conn":  # rotated and gzipped, as Zeek archives it
            with gzip.open(folder / "conn.2026-10-15-11-00-00.log.gz", "wt", encoding="utf-8") as f:
                f.write(text)
        else:
            (folder / f"{name}.log").write_text(text, encoding="utf-8")


def write_json(folder: pathlib.Path) -> None:
    for name, (fields, rows) in TRAFFIC.items():
        lines = [json.dumps({k: v for k, v in zip(fields, row) if v is not None}) for row in rows]
        (folder / f"{name}.json").write_text("\n".join(lines) + "\n", encoding="utf-8")


class TestZeek(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.tsv = pathlib.Path(self.tmp.name) / "tsv"
        self.json = pathlib.Path(self.tmp.name) / "json"
        self.tsv.mkdir()
        self.json.mkdir()
        write_tsv(self.tsv)
        write_json(self.json)

    def tearDown(self):
        self.tmp.cleanup()

    def test_both_formats_read_the_same(self):
        self.assertEqual(extract_zeek(self.tsv), extract_zeek(self.json))

    def test_the_four_signals_and_the_direct_contact(self):
        cam = extract_zeek(self.tsv)[CAM]
        self.assertEqual(cam["dns"], ["cloud.camvendor.example"])    # reverse lookup dropped
        self.assertEqual(cam["sni"], ["cloud.camvendor.example"])
        self.assertEqual(cam["http"], ["firmware.camvendor.example"])  # port stripped
        self.assertEqual(cam["direct_ips"], ["45.33.32.156"])          # only the unnamed one
        self.assertIsNone(cam["mac"])

    def test_tls_without_a_name_is_a_direct_contact(self):
        laptop = extract_zeek(self.json)[LAPTOP]
        self.assertEqual(laptop["sni"], ["mail.example.org"])
        self.assertEqual(laptop["direct_ips"], ["93.184.215.21"])

    def test_an_empty_folder_is_an_error_not_a_clean_network(self):
        empty = pathlib.Path(self.tmp.name) / "empty"
        empty.mkdir()
        with self.assertRaises(ZeekError):
            extract_zeek(empty)

    def test_check_runs_on_a_log_directory(self):
        claims = pathlib.Path(self.tmp.name) / "claims.yaml"
        claims.write_text(
            "devices:\n"
            f"  - id: \"{CAM}\"\n    name: camera\n"
            "    allowed_domains: [cloud.camvendor.example, firmware.camvendor.example]\n",
            encoding="utf-8")
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = main(["check", str(self.tsv), str(claims), "--json"])
        results = {r["device_id"]: r for r in json.loads(out.getvalue())}
        self.assertEqual(code, 1)
        self.assertEqual(results[CAM]["unexpected_ips"], ["45.33.32.156"])
        self.assertEqual(results[LAPTOP]["status"], "unverified")


class TestNotify(unittest.TestCase):
    RESULTS = [
        {"device_id": "192.168.1.20", "status": "fail", "unexpected_domains": ["evil.example"],
         "unexpected_ips": ["45.33.32.156"]},
        {"device_id": "192.168.1.30", "status": "unverified", "unexpected_domains": [], "unexpected_ips": []},
    ]

    def test_a_failure_posts_one_summary_slack_and_discord_both_read(self):
        sent = []

        class Response(io.BytesIO):
            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        def opener(request, timeout):
            sent.append(json.loads(request.data))
            return Response(b"ok")

        import os
        os.environ["DRIFT_TEST_HOOK"] = "https://hooks.example/abc"
        try:
            self.assertTrue(send(self.RESULTS, "DRIFT_TEST_HOOK", opener=opener))
            self.assertFalse(send(self.RESULTS[1:], "DRIFT_TEST_HOOK", opener=opener))  # nothing failed
        finally:
            del os.environ["DRIFT_TEST_HOOK"]
        self.assertEqual(len(sent), 1)
        self.assertEqual(sent[0]["text"], sent[0]["content"])
        self.assertIn("192.168.1.20: evil.example, 45.33.32.156", sent[0]["text"])
        self.assertIn("1 device(s) had no claims", summary(self.RESULTS))


if __name__ == "__main__":
    unittest.main()
