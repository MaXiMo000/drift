"""drift check <pcap> <claims.yaml> [--json]"""
from __future__ import annotations

import argparse
import json
import sys

from .check import FAIL, PASS, UNVERIFIED, check_pcap
from .claims import ClaimsError, load_claims
from .pcap import extract_domains

_TAG = {PASS: "OK", FAIL: "XX", UNVERIFIED: "??"}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="drift")
    sub = parser.add_subparsers(dest="command", required=True)

    check_p = sub.add_parser(
        "check", help="check devices in a packet capture against their declared allowed domains")
    check_p.add_argument("pcap", help="a packet capture file (.pcap/.pcapng)")
    check_p.add_argument("claims", help="drift-claims.yaml")
    check_p.add_argument("--json", action="store_true", help="print the full report as JSON")

    args = parser.parse_args(argv)

    try:
        claims = load_claims(args.claims)
    except ClaimsError as exc:
        sys.exit(f"drift: {exc}")

    try:
        observed = extract_domains(args.pcap)
    except OSError as exc:
        sys.exit(f"drift: could not read {args.pcap}: {exc}")
    except Exception as exc:  # noqa: BLE001 -- scapy's own parse errors vary by malformation
        sys.exit(f"drift: could not parse {args.pcap} as a packet capture ({exc})")

    results = check_pcap(observed, claims)

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        for r in results:
            print(f"[{_TAG[r['status']]}] {r['device_id']}: {r['detail']}")
        n_fail = sum(1 for r in results if r["status"] == FAIL)
        n_unverified = sum(1 for r in results if r["status"] == UNVERIFIED)
        n_pass = len(results) - n_fail - n_unverified
        summary = f"{n_pass}/{len(results)} pass"
        if n_fail:
            summary += f", {n_fail} fail"
        if n_unverified:
            summary += f", {n_unverified} unverified"
        print(f"\n{summary}")

    return 1 if any(r["status"] == FAIL for r in results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
