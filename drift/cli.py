"""drift check <pcap> <claims.yaml> [--json]
drift learn <pcap> [--device IP]... [--by-mac]"""
from __future__ import annotations

import argparse
import json
import sys

import yaml

from .check import FAIL, PASS, UNVERIFIED, check_pcap
from .claims import ClaimsError, load_claims
from .pcap import extract_domains

_TAG = {PASS: "OK", FAIL: "XX", UNVERIFIED: "??"}


def _extract(pcap: str) -> dict:
    try:
        return extract_domains(pcap)
    except OSError as exc:
        sys.exit(f"drift: could not read {pcap}: {exc}")
    except Exception as exc:  # noqa: BLE001 -- scapy's own parse errors vary by malformation
        sys.exit(f"drift: could not parse {pcap} as a packet capture ({exc})")


def _check(args) -> int:
    try:
        claims = load_claims(args.claims)
    except ClaimsError as exc:
        sys.exit(f"drift: {exc}")
    results = check_pcap(_extract(args.pcap), claims)

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        for r in results:
            print(f"[{_TAG[r['status']]}] {r['device_id']}: {r['detail']}")
        n_fail = sum(1 for r in results if r["status"] == FAIL)
        n_unverified = sum(1 for r in results if r["status"] == UNVERIFIED)
        summary = f"{len(results) - n_fail - n_unverified}/{len(results)} pass"
        if n_fail:
            summary += f", {n_fail} fail"
        if n_unverified:
            summary += f", {n_unverified} unverified"
        print(f"\n{summary}")

    return 1 if any(r["status"] == FAIL for r in results) else 0


def _learn(args) -> int:
    """A starting claims file from what a capture actually shows: a
    baseline to review, not something to trust blindly -- a device that
    was already misbehaving during the capture gets that baked in."""
    observed = _extract(args.pcap)
    devices = []
    for ip, obs in sorted(observed.items()):
        if args.device and ip not in args.device:
            continue
        domains = sorted({d for key in ("dns", "http", "sni") for d in obs[key]})
        entry = {"id": obs["mac"] if args.by_mac and obs["mac"] else ip, "name": ip,
                 "allowed_domains": domains}
        if obs["direct_ips"]:
            entry["allowed_ips"] = obs["direct_ips"]
        devices.append(entry)
    if not devices:
        sys.exit("drift: no devices in that capture" + (" match --device" if args.device else ""))
    print(f"# Learned from {args.pcap}. Review before trusting: anything the device\n"
          f"# was already doing wrong during this capture is now in the allow-list.")
    print(yaml.safe_dump({"devices": devices}, sort_keys=False), end="")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="drift")
    sub = parser.add_subparsers(dest="command", required=True)

    check_p = sub.add_parser(
        "check", help="check devices in a packet capture against their declared destinations")
    check_p.add_argument("pcap", help="a packet capture file (.pcap/.pcapng)")
    check_p.add_argument("claims", help="drift-claims.yaml")
    check_p.add_argument("--json", action="store_true", help="print the full report as JSON")
    check_p.set_defaults(func=_check)

    learn_p = sub.add_parser(
        "learn", help="print a starting claims file from what a capture shows each device doing")
    learn_p.add_argument("pcap")
    learn_p.add_argument("--device", action="append", metavar="IP",
                         help="only this device (repeatable)")
    learn_p.add_argument("--by-mac", action="store_true",
                         help="key devices by MAC address instead of IP, where the capture has one")
    learn_p.set_defaults(func=_learn)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
