"""Compare what a device actually contacted (extracted from a real packet
capture) against what it's declared to be allowed to contact. Same
three-status discipline as witness's own diff.js: no claim recorded for a
device is `unverified`, never a silent pass; a domain (or a direct IP)
outside the declared allow-list is `fail`, named explicitly, not folded
into a vague "suspicious" bucket.
"""
from __future__ import annotations

import ipaddress

PASS, FAIL, UNVERIFIED = "pass", "fail", "unverified"


def _norm(domain: str) -> str:
    return domain.strip().lower().rstrip(".")


def is_allowed(domain: str, allowed: list[str]) -> bool:
    """An entry is an exact domain, or `*.example.com` for any subdomain of
    example.com at any depth (not example.com itself -- list both if both
    are allowed). Exact-by-default means an allow-list never quietly
    covers more than it names."""
    for entry in allowed:
        if entry.startswith("*."):
            if domain.endswith(entry[1:]):
                return True
        elif domain == entry:
            return True
    return False


def ip_allowed(ip: str, networks: list) -> bool:
    addr = ipaddress.ip_address(ip)
    return any(addr in net for net in networks)


def check_device(device_id: str, observed: dict, claims: dict | None) -> dict:
    all_observed = sorted({_norm(d) for key in ("dns", "http", "sni") for d in observed.get(key, [])})
    direct = list(observed.get("direct_ips", []))
    base = {"device_id": device_id, "mac": observed.get("mac"),
            "observed_domains": all_observed, "direct_ips": direct}

    if claims is None:
        return {**base, "status": UNVERIFIED,
                "detail": (f"no claims recorded for device '{device_id}' -- observed "
                           f"{len(all_observed)} domain(s) and {len(direct)} direct IP(s), "
                           "nothing to check them against"),
                "unexpected_domains": [], "unexpected_ips": []}

    allowed = [_norm(d) for d in claims["allowed_domains"]]
    unexpected = [d for d in all_observed if not is_allowed(d, allowed)]
    unexpected_ips = [ip for ip in direct if not ip_allowed(ip, claims.get("allowed_ips", []))]

    if unexpected or unexpected_ips:
        parts = []
        if unexpected:
            parts.append(f"domain(s) outside its declared allow-list: {', '.join(unexpected)}")
        if unexpected_ips:
            parts.append(f"IP address(es) it never looked up or named: {', '.join(unexpected_ips)}")
        return {**base, "status": FAIL,
                "detail": f"'{claims['name']}' contacted " + "; and ".join(parts),
                "unexpected_domains": unexpected, "unexpected_ips": unexpected_ips}
    return {**base, "status": PASS,
            "detail": f"'{claims['name']}' only contacted declared destinations",
            "unexpected_domains": [], "unexpected_ips": []}


def check_pcap(observed_by_device: dict[str, dict], claims: dict[str, dict]) -> list[dict]:
    """A device's claims are found by its IP, or by its MAC -- so a claims
    file keyed on MAC addresses survives a DHCP lease change."""
    results = []
    for dev_id, obs in sorted(observed_by_device.items()):
        mac = (obs.get("mac") or "").lower()
        results.append(check_device(dev_id, obs, claims.get(dev_id) or (claims.get(mac) if mac else None)))
    return results
