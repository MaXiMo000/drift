"""Compare what a device actually contacted (extracted from a real packet
capture) against what it's declared to be allowed to contact. Same
three-status discipline as witness's own diff.js: no claim recorded for a
device is `unverified`, never a silent pass; a domain outside the
declared allow-list is `fail`, named explicitly, not folded into a vague
"suspicious" bucket.
"""
from __future__ import annotations

PASS, FAIL, UNVERIFIED = "pass", "fail", "unverified"


def _norm(domain: str) -> str:
    return domain.strip().lower().rstrip(".")


def check_device(device_id: str, observed: dict, claims: dict | None) -> dict:
    all_observed = sorted(set(observed.get("dns", [])) | set(observed.get("http", [])))

    if claims is None:
        return {
            "device_id": device_id, "status": UNVERIFIED,
            "detail": (f"no claims recorded for device '{device_id}' -- observed "
                       f"{len(all_observed)} domain(s), nothing to check them against"),
            "observed_domains": all_observed, "unexpected_domains": [],
        }

    allowed = {_norm(d) for d in claims["allowed_domains"]}
    unexpected = [d for d in all_observed if _norm(d) not in allowed]

    if unexpected:
        return {
            "device_id": device_id, "status": FAIL,
            "detail": (f"'{claims['name']}' contacted domain(s) outside its declared "
                       f"allow-list: {', '.join(unexpected)}"),
            "observed_domains": all_observed, "unexpected_domains": unexpected,
        }
    return {
        "device_id": device_id, "status": PASS,
        "detail": f"'{claims['name']}' only contacted declared domains",
        "observed_domains": all_observed, "unexpected_domains": [],
    }


def check_pcap(observed_by_device: dict[str, dict], claims: dict[str, dict]) -> list[dict]:
    return [
        check_device(dev_id, obs, claims.get(dev_id))
        for dev_id, obs in sorted(observed_by_device.items())
    ]
