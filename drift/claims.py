"""Load a drift claims file: which domains each device is declared to be
allowed to contact. Same discipline as witness's own claims schema (this
portfolio's browser-side equivalent): the allow-list is the actual gate,
and a device with no entry here reads as unverified, never a silent pass.
"""
from __future__ import annotations

import yaml


class ClaimsError(ValueError):
    pass


def _norm(domain: str) -> str:
    return domain.strip().lower().rstrip(".")


def load_claims(path: str) -> dict[str, dict]:
    try:
        with open(path, encoding="utf-8") as f:
            raw = yaml.safe_load(f)
    except yaml.YAMLError as exc:
        raise ClaimsError(f"{path}: not valid YAML ({exc})") from exc
    except OSError as exc:
        raise ClaimsError(f"{path}: {exc}") from exc

    if not isinstance(raw, dict) or "devices" not in raw:
        raise ClaimsError(f"{path}: must be a mapping with a top-level 'devices' list")
    devices = raw["devices"]
    if not isinstance(devices, list) or not devices:
        raise ClaimsError(f"{path}: 'devices' must be a non-empty list")

    result: dict[str, dict] = {}
    for i, dev in enumerate(devices):
        if not isinstance(dev, dict):
            raise ClaimsError(f"{path}: devices[{i}] must be a mapping")
        dev_id = dev.get("id")
        if not dev_id or not isinstance(dev_id, str):
            raise ClaimsError(f"{path}: devices[{i}] is missing a string 'id'")
        if dev_id in result:
            raise ClaimsError(f"{path}: duplicate device id '{dev_id}'")

        allowed = dev.get("allowed_domains", [])
        if not isinstance(allowed, list):
            raise ClaimsError(f"{path}: device '{dev_id}': 'allowed_domains' must be a list")

        for d in allowed:
            if not isinstance(d, str) or "*" in d.removeprefix("*."):
                raise ClaimsError(
                    f"{path}: device '{dev_id}': {d!r} -- the only wildcard form is a "
                    f"leading '*.' (e.g. '*.example.com')")

        result[dev_id] = {
            "name": dev.get("name", dev_id),
            "allowed_domains": [_norm(d) for d in allowed],
        }
    return result
