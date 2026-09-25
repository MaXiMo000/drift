"""Load a drift claims file: which domains (and, optionally, which raw IP
ranges) each device is declared to be allowed to contact. The allow-list
is the actual gate, and a device with no entry here reads as unverified,
never a silent pass.

    devices:
      - id: "192.168.1.42"            # an IP, or a MAC ("aa:bb:cc:dd:ee:ff")
        name: smart bulb
        allowed_domains: [api.vendor.example, "*.cdn.vendor.example"]
        allowed_ips: ["203.0.113.0/24"]   # direct-IP contacts that are fine
        mud: bulb.mud.json              # an RFC 8520 MUD file; its DNS names are added
"""
from __future__ import annotations

import ipaddress
import json
import pathlib
import re

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

        domains = [_norm(d) for d in allowed]
        if dev.get("mud"):
            mud_path = pathlib.Path(path).parent / dev["mud"]
            try:
                domains += mud_domains(mud_path)
            except (OSError, ValueError) as exc:
                raise ClaimsError(f"{path}: device '{dev_id}': mud file {mud_path}: {exc}") from exc

        allowed_ips = dev.get("allowed_ips", [])
        if not isinstance(allowed_ips, list):
            raise ClaimsError(f"{path}: device '{dev_id}': 'allowed_ips' must be a list")
        try:
            networks = [ipaddress.ip_network(str(n), strict=False) for n in allowed_ips]
        except ValueError as exc:
            raise ClaimsError(f"{path}: device '{dev_id}': {exc}") from exc

        # A MAC id is matched case-insensitively (captures write it lowercase).
        key = dev_id.lower() if _MAC.match(dev_id) else dev_id
        result[key] = {
            "name": dev.get("name", dev_id),
            "allowed_domains": domains,
            "allowed_ips": networks,
        }
    return result


_MAC = re.compile(r"^[0-9A-Fa-f]{2}([:-][0-9A-Fa-f]{2}){5}$")


def mud_domains(path) -> list[str]:
    """Every DNS name an RFC 8520 Manufacturer Usage Description allows the
    device to talk to: the `ietf-acldns:dst-dnsname` / `src-dnsname` matches
    in its access lists. A MUD file is the manufacturer's own published
    statement of what the device needs to contact -- checking a capture
    against it checks the device against its maker's word."""
    doc = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
    if not isinstance(doc, dict) or "ietf-mud:mud" not in doc:
        raise ValueError("not a MUD file (no top-level 'ietf-mud:mud')")
    found: list[str] = []

    def walk(node):
        if isinstance(node, dict):
            for k, v in node.items():
                if k in ("ietf-acldns:dst-dnsname", "ietf-acldns:src-dnsname") and isinstance(v, str):
                    found.append(_norm(v))
                else:
                    walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)

    walk(doc.get("ietf-access-control-list:acls", {}))
    return sorted(set(found))
