"""Read what each device contacted from Zeek logs instead of a capture.

A network that already runs Zeek has these four logs, and they carry the
same four signals drift reads from packets:

- dns.log   -- `query` per client, and the addresses its `answers` handed out
- ssl.log   -- `server_name`, the TLS SNI
- http.log  -- `host`, the Host header
- conn.log  -- every flow the device opened, for direct-IP contacts

Both of Zeek's formats are read: the default tab-separated logs (with their
`#fields` header) and JSON lines, gzipped or not, including rotated files
(`dns.2026-10-15-10-00-00.log.gz`). Zeek's default config records no MAC
addresses; when conn.log has `orig_l2_addr` it is used.
"""
from __future__ import annotations

import gzip
import ipaddress
import json
import pathlib
from collections.abc import Iterator

from .pcap import _NOT_A_DESTINATION, _is_public, assemble

LOGS = ("dns", "ssl", "http", "conn")
_NOT_DIRECT_UDP = (53, 67, 68, 123, 5353)  # the same ports the pcap reader skips


class ZeekError(ValueError):
    pass


def _open(path: pathlib.Path):
    return gzip.open(path, "rt", encoding="utf-8", errors="replace") if path.suffix == ".gz" \
        else open(path, encoding="utf-8", errors="replace")


def read_log(path: pathlib.Path) -> Iterator[dict]:
    """Records as dicts. TSV vectors come back as lists, unset fields are
    absent, the same shape JSON gives."""
    with _open(path) as f:
        fields: list[str] | None = None
        sep, set_sep, unset, empty = "\t", ",", "-", "(empty)"
        for line in f:
            line = line.rstrip("\n")
            if not line:
                continue
            if line.startswith("{"):
                yield json.loads(line)
                continue
            if line.startswith("#"):
                key, _, value = line[1:].partition(" " if line.startswith("#separator") else sep)
                if key == "separator":
                    sep = value.encode().decode("unicode_escape")
                elif key == "set_separator":
                    set_sep = value
                elif key == "unset_field":
                    unset = value
                elif key == "empty_field":
                    empty = value
                elif key == "fields":
                    fields = value.split(sep)
                continue
            if fields is None:
                raise ZeekError(f"{path.name}: a data line before any #fields header")
            record = {}
            for name, value in zip(fields, line.split(sep)):
                if value == unset:
                    continue
                record[name] = [] if value == empty else value
            yield record


def _is_ip(value: str) -> bool:
    """answers mixes addresses with CNAME targets and TXT data."""
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _as_list(value) -> list[str]:
    if isinstance(value, list):
        return [str(v) for v in value]
    return [] if value in (None, "") else str(value).split(",")


def find_logs(directory: str | pathlib.Path) -> dict[str, list[pathlib.Path]]:
    folder = pathlib.Path(directory)
    found = {name: sorted(p for p in folder.glob(f"{name}.*")
                          if p.is_file() and p.name.endswith((".log", ".log.gz", ".json", ".json.gz")))
             for name in LOGS}
    if not any(found.values()):
        raise ZeekError(f"no dns, ssl, http or conn log in {folder}")
    return found


def extract_zeek(directory: str | pathlib.Path) -> dict[str, dict]:
    """Same result shape as drift.pcap.extract_domains."""
    logs = find_logs(directory)
    names: dict[str, dict] = {}
    contacted: dict[str, set[str]] = {}
    resolved: set[str] = set()
    named: set[tuple[str, str]] = set()
    macs: dict[str, str] = {}

    def bucket(ip: str) -> dict:
        return names.setdefault(ip, {"dns": set(), "http": set(), "sni": set()})

    def records(name: str) -> Iterator[dict]:
        for path in logs[name]:
            yield from read_log(path)

    for r in records("dns"):
        src, query = r.get("id.orig_h"), str(r.get("query") or "").rstrip(".").lower()
        if src and query and not query.endswith(_NOT_A_DESTINATION):
            bucket(src)["dns"].add(query)
        resolved.update(a for a in _as_list(r.get("answers")) if _is_ip(a))

    for log, key, signal in (("ssl", "server_name", "sni"), ("http", "host", "http")):
        for r in records(log):
            src, dst, value = r.get("id.orig_h"), r.get("id.resp_h"), r.get(key)
            if src and value:
                host = str(value).rstrip(".").lower()
                if signal == "http":
                    host = host.split(":")[0]
                bucket(src)[signal].add(host)
                named.add((src, dst))

    for r in records("conn"):
        src, dst, proto = r.get("id.orig_h"), r.get("id.resp_h"), r.get("proto")
        if not src or not dst or not _is_public(dst):
            continue
        if r.get("orig_l2_addr"):
            macs.setdefault(src, str(r["orig_l2_addr"]).lower())
        if proto == "tcp" or (proto == "udp" and int(r.get("id.resp_p") or 0) not in _NOT_DIRECT_UDP):
            contacted.setdefault(src, set()).add(dst)

    return assemble(names, contacted, resolved, named, macs)
