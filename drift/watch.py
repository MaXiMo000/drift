"""`drift watch`: the same check as `drift check`, on a live interface.

Packets are read for a window, then everything seen so far is checked
against the claims, and only what is new since the last window is printed
(and sent to the webhook). Evidence accumulates across windows: an address
a device resolved an hour ago is still not a "direct IP" contact now.

Capturing needs root or CAP_NET_RAW on Linux, and Npcap on Windows.
"""
from __future__ import annotations

import time

from .check import FAIL, UNVERIFIED, check_pcap
from .notify import NotifyError, send
from .pcap import Extractor


class CaptureError(RuntimeError):
    pass


def watch(claims: dict, *, iface: str | None, window: float, rounds: int | None = None,
          notify: str | None = None, out=print, sniff=None, clock=time.strftime) -> int:
    """Returns the number of new violations seen. `sniff` and `clock` are
    swappable so the loop can be tested without a network interface."""
    if sniff is None:
        from scapy.all import sniff
    extractor = Extractor()
    reported: set[tuple[str, str]] = set()
    unknown: set[str] = set()
    violations = 0
    done = 0
    while rounds is None or done < rounds:
        try:
            sniff(iface=iface, prn=extractor.feed, store=False, timeout=window)
        except (PermissionError, OSError) as exc:
            raise CaptureError(
                f"could not capture on {iface or 'the default interface'}: {exc} -- live capture "
                "needs root or CAP_NET_RAW on Linux, and Npcap on Windows") from exc
        done += 1
        fresh_results = []
        for r in check_pcap(extractor.report(), claims):
            device = r["device_id"]
            if r["status"] == FAIL:
                new = [d for d in r["unexpected_domains"] + r["unexpected_ips"] if (device, d) not in reported]
                if new:
                    reported.update((device, d) for d in new)
                    violations += len(new)
                    fresh_results.append(r)
                    out(f"{clock('%H:%M:%S')} [XX] {device}: contacted {', '.join(new)}, "
                        "outside its declared allow-list")
            elif r["status"] == UNVERIFIED and device not in unknown:
                unknown.add(device)
                out(f"{clock('%H:%M:%S')} [??] {device}: no claims for this device yet")
        if fresh_results and notify:
            try:
                send(fresh_results, notify, "fail")
            except NotifyError as exc:
                out(f"drift: {exc}")
    return violations
