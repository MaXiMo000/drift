"""Extract what each device actually contacted in a packet capture.

Devices are keyed by source IP, with the MAC address recorded alongside
so a claims file can name a device by MAC and survive a DHCP lease change.

Four signals, all readable without decrypting anything:

- DNS query names -- the device asking "where is X", visible even when the
  connection to X is fully encrypted.
- TLS SNI -- the server name in a TLS ClientHello, sent in the clear before
  encryption starts. This is what names almost every HTTPS connection a
  modern device makes, including ones to a hostname it resolved some other
  way (DNS-over-HTTPS, a cached answer from before the capture started).
- HTTP `Host:` headers -- cleartext HTTP only.
- Direct IP contacts -- connections to a public address the device never
  looked up (no DNS answer in the capture) and never named (no SNI, no
  Host header). A device that talks to hardcoded IPs is exactly the one a
  DNS-only check misses.

Not read: QUIC (its ClientHello is encrypted with keys derived from the
connection ID -- decryptable, but real work of its own), and names inside
DNS-over-HTTPS. A QUIC connection still shows up as a direct IP contact
unless the device resolved that address via plain DNS first.
"""
from __future__ import annotations

import ipaddress


def _parse_host_header(data: bytes) -> str | None:
    """Only a complete line counts. A request split across TCP segments
    ends mid-line, and lotsofweb.pcapng taught "googleads.g.doublecl" as an
    allowed domain that way. The last piece after the split is unfinished
    unless the data ends with CRLF."""
    for line in data.split(b"\r\n")[:-1]:
        if line.lower().startswith(b"host:"):
            return line.split(b":", 1)[1].strip().decode("ascii", errors="replace")
    return None


def parse_client_hello_sni(record: bytes) -> str | None:
    """The server_name from one TLS ClientHello record, or None. `record`
    starts at the TLS record header (0x16 0x03 ..)."""
    try:
        if len(record) < 9 or record[0] != 0x16 or record[5] != 0x01:
            return None
        pos = 9 + 2 + 32                      # record(5)+handshake header(4), version, random
        pos += 1 + record[pos]                # session id
        pos += 2 + int.from_bytes(record[pos:pos + 2], "big")   # cipher suites
        pos += 1 + record[pos]                # compression methods
        end = pos + 2 + int.from_bytes(record[pos:pos + 2], "big")
        pos += 2
        while pos + 4 <= min(end, len(record)):
            ext_type = int.from_bytes(record[pos:pos + 2], "big")
            ext_len = int.from_bytes(record[pos + 2:pos + 4], "big")
            body = record[pos + 4:pos + 4 + ext_len]
            if ext_type == 0 and len(body) >= 5 and body[2] == 0:   # server_name, host_name
                name_len = int.from_bytes(body[3:5], "big")
                return body[5:5 + name_len].decode("ascii", errors="replace").rstrip(".").lower() or None
            pos += 4 + ext_len
    except IndexError:
        return None
    return None


def _is_public(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast
                or addr.is_reserved or addr.is_unspecified)


# A ClientHello bigger than this is either garbage or not a ClientHello.
_MAX_HELLO = 16 * 1024
_MAX_REQUEST_HEAD = 8 * 1024
# Lookups that name no destination: reverse DNS (a device asking who an
# address is -- often its own), multicast DNS on the local link, and the
# resolver's search-domain retries ("digg.com.localdomain").
_NOT_A_DESTINATION = (".in-addr.arpa", ".ip6.arpa", ".local", ".localdomain")


def extract_domains(pcap_path: str) -> dict[str, dict]:
    """Returns {source_ip: {"mac", "dns", "http", "sni", "direct_ips"}},
    every list sorted for deterministic output."""
    from scapy.all import PcapReader  # imported here, not at module load, so
    from scapy.layers.dns import DNS  # importing drift.claims/drift.check
    from scapy.layers.inet import IP, TCP, UDP  # never requires scapy at all
    from scapy.layers.inet6 import IPv6
    from scapy.layers.l2 import Ether
    from scapy.packet import Raw

    result: dict[str, dict] = {}
    resolved: set[str] = set()          # every address any DNS answer handed out
    named: set[tuple[str, str]] = set()  # (device, dst) pairs that carried an SNI/Host name
    contacted: dict[str, set[str]] = {}  # device -> public destinations it opened a flow to
    hellos: dict[tuple, bytearray] = {}  # TCP flow -> ClientHello bytes being reassembled
    heads: dict[tuple, bytearray] = {}   # TCP flow -> HTTP request head being reassembled
    macs: dict[str, str] = {}            # first MAC seen sending from each IP

    def bucket(ip: str) -> dict:
        return result.setdefault(ip, {"dns": set(), "http": set(), "sni": set()})

    # Streamed, not rdpcap(): a multi-GB capture from a real network tap
    # shouldn't have to fit in memory. The file is opened here, not by
    # scapy, because scapy's reader raises on a non-pcap file from inside
    # its constructor without closing the handle it opened (a locked file
    # on Windows).
    with open(pcap_path, "rb") as f, PcapReader(f) as packets:
        for pkt in packets:
            if IP in pkt:
                src, dst = pkt[IP].src, pkt[IP].dst
            elif IPv6 in pkt:
                src, dst = pkt[IPv6].src, pkt[IPv6].dst
            else:
                continue

            if Ether in pkt:
                macs.setdefault(src, pkt[Ether].src.lower())

            if DNS in pkt:
                dns = pkt[DNS]
                if dns.qr == 0 and dns.qd:
                    # qd is a PacketListField in current scapy; indexed, not
                    # treated as one record.
                    qname = dns.qd[0].qname
                    if isinstance(qname, bytes):
                        qname = qname.decode("ascii", errors="replace")
                    qname = qname.rstrip(".").lower()
                    if not qname.endswith(_NOT_A_DESTINATION):
                        bucket(src)["dns"].add(qname)
                elif dns.qr == 1:
                    for i in range(dns.ancount or 0):
                        try:
                            rr = dns.an[i]
                        except (IndexError, TypeError):
                            break
                        if getattr(rr, "type", None) in (1, 28):  # A, AAAA
                            resolved.add(str(rr.rdata))
                continue  # DNS traffic itself is never a "direct IP" contact

            if TCP in pkt:
                tcp = pkt[TCP]
                if tcp.flags & 0x02 and not tcp.flags & 0x10 and _is_public(dst):  # SYN, not SYN-ACK
                    contacted.setdefault(src, set()).add(dst)
                if Raw not in pkt:
                    continue
                data = bytes(pkt[Raw])
                flow = (src, tcp.sport, dst, tcp.dport)
                if flow in hellos or data[:2] == b"\x16\x03":
                    buf = hellos.setdefault(flow, bytearray())
                    buf += data
                    need = 5 + int.from_bytes(buf[3:5], "big") if len(buf) >= 5 else _MAX_HELLO
                    if len(buf) >= need or len(buf) >= _MAX_HELLO:
                        # ponytail: in-order reassembly only, no retransmit or
                        # out-of-order handling; enough for a ClientHello.
                        sni = parse_client_hello_sni(bytes(hellos.pop(flow)))
                        if sni:
                            bucket(src)["sni"].add(sni)
                            named.add((src, dst))
                    continue
                if flow in heads or data.startswith(
                        (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"PATCH ", b"OPTIONS ")):
                    buf = heads.setdefault(flow, bytearray())
                    buf += data
                    if b"\r\n\r\n" not in buf and len(buf) < _MAX_REQUEST_HEAD:
                        continue  # the rest of the header is in the next segment
                    host = _parse_host_header(bytes(heads.pop(flow)))
                    if host:
                        bucket(src)["http"].add(host.split(":")[0].lower())
                        named.add((src, dst))
            elif UDP in pkt and _is_public(dst) and pkt[UDP].dport not in (53, 67, 68, 123, 5353):
                contacted.setdefault(src, set()).add(dst)

    # A device is anything that initiated something: a DNS query, a named
    # connection, or a flow to a public address. Servers only answering
    # never appear here.
    out = {}
    for ip in set(result) | set(contacted):
        v = result.get(ip, {"dns": (), "http": (), "sni": ()})
        direct = sorted(d for d in contacted.get(ip, ()) if d not in resolved and (ip, d) not in named)
        out[ip] = {"mac": macs.get(ip), "dns": sorted(v["dns"]), "http": sorted(v["http"]),
                   "sni": sorted(v["sni"]), "direct_ips": direct}
    return out
