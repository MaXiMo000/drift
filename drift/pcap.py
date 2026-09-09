"""Extract which domains each device (identified by its source IP)
actually contacted in a packet capture.

Two signals, both cleartext regardless of what runs on top of them:

- DNS query names -- the device asking "where is X" is visible even when
  the connection to X itself is fully encrypted, which is why this is the
  signal that actually matters for a modern device whose traffic is
  mostly HTTPS.
- HTTP `Host:` headers -- a strictly narrower signal (cleartext HTTP
  only), kept because it's free once a capture has any plain HTTP in it
  at all, and it names the domain a request actually reached, not just
  one it resolved.

What this does NOT do: read a domain out of an HTTPS/TLS connection.
That needs either the TLS ClientHello's SNI field (sent in the clear even
over an otherwise-encrypted connection, and not read here -- real,
addable scope) or a decryption key. Stated as a real gap, not silently
worked around.
"""
from __future__ import annotations


def _parse_host_header(data: bytes) -> str | None:
    for line in data.split(b"\r\n"):
        if line.lower().startswith(b"host:"):
            return line.split(b":", 1)[1].strip().decode("ascii", errors="replace")
    return None


def extract_domains(pcap_path: str) -> dict[str, dict]:
    """Returns {source_ip: {"dns": [names...], "http": [hosts...]}},
    both lists sorted for deterministic output."""
    from scapy.all import rdpcap  # imported here, not at module load, so
    from scapy.layers.dns import DNS  # importing drift.claims/drift.check
    from scapy.layers.inet import IP, TCP  # never requires scapy at all
    from scapy.packet import Raw

    packets = rdpcap(pcap_path)
    result: dict[str, dict] = {}

    def bucket(ip: str) -> dict:
        return result.setdefault(ip, {"dns": set(), "http": set()})

    for pkt in packets:
        if IP not in pkt:
            continue
        src = pkt[IP].src

        # qr == 0 is a query, not a response -- the querier is the device
        # actually asking, which is who this attributes the lookup to.
        # qd is a PacketListField (scapy's newer versions warn on treating
        # it as a single record) -- indexed explicitly, not accessed as if
        # it were one object, so this doesn't silently break when a future
        # scapy release removes the deprecated single-object shim.
        if DNS in pkt and pkt[DNS].qd and pkt[DNS].qr == 0:
            qname = pkt[DNS].qd[0].qname
            if isinstance(qname, bytes):
                qname = qname.decode("ascii", errors="replace")
            bucket(src)["dns"].add(qname.rstrip("."))

        if TCP in pkt and Raw in pkt:
            data = bytes(pkt[Raw])
            if data.startswith((b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ")):
                host = _parse_host_header(data)
                if host:
                    bucket(src)["http"].add(host)

    return {ip: {"dns": sorted(v["dns"]), "http": sorted(v["http"])} for ip, v in result.items()}
