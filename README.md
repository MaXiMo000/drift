# drift

[![ci](https://github.com/MaXiMo000/drift/actions/workflows/ci.yml/badge.svg)](https://github.com/MaXiMo000/drift/actions/workflows/ci.yml)

**Does a device's real network traffic match what it's declared to be
allowed to contact? Checked against a real packet capture.**

[`witness`](https://github.com/MaXiMo000/witness) checks a website's own
traffic against its declared privacy claims, from inside a browser.
`drift` is the same idea pushed past that ceiling: a device on your own
network — anything, not just something with a browser in it — checked
against a declared allow-list by reading what it actually sent, from a
packet capture.

```
$ drift check http.cap claims.yaml
[XX] 145.254.160.237: 'test workstation' contacted domain(s) outside its declared allow-list: pagead2.googlesyndication.com

0/1 pass, 1 fail
```

(Real output — see "Tested against real traffic" below for what capture
this is and why.)

## Read this before anything else: what's actually verified here

The idea this comes from (see the portfolio audit) is a **Raspberry Pi
acting as a live network tap on a real home network**, checking a real
smart-home device's real traffic in real time. **That deployment is not
built or tested here** — this session has no access to a Raspberry Pi, a
real IoT device, or a real home network to verify any of it against, and
building software nobody can verify would be the one thing this whole
portfolio has consistently refused to do.

What genuinely is built and tested: the analysis core -- reading a
`.pcap`/`.pcapng` file, working out what each device contacted (DNS
lookups, TLS SNI, HTTP `Host:` headers, and IPs it reached without
naming), and checking that against a declared allow-list or the
manufacturer's own MUD file. That core doesn't care whether the capture
came from a live Pi tap, a router's own packet-capture feature, or a file
someone handed you -- a `.pcap` file is a `.pcap` file. **Wiring this to
a live tap on real hardware is real, unstarted future work**, stated
plainly rather than implied by silence.

## Scope

Same discipline as `witness`: this is for checking traffic *you* captured
on a network *you* own, against claims *you* declared. It has no notion
of any real device manufacturer's actual claims and ships with no data
about any real product.

## Install

```
pip install drift-evidence   # the command it installs is `drift`
```

(`drift` was already taken on PyPI — same story as most siblings in this
portfolio.)

## Use

Declare what each device is allowed to contact, in `claims.yaml`:

```yaml
devices:
  - id: "192.168.1.42"             # an IP -- or a MAC, "aa:bb:cc:dd:ee:ff",
    name: "smart bulb"             #   which survives a DHCP lease change
    allowed_domains:
      - vendor.example.com         # exactly this domain
      - "*.cdn.example.net"        # any subdomain of cdn.example.net, at any depth
    allowed_ips:                   # direct-IP contacts that are fine (optional)
      - "203.0.113.0/24"
    mud: bulb.mud.json             # the maker's RFC 8520 MUD file (optional)
```

A plain entry matches only itself: `vendor.example.com` does not cover
`telemetry.vendor.example.com`. A leading `*.` covers every subdomain but
not the domain itself, so list both if both are allowed. No other wildcard
form is accepted, so an allow-list never quietly covers more than it names.

**MUD files.** [RFC 8520](https://www.rfc-editor.org/rfc/rfc8520)
Manufacturer Usage Descriptions are the IETF standard for a manufacturer
to publish exactly what its device needs to talk to. Point `mud:` at one
(a path relative to `claims.yaml`) and every DNS name in its access lists
joins the allow-list -- so the check becomes "does this device do only
what its maker says it does," in the maker's own words.

Then check a real capture against it:

```
drift check capture.pcap claims.yaml
```

A device with no entry in `claims.yaml` reads `unverified`, never a
silent pass -- same three-status discipline as every claim-checking tool
in this portfolio. `--json` prints the full report. Exit code `1` if any
device failed.

**Don't have a claims file yet?** `drift learn` writes one from what a
capture shows:

```
drift learn capture.pcap --device 192.168.1.42 --by-mac > claims.yaml
```

It's a baseline to review, not something to trust blindly: anything the
device was already doing wrong during that capture is now in its
allow-list. Capture a fresh setup, learn once, then check every later
capture against it -- that's what catches a firmware update that starts
talking to somewhere new.

## How domains are actually extracted

Four signals, none of which needs anything decrypted:

- **DNS query names** -- the device asking "where is X", visible even when
  the connection to X itself is encrypted.
- **TLS SNI** -- the server name a TLS ClientHello sends in the clear
  before encryption starts. This names almost every HTTPS connection a
  modern device makes, including ones to a host it resolved some other way
  (DNS-over-HTTPS, an answer cached from before the capture started).
  ClientHellos split across TCP segments -- common now that post-quantum
  key shares make them bigger than one packet -- are reassembled first.
- **HTTP `Host:` headers** -- cleartext HTTP only.
- **Direct IP contacts** -- connections to a public address the device
  never looked up (no DNS answer anywhere in the capture) and never named
  (no SNI, no `Host:`). A device that talks to hardcoded IPs is exactly the
  one a DNS-only check misses. Each one fails the device unless it's in
  `allowed_ips`. Local-network traffic is never counted.

Devices are the addresses that *initiated* something; a server that only
answered never shows up as a device.

## What this does NOT do

- **Doesn't decrypt QUIC.** HTTP/3's ClientHello is encrypted with keys
  derived from the connection ID -- recoverable, but real work of its own.
  A QUIC connection to an address the device never resolved over plain DNS
  therefore shows up as a direct-IP contact, not by name.
- **Doesn't see names inside DNS-over-HTTPS** -- only the TLS SNI of the
  DoH server itself.
- **No live capture of anything.** `drift` reads a `.pcap` file that
  already exists; it has no code that touches a network interface. Making
  one (a Raspberry Pi tap, a router's mirror port, `tcpdump` itself) is
  the caller's job.
- **IP identity across a capture.** A claims file can name a device by
  MAC, and drift records the MAC seen for each source IP. But within one
  capture, if two devices held the same IP at different times, they're
  still counted as one.

## Privacy

Everything stays on the machine `drift` runs on. It makes no network
calls of its own -- it reads the `.pcap` file from disk, streamed, and the
report goes to stdout or a `--json` file you name; nothing is uploaded
or phoned home anywhere.

The thing to actually be careful of is upstream of drift, not in it: a
`.pcap` captured on a shared network (a router's mirror port, a home
Wi-Fi capture) records *every* device's traffic that happened to be on
the wire, not just the one you're checking. `extract_domains` (in
`pcap.py`) buckets by every source IP it sees, and `check_pcap` reports
on every one of them -- a device with no entry in `claims.yaml` still
comes back `unverified`, **with its full list of observed domains
included in the report**, exactly the same as a declared device's would
be. Point drift at a capture that includes a housemate's phone or a
guest's laptop, and their browsing domains end up in your output, not
just your smart bulb's.

That's not a bug to fix -- filtering out "devices you didn't mean to
capture" isn't something drift can know how to do, since it has no way
to tell an incidental bystander's IP from a device you meant to declare
later. It's a fact about what a shared-network capture *is*, and worth
knowing before you paste a report somewhere or hand it to someone else:
capture only what you mean to, and treat the report as covering
everyone who was on the network at the time, not just the device named
in your claims file.

## Tested against real traffic, not synthetic fixtures

`tests/fixtures/http.cap` is a real capture downloaded from
[Wireshark's own official sample-captures page](https://wiki.wireshark.org/SampleCaptures)
(see `tests/fixtures/PROVENANCE.md`) — 2004-era traffic of a client
requesting a page from `www.ethereal.com` (Wireshark's former name)
whose response pulled in a Google AdSense ad from
`pagead2.googlesyndication.com`. That's a real DNS query *and* a real
HTTP request to an undeclared third party, sitting in a 20-year-old
capture nobody built for this purpose — exactly the shape `drift` exists
to catch, found in genuine traffic rather than constructed to prove a
point.

## Tests

```
pip install -e .
python tests/test_pcap.py      # extraction, against the real fixture above
python tests/test_signals.py   # SNI, direct IPs, MAC ids, allowed_ips, MUD, learn
python tests/test_claims.py    # claims.yaml validation
python tests/test_check.py     # pass/fail/unverified classification
python tests/test_cli.py       # the real CLI entry point, against the real fixture
```

`test_signals.py` uses a real ClientHello produced by the local OpenSSL
(through Python's `ssl` module), split across two TCP segments inside a
capture generated with scapy -- a real device's traffic can't be
committed to a public repo, but the bytes being parsed are real.

MIT licensed.
