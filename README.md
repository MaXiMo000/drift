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

What genuinely is built and tested: the actual analysis core — reading a
`.pcap`/`.pcapng` file, extracting which domains each device contacted
(via DNS queries and HTTP `Host:` headers), and checking that against a
declared allow-list. That core doesn't care whether the capture came from
a live Pi tap, a router's own packet-capture feature, or a file someone
handed you — a `.pcap` file is a `.pcap` file. **Wiring this to an actual
live tap on real hardware is real, unstarted future work**, stated
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

Declare which domains each device (identified by its IP in the capture)
is allowed to contact, in `claims.yaml`:

```yaml
devices:
  - id: "192.168.1.42"
    name: "smart bulb"
    allowed_domains:
      - vendor.example.com
```

Then check a real capture against it:

```
drift check capture.pcap claims.yaml
```

A device with no entry in `claims.yaml` reads `unverified`, never a
silent pass — same three-status discipline as every claim-checking tool
in this portfolio. `--json` prints the full report.

## How domains are actually extracted

Two signals, both read in the clear regardless of what runs on top of
them:

- **DNS query names** — the device asking "where is X" is visible even
  when the connection to X itself is fully encrypted. This is the signal
  that matters for a real modern device, whose actual traffic is mostly
  HTTPS.
- **HTTP `Host:` headers** — cleartext HTTP only, a strictly narrower
  signal, kept because it names a domain a request actually *reached*,
  not just one that was looked up.

## What this does NOT do

- **Can't read a domain out of an HTTPS/TLS connection.** That needs
  either the TLS ClientHello's SNI field (sent in the clear even over an
  otherwise-encrypted connection, and not read here) or a decryption key.
  Real, addable scope — not attempted in this version.
- **No live capture of anything.** `drift` reads a `.pcap` file that
  already exists; it has no code that touches a network interface. Making
  one (a Raspberry Pi tap, a router's mirror port, `tcpdump` itself) is
  the caller's job.
- **Doesn't distinguish which device asked from which device the traffic
  is actually *about*** beyond source IP. On a network with NAT or DHCP
  churn, the same IP can mean a different physical device over time — a
  real limitation of IP-based identification, not solved here.

## Privacy

Everything stays on the machine `drift` runs on. It makes no network
calls of its own -- `rdpcap` reads the `.pcap` file from disk, and the
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
python tests/test_pcap.py     # domain extraction, against the real fixture above
python tests/test_claims.py   # claims.yaml validation
python tests/test_check.py    # pass/fail/unverified classification
python tests/test_cli.py      # the real CLI entry point, against the real fixture
```

29 tests.

MIT licensed.
