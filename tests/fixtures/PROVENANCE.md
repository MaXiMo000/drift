# `http.cap`

Downloaded directly from Wireshark's own official sample-captures page:
<https://wiki.wireshark.org/SampleCaptures> — listed there as "A simple
HTTP request and response," published by the Wireshark project
specifically for tool developers and learners to test against, the same
"official, explicitly for this purpose" standard this program has already
held other real-world fixtures to (LabLedger's Quest/LabCorp sample lab
reports, this same session).

Real traffic from 2004: a client (`145.254.160.237`) requesting
`http://www.ethereal.com/download.html` (Ethereal being Wireshark's
former name), whose response pulled in a Google AdSense ad from
`pagead2.googlesyndication.com` — a real DNS query *and* a real HTTP
request to a third-party ad-serving domain, alongside the "declared"
domain. That's not staged for this repo: it's exactly the "declared one
thing, actually did another" shape `drift` exists to catch, sitting
un-modified in a 20-year-old capture nobody built for this purpose.

Contains no personal data — a client fetching a public download page and
loading a public ad network, both long-defunct as specific endpoints.
