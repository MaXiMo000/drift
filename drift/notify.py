"""One webhook POST when a check fails.

The payload carries `text` (what Slack and Mattermost read) and `content`
(what Discord reads) with the same summary, plus the structured results
for anything else. The URL comes from an environment variable named on the
command line: a webhook URL is a credential, and argv is not a place for
one.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

from .check import FAIL, UNVERIFIED


class NotifyError(Exception):
    pass


def summary(results: list[dict]) -> str:
    failed = [r for r in results if r["status"] == FAIL]
    unverified = sum(r["status"] == UNVERIFIED for r in results)
    if not failed:
        line = f"drift PASS: {len(results) - unverified} of {len(results)} device(s) stayed within their claims"
    else:
        line = f"drift FAIL: {len(failed)} of {len(results)} device(s) contacted undeclared destinations"
        for r in failed[:5]:
            where = (r["unexpected_domains"] + r["unexpected_ips"])[:3]
            line += f"\n- {r['device_id']}: {', '.join(where)}"
        if len(failed) > 5:
            line += f"\n- and {len(failed) - 5} more"
    if unverified:
        line += f"\n{unverified} device(s) had no claims to check against"
    return line[:1900]  # Discord's content limit is 2000


def send(results: list[dict], env_var: str, when: str = "fail", opener=urllib.request.urlopen) -> bool:
    """True if a notification went out."""
    if when == "fail" and not any(r["status"] == FAIL for r in results):
        return False
    url = os.environ.get(env_var)
    if not url:
        raise NotifyError(f"${env_var} is not set")
    if not url.startswith("https://") and not url.startswith(("http://localhost", "http://127.0.0.1")):
        raise NotifyError(f"${env_var} must be an https:// URL")
    text = summary(results)
    body = {"text": text, "content": text,
            "failed": [r["device_id"] for r in results if r["status"] == FAIL], "results": results}
    request = urllib.request.Request(url, data=json.dumps(body).encode(),
                                     headers={"Content-Type": "application/json"}, method="POST")
    try:
        with opener(request, timeout=30) as response:
            response.read()
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        # The URL itself is never in the message.
        raise NotifyError(f"the webhook in ${env_var} did not accept it: "
                          f"{getattr(exc, 'code', '') or type(exc).__name__}") from None
    return True
