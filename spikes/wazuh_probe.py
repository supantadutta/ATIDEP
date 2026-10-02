"""Spike S1/S2 helper: talk to the Wazuh API with the standard library only.

Usage: python spikes/wazuh_probe.py logtest <event.json> [log_format] [location]
Environment: WAZUH_API_URL (default https://localhost:55000), WAZUH_API_USER, WAZUH_API_PASSWORD.
TLS verification is off because the lab manager uses a self-signed certificate.
"""
from __future__ import annotations

import base64
import json
import os
import ssl
import sys
import urllib.error
import urllib.request

URL = os.environ.get("WAZUH_API_URL", "https://localhost:55000")
USER = os.environ.get("WAZUH_API_USER", "wazuh-wui")
PASSWORD = os.environ.get("WAZUH_API_PASSWORD", "MyS3cr37P450r.*-")
_CTX = ssl.create_default_context()
_CTX.check_hostname = False
_CTX.verify_mode = ssl.CERT_NONE


def call(method: str, path: str, token: str | None = None, body: dict | None = None,
         raw: bool = False):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(URL + path, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, context=_CTX, timeout=30) as resp:
            text = resp.read().decode()
    except urllib.error.HTTPError as err:
        text = err.read().decode()
    return text if raw else json.loads(text)


def token(user: str = USER, password: str = PASSWORD) -> str:
    basic = base64.b64encode(f"{user}:{password}".encode()).decode()
    req = urllib.request.Request(URL + "/security/user/authenticate?raw=true", method="POST",
                                 headers={"Authorization": f"Basic {basic}"})
    with urllib.request.urlopen(req, context=_CTX, timeout=30) as resp:
        return resp.read().decode().strip()


def logtest(tok: str, event: str, log_format: str, location: str, session: str | None = None):
    body = {"event": event, "log_format": log_format, "location": location}
    if session:
        body["token"] = session
    return call("PUT", "/logtest", tok, body)


if __name__ == "__main__":
    if len(sys.argv) >= 3 and sys.argv[1] == "logtest":
        ev = open(sys.argv[2], encoding="utf-8").read()
        ev = json.dumps(json.loads(ev), separators=(",", ":"))
        fmt = sys.argv[3] if len(sys.argv) > 3 else "eventchannel"
        loc = sys.argv[4] if len(sys.argv) > 4 else "EventChannel"
        print(json.dumps(logtest(token(), ev, fmt, loc), indent=1))
    else:
        print(__doc__)
