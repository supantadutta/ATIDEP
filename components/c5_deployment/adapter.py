"""Wazuh deployment adapter: REST API only (blueprint §20.5, ADR-001 decision 7).

* Every call is checked against a hard allowlist of ``METHOD /path`` patterns (from
  ``policies.deployment.wazuh_api_allowlist``) before it is made. RBAC cannot limit file names
  (F10), so file names are also checked here: rule files ``NNNN-atidep_*.xml`` and lists
  ``atidep-*``.
* The connection verifies TLS against a pinned certificate file; there is no switch that turns
  verification off.
* An upload counts as failed when the **response body** reports failed items, whatever the HTTP
  status (F9). The adapter never reads or writes anything except through the API.
* A restart is confirmed by the logtest session token changing (sessions live in the running
  analysis engine and do not survive a restart), not by a timer.
"""

from __future__ import annotations

import base64
import fnmatch
import json
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

RULE_FILE_RE = re.compile(r"^\d{4}-atidep_[a-z0-9_]{1,40}\.xml$")
LIST_FILE_RE = re.compile(r"^atidep-[a-z0-9-]{1,40}$")
# Needed in addition to the configured allowlist: the login itself.
ALWAYS_ALLOWED = ("POST /security/user/authenticate",)
# rules:delete and lists:delete are needed because the framework overwrites an existing file
# by deleting it first and checks that permission (ADR-001 F16). manager:read is needed because
# the restart endpoint checks it as well as manager:restart (F17); it also lets the role read
# the manager configuration through the API, which the adapter never asks for. The adapter
# never calls a DELETE endpoint: they are not on its allowlist.
REQUIRED_ACTIONS = ("logtest:run", "rules:read", "rules:update", "rules:delete", "lists:read",
                    "lists:update", "lists:delete", "manager:read", "manager:restart")
NEUTRAL_RULES_XML = (
    '<group name="atidep,neutral,">\n'
    '  <rule id="119999" level="0">\n'
    "    <if_sid>61603</if_sid>\n"
    '    <field name="win.eventdata.commandLine" type="pcre2">(?!)</field>\n'
    "    <description>ATIDEP placeholder: matches nothing</description>\n"
    "  </rule>\n</group>\n")


class AdapterError(Exception):
    pass


class NotAllowed(AdapterError):
    pass


@dataclass
class LogtestResult:
    fired_rule: int | None
    level: int | None
    messages: list[str] = field(default_factory=list)


def _clean(path: str) -> str:
    return urllib.parse.urlsplit(path).path


class WazuhAdapter:
    def __init__(self, api_url: str, user: str, password: str, *, ca_file: str,
                 allowlist: list[str], timeout: float = 60.0,
                 sleep: Callable[[float], None] = time.sleep) -> None:
        if not api_url.startswith("https://"):
            raise AdapterError("the manager API must be reached over https")
        if not (user and password):
            raise AdapterError("API credentials are required")
        self.api_url = api_url.rstrip("/")
        self._user, self._password = user, password
        self.allowlist = list(allowlist) + list(ALWAYS_ALLOWED)
        self.timeout, self._sleep = timeout, sleep
        self._ctx = ssl.create_default_context(cafile=ca_file)
        self._ctx.check_hostname = False       # self-signed lab certificate; the pin is the trust
        self._ctx.verify_mode = ssl.CERT_REQUIRED
        self._token: str | None = None

    # ---- guarded transport ------------------------------------------------------------------
    def _check(self, method: str, path: str) -> None:
        """``*`` in a pattern stands for exactly one path segment, so it cannot span ``/`` or
        match ``..``; paths with empty, dot or percent-encoded segments are refused outright."""
        clean = _clean(path)
        segments = clean.split("/")
        if not clean.startswith("/") or "%" in clean or "\\" in clean or any(
                s in ("", ".", "..") for s in segments[1:]):
            raise NotAllowed(f"{method} {clean} is not an acceptable path")
        for pattern in self.allowlist:
            pm, _, pp = pattern.partition(" ")
            psegs = pp.split("/")
            if pm == method and len(psegs) == len(segments) and all(
                    fnmatch.fnmatchcase(s, p) for s, p in zip(segments, psegs, strict=True)):
                return
        raise NotAllowed(f"{method} {clean} is not on the allowlist")

    def _raw(self, method: str, path: str, *, body: bytes | None = None,
             headers: dict[str, str] | None = None, auth: bool = True) -> tuple[int, str]:
        self._check(method, path)
        h = dict(headers or {})
        if auth:
            h["Authorization"] = f"Bearer {self._token_value()}"
        req = urllib.request.Request(self.api_url + path, data=body, method=method, headers=h)
        try:
            with urllib.request.urlopen(req, context=self._ctx, timeout=self.timeout) as resp:
                return resp.status, resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as err:
            return err.code, err.read().decode("utf-8", "replace")
        except (OSError, ssl.SSLError) as exc:
            raise AdapterError(f"manager API unreachable: {exc}") from exc

    def _token_value(self) -> str:
        if self._token is None:
            basic = base64.b64encode(f"{self._user}:{self._password}".encode()).decode()
            status, text = self._raw("POST", "/security/user/authenticate?raw=true", auth=False,
                                     headers={"Authorization": f"Basic {basic}"})
            if status != 200 or not text.strip() or text.lstrip().startswith("{"):
                raise AdapterError("authentication to the manager API failed")
            self._token = text.strip()
        return self._token

    def _json(self, method: str, path: str, **kw: Any) -> dict[str, Any]:
        status, text = self._raw(method, path, **kw)
        if status == 401:                              # expired or invalidated token: log in again
            self._token = None
            status, text = self._raw(method, path, **kw)
        try:
            return json.loads(text)
        except ValueError as exc:
            raise AdapterError(f"{method} {_clean(path)}: unreadable response ({status})") from exc

    @staticmethod
    def _failed(doc: dict[str, Any], what: str) -> None:
        data = doc.get("data", {})
        if doc.get("error", 0) != 0 or data.get("total_failed_items", 0) > 0:
            failed = data.get("failed_items") or [{}]
            msg = failed[0].get("error", {}).get("message") or doc.get("detail") \
                or doc.get("message") or doc.get("title", "error")
            raise AdapterError(f"{what} failed: {msg}")

    # ---- files ------------------------------------------------------------------------------
    @staticmethod
    def _file_text(status: int, text: str) -> str | None:
        """The stored text of a file, or None if there is none. For a missing file the manager
        answers with an error *document* (sometimes with HTTP 200), never with file content;
        a rule file or an indicator list never starts like a JSON object."""
        if status != 200:
            return None
        if text.lstrip().startswith("{"):
            try:
                doc = json.loads(text)
            except ValueError:
                return text
            if isinstance(doc, dict) and ("error" in doc or "title" in doc or "data" in doc):
                return None
        return text

    def get_rule_file(self, name: str) -> str | None:
        self._name(name, RULE_FILE_RE)
        return self._file_text(*self._raw("GET", f"/rules/files/{name}?raw=true"))

    def put_rule_file(self, name: str, content: str) -> None:
        self._name(name, RULE_FILE_RE)
        doc = self._json("PUT", f"/rules/files/{name}?overwrite=true", body=content.encode(),
                         headers={"Content-Type": "application/octet-stream"})
        self._failed(doc, f"rule file {name}")

    def get_list(self, name: str) -> str | None:
        self._name(name, LIST_FILE_RE)
        return self._file_text(*self._raw("GET", f"/lists/files/{name}?raw=true"))

    def put_list(self, name: str, content: str) -> None:
        self._name(name, LIST_FILE_RE)
        doc = self._json("PUT", f"/lists/files/{name}?overwrite=true", body=content.encode(),
                         headers={"Content-Type": "application/octet-stream"})
        self._failed(doc, f"list {name}")

    @staticmethod
    def _name(name: str, pattern: re.Pattern[str]) -> None:
        if not pattern.match(name):
            raise NotAllowed(f"{name!r} is not an ATIDEP file name")

    # ---- logtest ----------------------------------------------------------------------------
    def logtest(self, event: str, *, log_format: str = "json", location: str = "atidep"
                ) -> LogtestResult:
        doc = self._json("PUT", "/logtest", body=json.dumps(
            {"event": event, "log_format": log_format, "location": location}).encode(),
            headers={"Content-Type": "application/json"})
        if doc.get("error", 0) != 0:
            raise AdapterError(f"logtest failed: {doc.get('detail') or doc.get('title')}")
        out = doc.get("data", {}).get("output", {})
        rule = out.get("rule") or {}
        return LogtestResult(int(rule["id"]) if "id" in rule else None,
                             int(rule["level"]) if "level" in rule else None,
                             doc.get("data", {}).get("messages", []))

    # ---- restart ----------------------------------------------------------------------------
    def _session(self, token: str | None = None) -> str:
        """The logtest session token the engine hands out. A session started before a restart
        is unknown afterwards, so the engine returns a different token."""
        body: dict[str, Any] = {"event": "{}", "log_format": "json", "location": "atidep-probe"}
        if token:
            body["token"] = token
        doc = self._json("PUT", "/logtest", body=json.dumps(body).encode(),
                         headers={"Content-Type": "application/json"})
        tok = doc.get("data", {}).get("token")
        if doc.get("error", 0) != 0 or not tok:
            raise AdapterError("the engine did not return a logtest session")
        return str(tok)

    def restart(self, timeout: float = 180.0) -> float:
        before = self._session()
        t0 = time.monotonic()
        doc = self._json("PUT", "/manager/restart")
        self._failed(doc, "restart request")
        while time.monotonic() - t0 < timeout:
            self._sleep(2.0)
            self._token = None
            try:
                if self._session(before) != before:
                    return time.monotonic() - t0
            except AdapterError:
                continue                                   # the API is down while restarting
        raise AdapterError("the manager did not confirm a restart in time")
