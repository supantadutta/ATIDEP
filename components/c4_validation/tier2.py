"""Tier 2 test harness: replay events through a real Wazuh manager's analysis pipeline
(blueprint §20.6, ADR-001 decisions 2 and 3).

This is a **test tool**, not the deployment adapter. It needs host access to the lab container
(``docker exec``/``docker cp``) to write Windows events to the analysis engine's queue socket
and to read ``alerts.json``, because ``wazuh-logtest`` cannot run the Windows event decoder.
It has its own allowlist, only talks to a manager named by the caller, and must never be
pointed at a production system.

Calls to the manager API are limited to authentication, uploading ATIDEP-named rule and list
files, and a restart. A rule or list upload counts as failed if the *response body* reports
failed items, whatever the HTTP status (ADR-001 F9).
"""

from __future__ import annotations

import base64
import json
import os
import re
import ssl
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from components.c4_validation.event_formats import to_queue_message

CONTAINER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
RULE_FILE_RE = re.compile(r"^\d{4}-atidep_[a-z0-9_]{1,40}\.xml$")
LIST_FILE_RE = re.compile(r"^atidep-[a-z0-9-]{1,40}$")
CANDIDATE_RULE_FILE = "0990-atidep_tier2.xml"
OSSEC_CONF = "/var/ossec/etc/ossec.conf"
ALERTS = "/var/ossec/logs/alerts/alerts.json"
INJECT_SCRIPT = (
    "import json, socket, time\n"
    "s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)\n"
    "s.connect('/var/ossec/queue/sockets/queue')\n"
    "for i, line in enumerate(open('/tmp/atidep_events.jsonl')):\n"
    "    s.send(json.loads(line).encode())\n"
    "    if i % 50 == 49:\n"
    "        time.sleep(0.2)\n")


# A valid rule file that can never match. The API rejects an empty <group> and a <decoded_as>
# naming a decoder that does not exist (ADR-001 F15), so a scratch or retired file is
# overwritten with a level-0 rule under a real parent whose pattern cannot match.
NEUTRAL_RULES_XML = (
    '<group name="atidep,neutral,">\n'
    '  <rule id="119999" level="0">\n'
    "    <if_sid>61603</if_sid>\n"
    '    <field name="win.eventdata.commandLine" type="pcre2">(?!)</field>\n'
    "    <description>ATIDEP placeholder: matches nothing</description>\n"
    "  </rule>\n</group>\n")


class LabError(Exception):
    pass


@dataclass(frozen=True)
class Fired:
    rule_id: int
    level: int
    description: str


@dataclass
class ReplayResult:
    fired: dict[str, list[Fired]] = field(default_factory=dict)   # eventRecordID -> alerts

    def rule_ids(self, record_id: str) -> list[int]:
        return [f.rule_id for f in self.fired.get(record_id, [])]

    def matched(self, record_id: str, rule_ids: set[int]) -> bool:
        return any(r in rule_ids for r in self.rule_ids(record_id))


class LabManager:
    def __init__(self, container: str = "wazuh", *, api_url: str | None = None,
                 user: str | None = None, password: str | None = None,
                 restart_timeout: float = 120.0) -> None:
        if not CONTAINER_RE.match(container):
            raise LabError(f"invalid container name {container!r}")
        self.container = container
        self.api_url = (api_url or os.environ.get("WAZUH_API_URL", "https://localhost:55000")
                        ).rstrip("/")
        self.user = user or os.environ.get("WAZUH_API_USER", "")
        self.password = password or os.environ.get("WAZUH_API_PASSWORD", "")
        if not (self.user and self.password):
            raise LabError("set WAZUH_API_USER and WAZUH_API_PASSWORD for the lab manager")
        self.restart_timeout = restart_timeout
        # The lab manager uses a self-signed certificate; the connection is to the local host.
        self._ctx = ssl.create_default_context()
        self._ctx.check_hostname = False
        self._ctx.verify_mode = ssl.CERT_NONE

    # ---- container access -----------------------------------------------------------------
    def sh(self, *args: str, timeout: float = 60.0) -> str:
        proc = subprocess.run(["docker", "exec", self.container, *args], capture_output=True,
                              text=True, timeout=timeout, check=False)
        return proc.stdout

    def available(self) -> bool:
        try:
            out = subprocess.run(["docker", "inspect", "-f", "{{.State.Running}}",
                                  self.container], capture_output=True, text=True, timeout=10,
                                 check=False).stdout.strip()
        except (OSError, subprocess.TimeoutExpired):
            return False
        return out == "true"

    def _copy_in(self, local: Path, remote: str) -> None:
        proc = subprocess.run(["docker", "cp", str(local), f"{self.container}:{remote}"],
                              capture_output=True, text=True, timeout=60, check=False)
        if proc.returncode != 0:
            raise LabError(f"docker cp failed: {proc.stderr.strip()[:200]}")

    # ---- API ------------------------------------------------------------------------------
    def _request(self, method: str, path: str, *, token: str | None = None,
                 body: bytes | None = None, headers: dict[str, str] | None = None) -> Any:
        req = urllib.request.Request(self.api_url + path, data=body, method=method,
                                     headers={**(headers or {}),
                                              **({"Authorization": f"Bearer {token}"}
                                                 if token else {})})
        try:
            with urllib.request.urlopen(req, context=self._ctx, timeout=60) as resp:
                text = resp.read().decode()
        except urllib.error.HTTPError as err:
            text = err.read().decode()
        except OSError as exc:
            raise LabError(f"manager API unreachable: {exc}") from exc
        return text

    def token(self) -> str:
        basic = base64.b64encode(f"{self.user}:{self.password}".encode()).decode()
        tok = self._request("POST", "/security/user/authenticate?raw=true",
                            headers={"Authorization": f"Basic {basic}"}).strip()
        if not tok or tok.startswith("{"):
            raise LabError("authentication to the manager API failed")
        return tok

    def _upload(self, kind: str, name: str, content: str, token: str) -> None:
        text = self._request("PUT", f"/{kind}/files/{name}?overwrite=true", token=token,
                             body=content.encode("utf-8"),
                             headers={"Content-Type": "application/octet-stream"})
        try:
            doc = json.loads(text)
        except ValueError as exc:
            raise LabError(f"unreadable API response uploading {name}") from exc
        data = doc.get("data", {})
        if doc.get("error", 0) != 0 or data.get("total_failed_items", 0) > 0:
            failed = data.get("failed_items", [{}])
            msg = failed[0].get("error", {}).get("message") if failed else doc.get("detail")
            raise LabError(f"{kind} upload {name} failed: {msg or doc.get('title', 'error')}")

    def upload_rule_file(self, name: str, xml: str, token: str | None = None) -> None:
        if not RULE_FILE_RE.match(name):
            raise LabError(f"rule file name {name!r} is not an ATIDEP name")
        self._upload("rules", name, xml, token or self.token())

    def upload_list(self, name: str, content: str, token: str | None = None) -> None:
        if not LIST_FILE_RE.match(name):
            raise LabError(f"list name {name!r} is not an ATIDEP name")
        self._upload("lists", name, content, token or self.token())

    def copy_out(self, remote: str, local: Path | str) -> None:
        proc = subprocess.run(["docker", "cp", f"{self.container}:{remote}", str(local)],
                              capture_output=True, text=True, timeout=60, check=False)
        if proc.returncode != 0:
            raise LabError(f"docker cp failed: {proc.stderr.strip()[:200]}")

    def create_deploy_user(self, user: str, password: str, actions: list[str]) -> None:
        """The least-privilege API user the deployment adapter logs in as (spike S2): a policy
        with only the given actions, a role and a user. Uses the admin credentials."""
        tok = self.token()

        def call(method: str, path: str, body: dict | None = None) -> dict:
            text = self._request(method, path, token=tok, headers={"Content-Type":
                                 "application/json"}, body=json.dumps(body).encode()
                                 if body is not None else None)
            try:
                return json.loads(text)
            except ValueError:
                return {}

        def created_id(doc: dict) -> int:
            try:
                return doc["data"]["affected_items"][0]["id"]
            except (KeyError, IndexError, TypeError) as exc:
                raise LabError(f"could not create the API user: {str(doc)[:200]}") from exc

        for kind, key, ids in (("users", "username", "user_ids"), ("roles", "name", "role_ids"),
                               ("policies", "name", "policy_ids")):
            listing = call("GET", f"/security/{kind}?limit=500")
            for item in listing.get("data", {}).get("affected_items", []):
                if str(item.get(key, "")).startswith("atidep") or item.get(key) == user:
                    call("DELETE", f"/security/{kind}?{ids}={item['id']}")
        pid = created_id(call("POST", "/security/policies", {"name": "atidep_deploy", "policy": {
            "actions": actions, "resources": ["*:*:*", "rule:file:*", "list:file:*"],
            "effect": "allow"}}))
        rid = created_id(call("POST", "/security/roles", {"name": "atidep_role"}))
        uid = created_id(call("POST", "/security/users", {"username": user,
                                                          "password": password}))
        call("POST", f"/security/roles/{rid}/policies?policy_ids={pid}")
        call("POST", f"/security/users/{uid}/roles?role_ids={rid}")
        time.sleep(3)                 # tokens issued in the same second as an RBAC change die (F9)

    # ---- provisioning and restart -----------------------------------------------------------
    def declare_lists(self, names: list[str]) -> bool:
        """Make sure ``ossec.conf`` declares the lists. Returns True if it was changed (a
        restart is then needed). This edits the lab manager's own file through docker, as
        provisioning, and is not something the deployment adapter ever does."""
        for n in names:
            if not LIST_FILE_RE.match(n):
                raise LabError(f"list name {n!r} is not an ATIDEP name")
        conf = self.sh("cat", OSSEC_CONF)
        missing = [n for n in names if f"etc/lists/{n}</list>" not in conf]
        if not missing:
            return False
        add = "".join(f"    <list>etc/lists/{n}</list>\\n" for n in missing)
        self.sh("sh", "-c", f"sed -i 's#</ruleset>#{add}  </ruleset>#' {OSSEC_CONF}")
        if any(f"etc/lists/{n}</list>" not in self.sh("cat", OSSEC_CONF) for n in missing):
            raise LabError("could not declare the lists in ossec.conf")
        return True

    def _started_count(self) -> str:
        return self.sh("sh", "-c",
                       "grep -c 'wazuh-analysisd: INFO: Started' /var/ossec/logs/ossec.log"
                       ).strip()

    def restart(self, token: str | None = None) -> float:
        before = self._started_count()
        t0 = time.time()
        self._request("PUT", "/manager/restart", token=token or self.token())
        while time.time() - t0 < self.restart_timeout:
            time.sleep(2)
            if self._started_count() != before:
                while time.time() - t0 < self.restart_timeout:   # the API comes up last
                    time.sleep(2)
                    try:
                        self.token()
                        return time.time() - t0
                    except LabError:
                        continue
        raise LabError("the manager did not restart in time")

    def provision(self, lists: dict[str, str]) -> None:
        """Idempotent lab setup: declare the ATIDEP lists and create the ones that are
        missing, with the content given (never empty: the API refuses an empty list)."""
        changed = self.declare_lists(list(lists))
        tok = self.token()
        existing = self.sh("ls", "/var/ossec/etc/lists").split()
        for n, content in lists.items():
            if n not in existing:
                self.upload_list(n, content, tok)
                changed = True
        if changed:
            self.restart()

    # ---- replay ---------------------------------------------------------------------------
    def reset_atidep_files(self, lists: dict[str, str]) -> None:
        """Lab hygiene (admin credentials): neutralise every ATIDEP rule file and give every
        ATIDEP list the sentinel content, so a failed earlier run cannot poison the next.
        Restarts the manager only if something had to change."""
        tok = self.token()
        doc = json.loads(self._request("GET", "/rules/files?search=atidep&limit=500", token=tok))
        changed = False
        for item in doc.get("data", {}).get("affected_items", []):
            name = item["filename"]
            if not RULE_FILE_RE.match(name):
                continue
            current = self._request("GET", f"/rules/files/{name}?raw=true", token=tok)
            if current != NEUTRAL_RULES_XML:
                self.upload_rule_file(name, NEUTRAL_RULES_XML, tok)
                changed = True
        for name, content in lists.items():
            current = self._request("GET", f"/lists/files/{name}?raw=true", token=tok)
            if current != content:
                self.upload_list(name, content, tok)
                changed = True
        if changed:
            self.restart()

    def reset_candidate(self) -> None:
        """Neutralise the Tier 2 candidate file so a leftover rule cannot load at the next
        restart. No restart is needed: the engine only reads the file when it starts."""
        self.upload_rule_file(CANDIDATE_RULE_FILE, NEUTRAL_RULES_XML)

    def deploy_candidate(self, rules_xml: str, lists: dict[str, str] | None = None) -> float:
        """Install the rule under test (alone, in one file) and the lists it needs, then
        restart. Returns the restart time in seconds."""
        tok = self.token()
        for name, content in (lists or {}).items():
            self.upload_list(name, content, tok)
        self.upload_rule_file(CANDIDATE_RULE_FILE, rules_xml, tok)
        return self.restart()

    def replay(self, events: list[dict[str, Any]], *, settle: float = 3.0,
               max_wait: float = 60.0) -> ReplayResult:
        """Send structured Sysmon events as raw agent messages and collect the alerts."""
        if not events:
            return ReplayResult()
        ids = [str(e["win"]["system"]["eventRecordID"]) for e in events]
        if len(set(ids)) != len(ids):
            raise LabError("event record IDs must be unique within one replay")
        with tempfile.TemporaryDirectory() as tmp:
            ev_file, script = Path(tmp) / "events.jsonl", Path(tmp) / "inject.py"
            ev_file.write_text("\n".join(json.dumps(to_queue_message(e)) for e in events) + "\n",
                               encoding="utf-8")
            script.write_text(INJECT_SCRIPT, encoding="utf-8")
            self._copy_in(ev_file, "/tmp/atidep_events.jsonl")
            self._copy_in(script, "/tmp/atidep_inject.py")
        marker = int(self.sh("sh", "-c", f"wc -l < {ALERTS}").strip() or 0)
        self.sh("/var/ossec/framework/python/bin/python3", "/tmp/atidep_inject.py")
        time.sleep(settle + 0.01 * len(events))
        deadline, last, stable = time.time() + max_wait, -1, 0
        while time.time() < deadline:
            size = int(self.sh("sh", "-c", f"wc -l < {ALERTS}").strip() or 0)
            stable = stable + 1 if size == last else 0
            if stable >= 2:
                break
            last = size
            time.sleep(1.0)
        raw = self.sh("sh", "-c", f"tail -n +{marker + 1} {ALERTS}")
        result = ReplayResult()
        wanted = set(ids)
        for line in raw.splitlines():
            try:
                alert = json.loads(line)
                rec = str(alert["data"]["win"]["system"]["eventRecordID"])
            except (ValueError, KeyError, TypeError):
                continue
            if rec in wanted:
                rule = alert["rule"]
                result.fired.setdefault(rec, []).append(
                    Fired(int(rule["id"]), int(rule["level"]), rule.get("description", "")))
        return result
