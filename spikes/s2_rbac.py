"""Spike S2: create a least-privilege RBAC user for ATIDEP and test what it can and cannot do."""
from __future__ import annotations

import json
import sys
import time
import urllib.request

sys.path.insert(0, "spikes")
import wazuh_probe as w  # noqa: E402

ACTIONS = ["logtest:run", "rules:read", "rules:update", "lists:read", "lists:update",
           "manager:restart"]
USER, PASSWORD = "atidep", "Atidep#Lab2026x"


def api(tok, method, path, body=None, ctype="application/json", raw=None):
    data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
    req = urllib.request.Request(w.URL + path, data=data, method=method,
                                 headers={"Authorization": f"Bearer {tok}", "Content-Type": ctype})
    try:
        with urllib.request.urlopen(req, context=w._CTX, timeout=30) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"{}")
        except Exception:
            return e.code, {}


def main() -> None:
    admin = w.token()
    # clean slate, then create (users first, then roles, then policies)
    for kind, key, ids in (("users", "username", "user_ids"), ("roles", "name", "role_ids"),
                           ("policies", "name", "policy_ids")):
        _, d = api(admin, "GET", f"/security/{kind}?limit=500")
        for it in d.get("data", {}).get("affected_items", []):
            if str(it.get(key, "")).startswith("atidep"):
                api(admin, "DELETE", f"/security/{kind}?{ids}={it['id']}")
    s, d = api(admin, "POST", "/security/policies", {"name": "atidep_deploy", "policy": {
        "actions": ACTIONS, "resources": ["*:*:*"], "effect": "allow"}})
    pid = d["data"]["affected_items"][0]["id"]
    s, d = api(admin, "POST", "/security/roles", {"name": "atidep_role"})
    rid = d["data"]["affected_items"][0]["id"]
    s, d = api(admin, "POST", "/security/users", {"username": USER, "password": PASSWORD})
    uid = d["data"]["affected_items"][0]["id"]
    print("link policy->role:", api(admin, "POST", f"/security/roles/{rid}/policies?policy_ids={pid}")[0],
          " role->user:", api(admin, "POST", f"/security/users/{uid}/roles?role_ids={rid}")[0])
    time.sleep(3)  # tokens issued in the same second as an RBAC change are invalidated
    tok = w.token(USER, PASSWORD)
    ok_xml = b"<group name='atidep,'><rule id='110900' level='3'><if_sid>61603</if_sid><description>rbac probe</description></rule></group>"
    tests = [
        ("ALLOW  PUT /logtest", "PUT", "/logtest", {"event": "x", "log_format": "syslog", "location": "t"}, None),
        ("ALLOW  GET /rules/files", "GET", "/rules/files?limit=1", None, None),
        ("ALLOW  PUT /rules/files/{atidep file}", "PUT", "/rules/files/0990-atidep_rbac_probe.xml?overwrite=true", None, ok_xml),
        ("ALLOW  PUT /lists/files/{atidep list}", "PUT", "/lists/files/atidep-rbac-probe?overwrite=true", None, b"k:\n"),
        ("DENY   GET /agents", "GET", "/agents?limit=1", None, None),
        ("DENY   GET /security/users", "GET", "/security/users", None, None),
        ("DENY   PUT /manager/configuration", "PUT", "/manager/configuration", None, b"<ossec_config/>"),
        ("DENY   DELETE /rules/files/{file}", "DELETE", "/rules/files/0990-atidep_rbac_probe.xml", None, None),
        ("DENY   DELETE /lists/files/{list}", "DELETE", "/lists/files/atidep-rbac-probe", None, None),
        ("DENY   PUT /active-response", "PUT", "/active-response", {"command": "restart-wazuh0"}, None),
        ("NOTE   PUT /rules/files/{ANY other file}", "PUT", "/rules/files/0991-not-atidep.xml?overwrite=true", None, ok_xml),
    ]
    for label, method, path, body, raw in tests:
        ctype = "application/octet-stream" if raw is not None else "application/json"
        status, data = api(tok, method, path, body, ctype, raw)
        failed = data.get("data", {}).get("total_failed_items") if isinstance(data.get("data"), dict) else None
        detail = data.get("title") or data.get("detail") or ""
        print(f"{label:46} http={status} error={data.get('error')} failed_items={failed} {str(detail)[:60]}")
    # clean up probe artefacts as admin
    for path in ("/rules/files/0990-atidep_rbac_probe.xml", "/rules/files/0991-not-atidep.xml", "/lists/files/atidep-rbac-probe"):
        api(admin, "DELETE", path)


if __name__ == "__main__":
    main()
