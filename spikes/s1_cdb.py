"""Spike S1: CDB list behaviour through the real pipeline.

Checks: exact-match domains, subdomain and case behaviour, address lookups with prefix keys,
SHA-256 matching on Sysmon's combined hashes field, and whether a list change needs a restart.
"""
from __future__ import annotations

import json
import subprocess
import sys
import time
import urllib.request

sys.path.insert(0, "spikes")
sys.path.insert(0, ".")
import wazuh_probe as w  # noqa: E402

from components.c4_validation.event_formats import to_queue_message  # noqa: E402
from tests.events import sysmon_factory as f  # noqa: E402

HASH = "A" * 63 + "B"
RULES = f"""<group name="atidep,ioc,">
  <rule id="110101" level="10"><if_sid>61650</if_sid>
    <list field="win.eventdata.queryName" lookup="match_key">etc/lists/atidep-domains</list>
    <description>ATIDEP S1: DNS query for a listed domain</description></rule>
  <rule id="110102" level="10"><if_sid>61605</if_sid>
    <list field="win.eventdata.destinationIp" lookup="address_match_key">etc/lists/atidep-ips</list>
    <description>ATIDEP S1: connection to a listed address</description></rule>
  <rule id="110103" level="10"><if_sid>61603</if_sid>
    <field name="win.eventdata.hashes" type="pcre2">(?i)SHA256=({HASH})</field>
    <description>ATIDEP S1: process with a listed SHA-256 (regex alternation)</description></rule>
  <rule id="110104" level="10"><if_sid>61603</if_sid>
    <list field="win.eventdata.hashes" lookup="match_key">etc/lists/atidep-domains</list>
    <description>ATIDEP S1: probe whether a CDB key can match the combined hashes field</description></rule>
</group>
"""
CASES = [  # (record, label, event, expected rule)
    (5001, "dns listed", f.dns_query(5001, "bad.example.invalid"), "110101"),
    (5002, "dns not listed", f.dns_query(5002, "good.example.invalid"), None),
    (5003, "dns subdomain of listed", f.dns_query(5003, "sub.bad.example.invalid"), None),
    (5004, "dns listed, upper case", f.dns_query(5004, "BAD.EXAMPLE.INVALID"), None),
    (5005, "ip exact listed", f.network_connect(5005, "203.0.113.10"), "110102"),
    (5006, "ip inside listed /24 prefix", f.network_connect(5006, "198.51.100.77"), "110102"),
    (5007, "ip not listed", f.network_connect(5007, "192.0.2.5"), None),
    (5008, "process with listed sha256", f.process_create(5008, f.PS, "powershell.exe", "C:\\Windows\\explorer.exe", sha256=HASH), "110103"),
    (5009, "process with other sha256", f.process_create(5009, f.PS, "powershell.exe", "C:\\Windows\\explorer.exe", sha256="C" * 64), None),
]


def sh(*a: str) -> str:
    return subprocess.run(["docker", "exec", "wazuh", *a], capture_output=True, text=True).stdout


def put(tok: str, kind: str, name: str, body: str) -> dict:
    req = urllib.request.Request(w.URL + f"/{kind}/files/{name}?overwrite=true", data=body.encode(),
                                 method="PUT", headers={"Authorization": f"Bearer {tok}",
                                                        "Content-Type": "application/octet-stream"})
    with urllib.request.urlopen(req, context=w._CTX, timeout=30) as r:
        return json.loads(r.read())


def restart(tok: str) -> float:
    n0 = sh("sh", "-c", "grep -c 'wazuh-analysisd: INFO: Started' /var/ossec/logs/ossec.log").strip()
    t0 = time.time()
    w.call("PUT", "/manager/restart", tok)
    for _ in range(90):
        time.sleep(2)
        if sh("sh", "-c", "grep -c 'wazuh-analysisd: INFO: Started' /var/ossec/logs/ossec.log").strip() != n0:
            time.sleep(3)
            return time.time() - t0
    raise RuntimeError("restart timeout")


def inject(cases) -> dict[str, str]:
    marker = int(sh("sh", "-c", "wc -l < /var/ossec/logs/alerts/alerts.json").strip())
    open("/tmp/ev.jsonl", "w").write("\n".join(json.dumps(to_queue_message(c[2])) for c in cases) + "\n")
    subprocess.run(["docker", "cp", "/tmp/ev.jsonl", "wazuh:/tmp/atidep_events.jsonl"], check=True)
    sh("/var/ossec/framework/python/bin/python3", "/tmp/inject.py")
    time.sleep(6)
    out = {}
    for line in sh("sh", "-c", f"tail -n +{marker + 1} /var/ossec/logs/alerts/alerts.json").splitlines():
        j = json.loads(line)
        if "data" in j and "win" in j["data"]:
            out[j["data"]["win"]["system"]["eventRecordID"]] = j["rule"]["id"]
    return out


def report(title: str, cases, fired) -> None:
    print(f"\n== {title}")
    for rec, label, _ev, expect in cases:
        got = fired.get(str(rec))
        ok = "OK " if got == expect else "DIFF"
        print(f"  {ok} {label:34} expected={expect} got={got}")


def main() -> None:
    tok = w.token()
    put(tok, "lists", "atidep-domains", "bad.example.invalid:\n")
    put(tok, "lists", "atidep-ips", "203.0.113.10:\n198.51.100.:\n")
    put(tok, "rules", "0910-atidep_s1_ioc.xml", RULES)
    conf = sh("cat", "/var/ossec/etc/ossec.conf")
    if "atidep-domains" not in conf:
        sh("sh", "-c", "sed -i 's#</ruleset>#  <list>etc/lists/atidep-domains</list>\\n    <list>etc/lists/atidep-ips</list>\\n  </ruleset>#' /var/ossec/etc/ossec.conf")
    print("restart #1 took %.0f s" % restart(tok))
    sh("sh", "-c", "grep -c . /var/ossec/etc/lists/atidep-domains")
    report("initial lists", CASES, inject(CASES))
    # change a list through the API and test WITHOUT a restart
    put(tok, "lists", "atidep-domains", "bad.example.invalid:\nnew.example.invalid:\n")
    c2 = [(5101, "dns newly added, NO restart", f.dns_query(5101, "new.example.invalid"), "110101")]
    report("after list change, before restart (expect no match if restart is required)", c2, inject(c2))
    print("restart #2 took %.0f s" % restart(tok))
    c3 = [(5102, "dns newly added, after restart", f.dns_query(5102, "new.example.invalid"), "110101")]
    report("after restart", c3, inject(c3))


if __name__ == "__main__":
    main()
