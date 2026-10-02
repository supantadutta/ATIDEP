"""Spike S1, route 2b: replay Windows events through the REAL analysis pipeline.

logtest cannot run the windows_eventchannel decoder, so this uploads the rule through the API,
restarts the manager, and writes raw EventChannel messages (queue marker 'f') to analysisd's
input socket from inside the container. Alerts are read back from alerts.json.

Requires a running container named "wazuh" (docker) and the API credentials of wazuh_probe.py.
"""
from __future__ import annotations

import glob
import json
import subprocess
import sys
import time
import urllib.request

sys.path.insert(0, "spikes")
sys.path.insert(0, ".")
import wazuh_probe as w  # noqa: E402

from components.c4_validation.event_formats import to_queue_message  # noqa: E402

CONTAINER = "wazuh"
RULE_FILE = "spikes/s1/0900-atidep_s1_rules.xml"
INJECT = r"""
import json, socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
s.connect("/var/ossec/queue/sockets/queue")
for line in open("/tmp/atidep_events.jsonl"):
    s.send(json.loads(line).encode())
"""


def sh(*args: str) -> str:
    return subprocess.run(["docker", "exec", CONTAINER, *args], capture_output=True, text=True).stdout


def put_rule(tok: str, path: str, name: str) -> dict:
    req = urllib.request.Request(w.URL + f"/rules/files/{name}?overwrite=true",
                                 data=open(path, "rb").read(), method="PUT",
                                 headers={"Authorization": f"Bearer {tok}",
                                          "Content-Type": "application/octet-stream"})
    with urllib.request.urlopen(req, context=w._CTX, timeout=30) as r:
        return json.loads(r.read())


def restart_and_wait(tok: str) -> float:
    before = sh("sh", "-c", "grep -c 'wazuh-analysisd: INFO: Started' /var/ossec/logs/ossec.log")
    t0 = time.time()
    w.call("PUT", "/manager/restart", tok)
    for _ in range(90):
        time.sleep(2)
        now = sh("sh", "-c", "grep -c 'wazuh-analysisd: INFO: Started' /var/ossec/logs/ossec.log")
        if now.strip() != before.strip() and "running" in sh("/var/ossec/bin/wazuh-control", "status"):
            return time.time() - t0
    raise RuntimeError("manager did not come back")


def main() -> None:
    tok = w.token()
    print("upload:", put_rule(tok, RULE_FILE, "0900-atidep_s1_rules.xml")["data"]["affected_items"])
    print("restart took %.0f s" % restart_and_wait(tok))
    files = sorted(glob.glob("tests/events/*/*.json"))
    lines = [json.dumps(to_queue_message(json.load(open(f)))) for f in files]
    open("/tmp/atidep_events.jsonl", "w").write("\n".join(lines) + "\n")
    subprocess.run(["docker", "cp", "/tmp/atidep_events.jsonl", f"{CONTAINER}:/tmp/atidep_events.jsonl"])
    marker = sh("sh", "-c", "wc -l < /var/ossec/logs/alerts/alerts.json").strip()
    open("/tmp/inject.py", "w").write(INJECT)
    subprocess.run(["docker", "cp", "/tmp/inject.py", f"{CONTAINER}:/tmp/inject.py"])
    sh("/var/ossec/framework/python/bin/python3", "/tmp/inject.py")
    time.sleep(6)
    alerts = sh("sh", "-c", f"tail -n +{int(marker) + 1} /var/ossec/logs/alerts/alerts.json").strip().splitlines()
    print(f"injected {len(files)} events; {len(alerts)} alert(s) written")
    fired = {}
    for a in alerts:
        j = json.loads(a)
        fired[j["data"]["win"]["system"]["eventRecordID"]] = (j["rule"]["id"], j["rule"]["level"])
    for f in files:
        rid = json.load(open(f))["win"]["system"]["eventRecordID"]
        print(f"{f.split('events/')[1]:46} -> {fired.get(rid, 'no alert')}")


if __name__ == "__main__":
    main()
