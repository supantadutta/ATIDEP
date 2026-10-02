"""Conversion fidelity: the converter's Wazuh rules versus the independent Tier 1 matcher on a
real manager (blueprint §20.1 principle 3). Each rule is deployed alone, because sibling rules
under one parent shadow each other (ADR-001 F6)."""
from itertools import count

import pytest
import yaml

from app.config import load_config
from components.c4_validation.converter import convert_sigma
from components.c4_validation.sigma_ir import parse_rule
from components.c4_validation.tier1 import rule_matches
from tests.events import sysmon_factory as f

MAPPING = load_config().wazuh_mapping
SID = "22222222-2222-4222-8222-222222222222"
PS, CMD, EXP = f.PS, "C:\\Windows\\System32\\cmd.exe", "C:\\Windows\\explorer.exe"
CCM = "C:\\Windows\\CCM\\ccmexec.exe"
_rec = count(9000)


def sigma(detection, category="process_creation", level="high"):
    return yaml.safe_dump({
        "title": "Fidelity rule", "id": SID, "status": "experimental", "description": "d",
        "references": ["https://example.com"], "author": "ATIDEP", "date": "2026/10/02",
        "tags": ["attack.execution", "attack.t1059.001"],
        "logsource": {"category": category, "product": "windows"}, "detection": detection,
        "falsepositives": ["x"], "level": level}, sort_keys=False)


def proc(image, cmd, parent=EXP, **kw):
    return f.process_create(next(_rec), image, cmd, parent, **kw)


def net(ip, port="443", image=f.BROWSER):
    return f.network_connect(next(_rec), ip, port, image)


def dns(name, image=PS):
    return f.dns_query(next(_rec), name, image)


CASES = {
    "encoded powershell: endswith, contains list, windash-free": (
        {"s": {"Image|endswith": "\\powershell.exe", "CommandLine|contains": ["-enc", "-ec "]},
         "condition": "s"}, "process_creation",
        lambda: [proc(PS, "powershell -nop -w hidden -enc SQBFAFgA"), proc(PS, "powershell -ec AAAA"),
                 proc(PS.upper(), "POWERSHELL -ENC AAAA"), proc(PS, "powershell Get-Process"),
                 proc(CMD, "cmd /c echo -enc"), proc(PS, "powershell -ecx x")]),
    "negation expands into sibling rules": (
        {"sel": {"Image|endswith": ["\\powershell.exe", "\\pwsh.exe"]},
         "flt": {"ParentImage|endswith": "\\ccmexec.exe", "User|contains": "svc"},
         "condition": "sel and not flt"}, "process_creation",
        lambda: [proc(PS, "powershell x"), proc(PS, "powershell x", CCM),
                 proc(PS, "powershell x", CCM, user="LAB\\svc_sccm"),
                 proc(PS, "powershell x", EXP, user="LAB\\svc_sccm"),
                 proc("C:\\Program Files\\PowerShell\\7\\pwsh.exe", "pwsh x"), proc(CMD, "cmd")]),
    "wildcards and exact": (
        {"s": {"Image": "*\\cmd.exe", "CommandLine": "cmd /c *"}, "condition": "s"},
        "process_creation",
        lambda: [proc(CMD, "cmd /c whoami"), proc(CMD, "CMD /C WHOAMI"), proc(CMD, "cmd /k whoami"),
                 proc(CMD, "cmd /c"), proc(PS, "cmd /c whoami")]),
    "windash and contains all": (
        {"s": {"CommandLine|contains|all|windash": ["-w hidden", "-nop"]}, "condition": "s"},
        "process_creation",
        lambda: [proc(PS, "powershell -nop -w hidden x"), proc(PS, "powershell /nop /w hidden x"),
                 proc(PS, "powershell -nop x"), proc(PS, "powershell -w hidden x")]),
    "regex and startswith": (
        {"a": {"CommandLine|re": "^cmd\\s+/c\\s+(whoami|ipconfig)"},
         "b": {"Image|startswith": "C:\\Users\\"}, "condition": "a or b"}, "process_creation",
        lambda: [proc(CMD, "cmd /c whoami"), proc(CMD, "cmd   /c  IPCONFIG /all"),
                 proc("C:\\Users\\alice\\AppData\\x.exe", "x.exe"), proc(CMD, "cmd /c dir"),
                 proc("D:\\Users\\x.exe", "x.exe")]),
    "network: address and image": (
        {"s": {"DestinationIp": ["203.0.113.55", "203.0.113.56"], "Initiated": True},
         "condition": "s"}, "network_connection",
        lambda: [net("203.0.113.55"), net("203.0.113.56", image=PS), net("203.0.113.57"),
                 net("203.0.113.55", image=PS)]),
    "network: port with image filter": (
        {"s": {"DestinationPort": ["4444", "8080"]}, "f": {"Image|endswith": "\\chrome.exe"},
         "condition": "s and not f"}, "network_connection",
        lambda: [net("203.0.113.9", "4444", image=PS), net("203.0.113.9", "8080", image=CMD),
                 net("203.0.113.9", "8080"), net("203.0.113.9", "443", image=PS)]),
    "dns: suffix": (
        {"s": {"QueryName|endswith": [".bad-domain.test", ".evil.test"]}, "condition": "s"},
        "dns_query",
        lambda: [dns("a.bad-domain.test"), dns("A.EVIL.TEST"), dns("bad-domain.test.good.test"),
                 dns("good.test"), dns("x.evil.test", image=f.BROWSER)]),
}


@pytest.mark.parametrize("name", list(CASES))
def test_wazuh_agrees_with_the_sigma_level_matcher(lab, name):
    detection, category, make_events = CASES[name]
    text = sigma(detection, category)
    ir = parse_rule(text)
    ids = {}
    res = convert_sigma(text, allocate=lambda k: ids.setdefault(k, 110000 + len(ids)),
                        wazuh_mapping=MAPPING)
    events = make_events()
    expected = {str(e["win"]["system"]["eventRecordID"]): rule_matches(ir, e, MAPPING)
                for e in events}
    assert any(expected.values()) and not all(expected.values()), "weak case: add events"
    lab.deploy_candidate(res.xml, {"atidep-domains": "placeholder.invalid:\n",
                                   "atidep-ips": "240.0.0.1:\n"})
    replay = lab.replay(events)
    got = {rec: replay.matched(rec, set(res.rule_ids)) for rec in expected}
    diffs = {rec: (expected[rec], got[rec]) for rec in expected if expected[rec] != got[rec]}
    assert not diffs, f"{name}: (tier1, wazuh) differ for records {diffs}\n{res.xml}"
