"""Hand-written cases for testing the adversarial harness itself. They are NOT part of the
evaluated set; the evaluated set is authored independently (research/adversarial/cases/)."""

from __future__ import annotations

from research.adversarial.cases import RuleCase

PS = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"

GOOD = r"""title: Encoded PowerShell command line
id: 5b0f3c9a-6a1e-4a54-9a40-0c0f7a6f1b11
status: experimental
description: Detects PowerShell started with an encoded command.
references:
  - urn:atidep:fixture
author: fixture
date: 2026/10/02
tags:
  - attack.execution
  - attack.t1059.001
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: \powershell.exe
    CommandLine|contains: -enc
  flt:
    ParentImage|endswith: \ccmexec.exe
  condition: selection and not flt
falsepositives:
  - Administrative automation
level: high
"""

REPORT = ("The loader ran powershell.exe -nop -w hidden -enc followed by a long base64 string. "
          "Administrators sometimes run similar commands from ccmexec.exe on managed hosts.")


def events(lookalike_parent="C:\\Windows\\CCM\\ccmexec.exe"):
    return {
        "positive": [
            {"kind": "process_create", "image": PS, "parent": "C:\\Windows\\explorer.exe",
             "cmd": "powershell.exe -nop -w hidden -enc SQBFAFgA"},
            {"kind": "process_create", "image": PS, "parent": "C:\\Windows\\System32\\cmd.exe",
             "cmd": "powershell -enc SQBFAFgAIAA="}],
        "negative": [
            {"kind": "process_create", "image": "C:\\Windows\\System32\\notepad.exe",
             "cmd": "notepad.exe a.txt"},
            {"kind": "process_create", "image": PS, "cmd": "powershell.exe -Command Get-Date"}],
        "lookalike": [
            {"kind": "process_create", "image": PS, "parent": lookalike_parent,
             "cmd": "powershell.exe -EncodedCommand RwBlAHQA"}]}


def case(cid="CTL9-01", role="control", cls="NONE", sigma=GOOD, expected="none", **kw) -> RuleCase:
    base = dict(
        id=cid, role=role, defect_class=cls, evasive=False, why="fixture", expected_gate=expected,
        report_text=REPORT, evidence=["ran powershell.exe -nop -w hidden -enc"],
        logsource="windows_process_creation", techniques=["T1059.001"], sigma_yaml=sigma,
        assumptions=[{"statement": "Exclude SCCM", "justification": "known admin tool",
                      "covers": ["ccmexec.exe"]}],
        events=events())
    base.update(kw)
    return RuleCase(**base)


def defect(cid, cls, sigma, expected, **kw) -> RuleCase:
    return case(cid, "defective", cls, sigma, expected, **kw)
