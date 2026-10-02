"""Deterministic builders for inert Sysmon events in the structured ``win`` form (tests and
the synthesised IOC test events)."""
from __future__ import annotations

import pathlib
from typing import Any

PROVIDER = "Microsoft-Windows-Sysmon"
GUID = "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"
PS = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
BROWSER = "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"


def _system(event_id: int, record: int, host: str, when: str) -> dict[str, str]:
    return {"providerName": PROVIDER, "providerGuid": GUID, "eventID": str(event_id),
            "version": "5", "level": "4", "task": str(event_id), "opcode": "0",
            "keywords": "0x8000000000000000", "systemTime": when, "eventRecordID": str(record),
            "processID": "2412", "threadID": "3524",
            "channel": "Microsoft-Windows-Sysmon/Operational", "computer": host,
            "severityValue": "INFORMATION", "message": "Sysmon event"}


def event(event_id: int, record: int, data: dict[str, str], host: str = "WIN10-LAB",
          when: str = "2026-10-02T10:00:00.000000000Z") -> dict[str, Any]:
    base = {"ruleName": "-", "utcTime": when[:10] + " " + when[11:23],
            "processGuid": "{c3a9f1a2-0000-0000-0000-000000000000}", "processId": "4568"}
    return {"win": {"system": _system(event_id, record, host, when),
                    "eventdata": {**base, **data}}}


def process_create(record: int, image: str, cmd: str, parent: str, pcmd: str = "",
                   user: str = "LAB\\alice", sha256: str = "0" * 64) -> dict[str, Any]:
    name = pathlib.PureWindowsPath(image).name
    return event(1, record, {
        "image": image, "description": name, "originalFileName": name, "commandLine": cmd,
        "currentDirectory": "C:\\Users\\alice\\", "user": user, "integrityLevel": "Medium",
        "hashes": f"SHA256={sha256}", "parentProcessGuid": "{c3a9f1a2-0000-0000-0000-000000000001}",
        "parentProcessId": "3120", "parentImage": parent, "parentCommandLine": pcmd or parent})


def network_connect(record: int, dest_ip: str, dest_port: str = "443",
                    image: str = BROWSER) -> dict[str, Any]:
    return event(3, record, {
        "image": image, "user": "LAB\\alice", "protocol": "tcp", "initiated": "true",
        "sourceIsIpv6": "false", "sourceIp": "10.0.0.15", "sourcePort": "49822",
        "destinationIsIpv6": "false", "destinationIp": dest_ip, "destinationPort": dest_port})


def dns_query(record: int, name: str, image: str = PS) -> dict[str, Any]:
    return event(22, record, {"image": image, "queryName": name, "queryStatus": "0",
                              "queryResults": "type:  5 example.invalid;203.0.113.10;"})
