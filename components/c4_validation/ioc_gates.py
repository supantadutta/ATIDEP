"""Test events and a reference matcher for IOC bundles (blueprint §17.3.4, §20.4).

An indicator list has no Sigma conditions, so its tests come from the bundle itself:

* positives: one event per listed indicator (a DNS query, a connection or a process with that
  hash), up to a cap per kind;
* negatives: events with similar but unlisted values;
* look-alikes: values that resemble a listed one but must not match under the documented
  rules (a sub-domain, an upper-case name, a neighbouring address, a changed hash).

They test the plumbing (rendering, list lookup, rule parent), not the intelligence. The Tier 1
reference matcher models the documented Wazuh behaviour: exact, case-sensitive domain keys;
exact addresses; hash match on the ``Hashes`` field.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from itertools import count
from typing import Any
from urllib.parse import urlsplit

from components.c3_detection.ioc_builder import effective_kind
from components.c4_validation import sysmon_factory as f
from components.c4_validation.corpus import TestEvent, TestSet
from schemas.claim import IndicatorType
from schemas.ioc_bundle import IocEntry

PER_KIND_CAP = 10
FIRST_RECORD_ID = 30000
HASH_LABEL = {"md5": "MD5", "sha1": "SHA1", "sha256": "SHA256"}


def targets(entries: Iterable[IocEntry]) -> dict[str, set[str]]:
    """What the lists and rules will contain: domains, addresses and hashes by algorithm."""
    out: dict[str, set[str]] = {"domain": set(), "ipv4": set(), "md5": set(), "sha1": set(),
                                "sha256": set()}
    for e in entries:
        kind = effective_kind(e.type, e.value)
        value = (urlsplit(e.value).hostname or "").lower() if e.type is IndicatorType.URL \
            else e.value.lower()
        out[kind].add(value)
    return out


class IocTier1Runner:
    tier = 1

    def __init__(self, entries: Iterable[IocEntry]) -> None:
        self.t = targets(entries)

    def _matches(self, event: dict[str, Any]) -> bool:
        win = event.get("win", {})
        eid = str(win.get("system", {}).get("eventID", ""))
        data = win.get("eventdata", {})
        if eid == "22":
            return data.get("queryName") in self.t["domain"]               # exact, case-sensitive
        if eid == "3":
            return data.get("destinationIp") in self.t["ipv4"]
        if eid == "1":
            hashes = str(data.get("hashes", "")).casefold()
            return any(f"{HASH_LABEL[k].casefold()}={h}" in hashes
                       for k in HASH_LABEL for h in self.t[k])
        return False

    def run(self, events: list[dict[str, Any]]) -> dict[str, bool]:
        return {str(e["win"]["system"]["eventRecordID"]): self._matches(e) for e in events}


def _hash_event(rec: int, label: str, value: str) -> dict[str, Any]:
    ev = f.process_create(rec, f.PS, "powershell.exe -NoProfile Get-Date",
                          "C:\\Windows\\explorer.exe")
    ev["win"]["eventdata"]["hashes"] = f"{HASH_LABEL[label]}={value.upper()}"
    return ev


def _flip(value: str) -> str:
    return value[:-1] + ("0" if value[-1] != "0" else "1")


def synthesize_tests(entries: Iterable[IocEntry]) -> TestSet:
    t = targets(entries)
    ts = TestSet("ioc-synthetic")
    counter = count(FIRST_RECORD_ID)

    def add(group: list[TestEvent], name: str, make: Callable[[int], dict[str, Any]]) -> None:
        group.append(TestEvent(name, make(next(counter))))

    for d in sorted(t["domain"])[:PER_KIND_CAP]:
        add(ts.positive, f"dns {d}", lambda r, d=d: f.dns_query(r, d))
    for ip in sorted(t["ipv4"])[:PER_KIND_CAP]:
        add(ts.positive, f"net {ip}", lambda r, ip=ip: f.network_connect(r, ip))
    for k in HASH_LABEL:
        for h in sorted(t[k])[:PER_KIND_CAP]:
            add(ts.positive, f"hash {k} {h[:12]}", lambda r, k=k, h=h: _hash_event(r, k, h))

    add(ts.negative, "dns unlisted", lambda r: f.dns_query(r, "unlisted-host.example.net"))
    add(ts.negative, "net unlisted", lambda r: f.network_connect(r, "198.18.0.77"))
    add(ts.negative, "hash unlisted", lambda r: _hash_event(r, "sha256", "ab" * 32))

    for d in sorted(t["domain"])[:3]:
        add(ts.lookalike, f"dns subdomain of {d}", lambda r, d=d: f.dns_query(r, "www." + d))
        add(ts.lookalike, f"dns upper case {d}", lambda r, d=d: f.dns_query(r, d.upper()))
    for ip in sorted(t["ipv4"])[:3]:
        head, last = ip.rsplit(".", 1)
        neighbour = f"{head}.{(int(last) + 1) % 256}"
        if neighbour not in t["ipv4"]:
            add(ts.lookalike, f"net neighbour of {ip}",
                lambda r, n=neighbour: f.network_connect(r, n))
    for k in HASH_LABEL:
        for h in sorted(t[k])[:2]:
            add(ts.lookalike, f"hash {k} one character changed",
                lambda r, k=k, h=h: _hash_event(r, k, _flip(h)))
    return ts
