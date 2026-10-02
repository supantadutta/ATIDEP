"""Tier 1: a Sigma-level matcher over structured events (blueprint §20.6).

It evaluates the rule's boolean expression directly with plain string comparison and a small
glob matcher. It deliberately shares **no code** with the converter's regex builder, so when a
rule matches an event here but not in Wazuh (or the other way round) the difference points at
the converter, and the *conversion fidelity* metric counts those cases.

Events are the structured ``{"win": {"system": ..., "eventdata": ...}}`` form. Windows paths
in these events have single backslashes.
"""

from __future__ import annotations

import re
from typing import Any

from components.c4_validation.sigma_ir import And, Expr, Lit, Matcher, Not, Or, RuleIR

EVENT_IDS = {"process_creation": "1", "network_connection": "3", "dns_query": "22"}
DASHES = frozenset("-/–—―")
_PREFIX = "win.eventdata."


def event_category(event: dict[str, Any]) -> str | None:
    eid = str(event.get("win", {}).get("system", {}).get("eventID", ""))
    return next((c for c, i in EVENT_IDS.items() if i == eid), None)


def event_value(event: dict[str, Any], sigma_field: str, field_map: dict[str, str]) -> str | None:
    wazuh = field_map.get(sigma_field)
    if not wazuh or not wazuh.startswith(_PREFIX):
        return None
    value = event.get("win", {}).get("eventdata", {}).get(wazuh[len(_PREFIX):])
    return None if value is None else str(value)


# ---- glob matching ------------------------------------------------------------------------
def _tokens(pattern: str, windash: bool) -> list[tuple[str, str]]:
    toks: list[tuple[str, str]] = []
    i = 0
    while i < len(pattern):
        ch = pattern[i]
        if ch == "\\" and i + 1 < len(pattern) and pattern[i + 1] in "*?":
            toks.append(("lit", pattern[i + 1].casefold()))
            i += 2
            continue
        if ch == "*":
            toks.append(("star", ""))
        elif ch == "?":
            toks.append(("any", ""))
        elif windash and ch in "-/" and (i == 0 or pattern[i - 1] == " "):
            toks.append(("dash", ""))
        else:
            toks.append(("lit", ch.casefold()))
        i += 1
    return toks


def _glob(toks: list[tuple[str, str]], text: str) -> bool:
    s = text.casefold()
    ti = si = 0
    star = -1
    mark = 0
    while si < len(s):
        if ti < len(toks) and toks[ti][0] == "star":
            star, mark = ti, si
            ti += 1
        elif ti < len(toks) and (toks[ti][0] == "any"
                                 or (toks[ti][0] == "lit" and toks[ti][1] == s[si])
                                 or (toks[ti][0] == "dash" and s[si] in DASHES)):
            ti += 1
            si += 1
        elif star >= 0:
            ti, mark = star + 1, mark + 1
            si = mark
        else:
            return False
    while ti < len(toks) and toks[ti][0] == "star":
        ti += 1
    return ti == len(toks)


def _one(value: str, kind: str, windash: bool, text: str) -> bool:
    if kind == "re":
        return re.search(value, text, re.I) is not None
    toks = _tokens(value, windash)
    star = [("star", "")]
    if kind == "contains":
        toks = star + toks + star
    elif kind == "startswith":
        toks = toks + star
    elif kind == "endswith":
        toks = star + toks
    return _glob(toks, text)


def matcher_matches(m: Matcher, text: str | None) -> bool:
    if text is None:
        return False
    return any(_one(v, m.kind, m.windash, text) for v in m.values)


# ---- rule evaluation ----------------------------------------------------------------------
def _eval(e: Expr, event: dict[str, Any], field_map: dict[str, str]) -> bool:
    if isinstance(e, Lit):
        return matcher_matches(e.matcher, event_value(event, e.matcher.field, field_map))
    if isinstance(e, Not):
        return not _eval(e.item, event, field_map)
    if isinstance(e, And):
        return all(_eval(i, event, field_map) for i in e.items)
    if isinstance(e, Or):
        return any(_eval(i, event, field_map) for i in e.items)
    raise TypeError(e)


def rule_matches(ir: RuleIR, event: dict[str, Any], wazuh_mapping: dict[str, Any]) -> bool:
    if event_category(event) != ir.category:
        return False
    return _eval(ir.expr, event, wazuh_mapping["field_map"])
