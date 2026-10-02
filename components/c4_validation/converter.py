"""Sigma (v0 subset) -> Wazuh rule XML (blueprint §20.3, ADR-001 decision 5).

One Wazuh rule is a conjunction scoped to a parent rule, so the condition is expanded into
disjunctive normal form and every clause becomes one sibling rule (capped, refusing with
``EXPANSION_TOO_LARGE`` beyond it). Within a clause:

* several values for one field become one regex alternation;
* two tests on the same field become two ``<field>`` elements (ANDed, confirmed in F13);
* a negated test becomes ``negate="yes"`` (F13);
* every literal backslash becomes ``\\{1,2}``, because the real pipeline decodes Windows paths
  with doubled backslashes (F5, F13);
* matching is case-insensitive (``(?i)``), as Sigma is.

The parent rule and the shadowing siblings come from ``knowledge/wazuh_parent_sids.json``.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from xml.sax.saxutils import escape

from components.c4_validation.sigma_ir import Matcher, RuleIR, SubsetError, parse_rule
from components.wazuh_knowledge import Parent, parent_for
from schemas.sigma_subset import UnsupportedReason

MAX_REGEX_CHARS = 4000
DASHES = "\\-/–—―"
_SPECIAL = set(".^$*+?{}[]\\|()")
_TECHNIQUE_TAG = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.I)


@dataclass
class ConversionResult:
    xml: str
    rule_ids: list[int]
    report: dict[str, Any] = field(default_factory=dict)


def _lit(ch: str) -> str:
    return "\\" + ch if ch in _SPECIAL else ch


def value_regex(value: str, windash: bool = False) -> tuple[str, dict[str, int]]:
    """Regex body for one Sigma value (no anchors, no flags). ``*`` and ``?`` are wildcards
    unless written ``\\*`` or ``\\?``; every other backslash is a literal one."""
    out: list[str] = []
    stats = {"wildcards": 0, "backslashes": 0, "windash": 0}
    i = 0
    while i < len(value):
        ch = value[i]
        if ch == "\\" and i + 1 < len(value) and value[i + 1] in "*?":
            out.append(_lit(value[i + 1]))
            i += 2
            continue
        if ch == "\\":
            out.append("\\\\{1,2}")
            stats["backslashes"] += 1
        elif ch == "*":
            out.append(".*")
            stats["wildcards"] += 1
        elif ch == "?":
            out.append(".")
            stats["wildcards"] += 1
        elif windash and ch in "-/" and (i == 0 or value[i - 1] == " "):
            out.append(f"[{DASHES}]")
            stats["windash"] += 1
        else:
            out.append(_lit(ch))
        i += 1
    return "".join(out), stats


def _has_single_char_wildcard(value: str) -> bool:
    return re.search(r"(?<!\\)\?", value) is not None


def matcher_regex(m: Matcher) -> tuple[str, dict[str, int]]:
    total = {"wildcards": 0, "backslashes": 0, "windash": 0}
    bodies = []
    for v in m.values:
        if m.kind == "re":
            bodies.append(v)
            continue
        body, st = value_regex(v, m.windash)
        for k in total:
            total[k] += st[k]
        bodies.append(body)
    body = bodies[0] if len(bodies) == 1 else "(?:" + "|".join(bodies) + ")"
    if m.kind == "exact":
        body = f"^{body}$"
    elif m.kind == "startswith":
        body = f"^{body}"
    elif m.kind == "endswith":
        body = f"{body}$"
    regex = "(?i)" + body
    if regex.endswith(" "):
        regex = regex[:-1] + "\\x20"          # element text may be trimmed by the XML reader
    if len(regex) > MAX_REGEX_CHARS:
        raise SubsetError(UnsupportedReason.EXPANSION_TOO_LARGE, f"detection.{m.field}",
                          "the pattern is too long; use a CDB list")
    try:
        re.compile(regex)
    except re.error as exc:
        raise SubsetError(UnsupportedReason.INVALID_REGEX, f"detection.{m.field}",
                          str(exc)) from exc
    return regex, total


def attack_ids(tags: list[str]) -> list[str]:
    ids = []
    for t in tags:
        m = _TECHNIQUE_TAG.match(t.strip())
        if m and m.group(1).upper() not in ids:
            ids.append(m.group(1).upper())
    return ids


def convert_ir(ir: RuleIR, *, allocate: Callable[[str], int], wazuh_mapping: dict[str, Any],
               max_siblings: int = 20) -> ConversionResult:
    if len(ir.clauses) > max_siblings:
        raise SubsetError(UnsupportedReason.EXPANSION_TOO_LARGE, "detection.condition",
                          f"{len(ir.clauses)} sibling rules needed, the limit is {max_siblings}; "
                          "use a CDB list")
    field_map: dict[str, str] = wazuh_mapping["field_map"]
    levels: dict[str, int] = wazuh_mapping["level_map"]
    if ir.level not in levels:
        raise SubsetError(UnsupportedReason.UNSUPPORTED_SELECTION, "level",
                          f"unknown level {ir.level!r}")
    parent: Parent = parent_for(ir.category)
    techniques = attack_ids(ir.tags)
    rules: list[str] = []
    ids: list[int] = []
    totals = {"wildcards": 0, "backslashes": 0, "windash": 0}
    alternations = 0
    warnings: list[dict[str, str]] = []
    for n, clause in enumerate(ir.clauses):
        rid = allocate(f"sigma:{ir.sigma_id}#{n}")
        ids.append(rid)
        fields = []
        for matcher, negated in sorted(clause, key=lambda t: (t[1], t[0].field, t[0].kind,
                                                               t[0].values)):
            if matcher.field not in field_map:
                raise SubsetError(UnsupportedReason.UNMAPPED_FIELD, f"detection.{matcher.field}",
                                  f"no Wazuh field is known for {matcher.field!r}")
            regex, st = matcher_regex(matcher)
            for k in totals:
                totals[k] += st[k]
            alternations += len(matcher.values) > 1
            if matcher.kind != "re" and any(_has_single_char_wildcard(v) for v in matcher.values):
                warnings.append({
                    "code": "SINGLE_CHAR_WILDCARD", "path": f"detection.{matcher.field}",
                    "message": "a ? wildcard counts the pipeline's doubled backslash as two "
                               "characters; avoid ? on fields that hold Windows paths"})
            neg = ' negate="yes"' if negated else ""
            fields.append(f'    <field name="{field_map[matcher.field]}" type="pcre2"{neg}>'
                          f"{escape(regex)}</field>\n")
        mitre = "".join(f"<id>{t}</id>" for t in techniques)
        desc = escape(ir.title.strip()[:200]) + (f" ({n + 1}/{len(ir.clauses)})"
                                                  if len(ir.clauses) > 1 else "")
        rules.append(
            f'  <rule id="{rid}" level="{levels[ir.level]}">\n'
            f"    <if_sid>{parent.if_sid}</if_sid>\n{''.join(fields)}"
            f"    <description>{desc}</description>\n"
            + (f"    <mitre>{mitre}</mitre>\n" if mitre else "")
            + f"    <group>atidep,sigma,{ir.sigma_id},</group>\n  </rule>\n")
    xml = ('<!-- Generated by ATIDEP from Sigma rule ' + escape(ir.sigma_id)
           + '. Do not edit by hand. -->\n<group name="atidep,sigma,">\n' + "".join(rules)
           + "</group>\n")
    report = {
        "sigma_id": ir.sigma_id, "rules": ids, "sibling_rules": len(ids),
        "parent_if_sid": parent.if_sid, "log_source": ir.category,
        "shadow_risk": [{"sid": s, "note": "listed as an additional parent"}
                        for s in parent.shadowing_siblings],
        "value_alternations": alternations,
        "backslashes_made_tolerant": totals["backslashes"], "wildcards": totals["wildcards"],
        "windash_expansions": totals["windash"],
        "negated_terms": sum(neg for c in ir.clauses for _, neg in c),
        "case_handling": "case-insensitive: every pattern starts with (?i)",
        "mitre": techniques, "rejected": [], "warnings": warnings,
        "notes": ["Windows paths match one or two backslashes (the pipeline doubles them)"],
    }
    return ConversionResult(xml, ids, report)


def convert_sigma(sigma_yaml: str, *, allocate: Callable[[str], int],
                  wazuh_mapping: dict[str, Any], max_siblings: int = 20) -> ConversionResult:
    return convert_ir(parse_rule(sigma_yaml), allocate=allocate, wazuh_mapping=wazuh_mapping,
                      max_siblings=max_siblings)
