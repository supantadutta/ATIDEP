"""Hard gates G8-G11: tests against events (blueprint §17.4.1, §20.6).

* G8  every designated positive event is matched;
* G9  no negative event is matched;
* G10 no benign look-alike event is matched;
* G11 the rule is not too broad: it has a discriminating condition in every alternative and
      matches no more than ``max_benign_match_pct`` of the benign baseline.

Events run through one or two *runners*. Tier 1 is the Sigma-level matcher, Tier 2 the real
Wazuh pipeline. When both run, Tier 2 decides the gates (it is the authoritative test) and any
event on which the two disagree is reported as a conversion-fidelity finding.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

from app.config import PoliciesConfig
from components.c4_validation.corpus import TestEvent, TestSet, check_unique
from components.c4_validation.sigma_ir import RuleIR
from components.c4_validation.tier1 import rule_matches
from components.c4_validation.tier2 import LabManager
from schemas.validation_result import Defect, GateId, GateResult, GateStatus

MIN_BASELINE_EVENTS = 100
GENERIC_FIELDS = frozenset({"Image", "ParentImage", "OriginalFileName", "User", "Initiated"})
MIN_VALUE_CHARS = 4


class EventRunner(Protocol):
    tier: int

    def run(self, events: list[dict[str, Any]]) -> dict[str, bool]: ...


class Tier1Runner:
    tier = 1

    def __init__(self, ir: RuleIR, wazuh_mapping: dict[str, Any]) -> None:
        self.ir, self.mapping = ir, wazuh_mapping

    def run(self, events: list[dict[str, Any]]) -> dict[str, bool]:
        return {str(e["win"]["system"]["eventRecordID"]): rule_matches(self.ir, e, self.mapping)
                for e in events}


class Tier2Runner:
    """Deploys the converted rule alone to the lab manager (restart) and replays the events."""

    tier = 2

    def __init__(self, lab: LabManager, rules_xml: str, rule_ids: list[int],
                 lists: dict[str, str] | None = None) -> None:
        self.lab, self.xml, self.ids = lab, rules_xml, set(rule_ids)
        self.lists = lists or {}
        self._deployed = False

    def run(self, events: list[dict[str, Any]]) -> dict[str, bool]:
        if not self._deployed:
            self.lab.deploy_candidate(self.xml, self.lists)
            self._deployed = True
        replay = self.lab.replay(events)
        return {str(e["win"]["system"]["eventRecordID"]):
                replay.matched(str(e["win"]["system"]["eventRecordID"]), self.ids)
                for e in events}


@dataclass
class EventGateReport:
    results: list[GateResult] = field(default_factory=list)
    defects: list[Defect] = field(default_factory=list)
    tier: int = 0
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def passed(self) -> bool:
        return bool(self.results) and all(r.status is GateStatus.PASSED for r in self.results)


def _defect(gate: GateId, code: str, path: str, message: str) -> Defect:
    return Defect(gate=gate, code=f"{gate.value}_{code}", path=path, message=message[:400])


def _result(gate: GateId, defects: list[Defect], tier: int, note: str = "") -> GateResult:
    if defects:
        return GateResult(gate=gate, status=GateStatus.FAILED,
                          reason_codes=sorted({d.code for d in defects}),
                          message="; ".join(f"{d.path}: {d.message}" for d in defects)[:900],
                          tier=tier)
    return GateResult(gate=gate, status=GateStatus.PASSED, message=note, tier=tier)


def discriminating_defects(ir: RuleIR) -> list[Defect]:
    """Every alternative must hold something beyond a generic match: a positive term on a
    field that is not just a process name or user, with a value of some length, or terms on
    at least two different fields."""
    out: list[Defect] = []
    for n, clause in enumerate(ir.clauses):
        positive = [m for m, neg in clause if not neg]
        fields = {m.field for m in positive}
        specific = any(
            m.field not in GENERIC_FIELDS and any(
                len(v.replace("*", "").replace("?", "").strip("\\ ")) >= MIN_VALUE_CHARS
                for v in m.values)
            for m in positive)
        if not specific and len(fields) < 2:
            out.append(_defect(
                GateId.G11, "NOT_DISCRIMINATING", f"detection.alternative[{n}]",
                "this alternative matches only a generic field; add a condition on "
                f"{sorted(set(ir.fields_used()) - GENERIC_FIELDS) or 'a specific field'}"
                " or a second field"))
    return out


def run_event_gates(ir: RuleIR | None, test_set: TestSet, baseline: list[TestEvent],
                    runners: list[EventRunner], policy: PoliciesConfig) -> EventGateReport:
    """``ir`` is None for an IOC bundle, which has no Sigma conditions to inspect."""
    if not runners:
        raise ValueError("at least one runner is needed")
    check_unique(test_set.all_events(), baseline)
    v = policy.validation
    report = EventGateReport()
    events = [e.event for e in test_set.all_events() + baseline]
    outcomes: dict[int, dict[str, bool]] = {}
    for runner in sorted(runners, key=lambda r: r.tier):
        outcomes[runner.tier] = runner.run(events)
    report.tier = max(outcomes)
    got = outcomes[report.tier]                      # the highest tier decides the gates

    def failing(group: list[TestEvent], should_match: bool) -> list[str]:
        return [e.name for e in group if got[e.record_id] is not should_match]

    for gate, group, should, code, needed in (
            (GateId.G8, test_set.positive, True, "MISSED_POSITIVE", v.require_positive_test),
            (GateId.G9, test_set.negative, False, "MATCHED_NEGATIVE", v.require_negative_test),
            (GateId.G10, test_set.lookalike, False, "MATCHED_LOOKALIKE",
             v.require_benign_lookalike_test)):
        defects: list[Defect] = []
        if needed and not group:
            defects.append(_defect(gate, "NO_EVENTS", "tests",
                                   "this rule has no designated test events of this kind"))
        for name in failing(group, should):
            what = "did not match the positive event" if should else "matched the event"
            defects.append(_defect(gate, code, name, f"the rule {what} {name}"))
        report.results.append(_result(gate, defects, report.tier,
                                      f"{len(group)} event(s) behaved as expected"))
        report.defects += defects

    g11 = discriminating_defects(ir) if ir is not None else []
    matched = [e.name for e in baseline if got[e.record_id]]
    rate = 100.0 * len(matched) / len(baseline) if baseline else 0.0
    if len(baseline) < MIN_BASELINE_EVENTS:
        g11.append(_defect(GateId.G11, "BASELINE_TOO_SMALL", "baseline",
                           f"{len(baseline)} baseline events; at least {MIN_BASELINE_EVENTS} are "
                           "needed to measure the breadth limit"))
    elif rate > v.max_benign_match_pct:
        g11.append(_defect(GateId.G11, "TOO_BROAD", "baseline",
                           f"the rule matches {len(matched)} of {len(baseline)} benign baseline "
                           f"events ({rate:.2f}%); the limit is {v.max_benign_match_pct}%. "
                           f"First matches: {matched[:3]}"))
    report.results.append(_result(GateId.G11, g11, report.tier,
                                  f"{len(matched)}/{len(baseline)} baseline matches ({rate:.2f}%)"))
    report.defects += g11

    disagreements: list[str] = []
    if 1 in outcomes and 2 in outcomes:
        disagreements = sorted(r for r in outcomes[1] if outcomes[1][r] != outcomes[2][r])
    report.details = {
        "events": len(events), "baseline_events": len(baseline), "baseline_matches": len(matched),
        "baseline_match_pct": round(rate, 3), "tiers_run": sorted(outcomes),
        "fidelity_disagreements": disagreements,
        "test_set": test_set.set_id,
        "counts": {"positive": len(test_set.positive), "negative": len(test_set.negative),
                   "lookalike": len(test_set.lookalike)}}
    report.results.sort(key=lambda r: int(r.gate.value[1:]))
    return report
