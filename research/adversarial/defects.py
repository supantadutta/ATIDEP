"""Run the seeded defective rules and the clean controls through conditions B, B-V and C
(protocol: ``PROTOCOL.md``).

Every case gets its own in-memory database, so cases cannot influence each other. The surrounding
scenario (the ingested report, its verified claims, the opportunity) is built with the real
processing code and a scripted model; only the rule under test is injected, as a stored draft
version, which is the point at which every route into the system (the Rule Agent, a person's edit,
an import) meets the governance code.

* **B** runs the real governance code end to end: all eleven gates, submission, a worst-case
  reviewer who approves whatever is presented, the approval binding, and the package check.
* **B-V** runs the real gates and logs their results, but does not let them decide: the rule is
  advanced and approved by the harness, because "validators logged but not enforced" is exactly
  that. The approval binding and content-hash checks are the real ones.
* **C** applies no controls: the output is accepted as it is, and the gates are applied post hoc.
"""

from __future__ import annotations

import re
import tempfile
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from app.config import AppConfig, load_config
from app.db import models as m
from app.db.session import init_db, make_engine, session_scope
from app.services.deployment import build_rule_package
from app.services.detection import add_rule_version, assess_item
from app.services.governance import (
    ApprovalError,
    GovernanceError,
    _store,
    decide,
    edit_rule,
    evaluate_rule,
    report_sha256,
    submit_for_approval,
    transition,
    validate_rule,
    verify_approval,
)
from app.services.ingest import get_or_create_source, ingest
from app.services.process import process_item
from components.c1_ingest.collect import collect_bytes
from components.c1_ingest.evidence import EvidenceStore
from components.c2_processing.attack import AttackRelease, load_release
from components.c2_processing.indicators import load_benign_domains
from components.c3_detection.baseline import posthoc_report
from components.c4_validation.corpus import TestEvent, TestSet, load_baseline
from components.llm.prompts import PromptSet, load_prompt_set
from research.adversarial.cases import RuleCase, build_test_set
from research.adversarial.scripted import AgentRouter
from schemas.common import RuleKind, RuleState
from schemas.validation_result import Outcome

ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 10, 2, 9, 0, tzinfo=UTC)
REVIEWER = "Reviewer R1"          # a human identity as far as the guard is concerned
CONDITIONS = ("B", "B-V", "C")


@dataclass
class Context:
    cfg: AppConfig
    attack: AttackRelease
    baseline: list[TestEvent]
    prompts: PromptSet
    benign_domains: list[str]


def default_context() -> Context:
    return Context(load_config(), load_release(),
                   load_baseline(ROOT / "tests" / "events" / "benign_baseline" / "baseline.jsonl"),
                   load_prompt_set(), load_benign_domains())


@dataclass
class CaseResult:
    case_id: str
    role: str
    defect_class: str
    condition: str
    evasive: bool
    expected_gate: str
    opportunity_decision: str | None = None
    outcome: str | None = None                    # validation outcome, or C's post-hoc verdict
    failed_gates: list[str] = field(default_factory=list)
    reason_codes: dict[str, list[str]] = field(default_factory=dict)
    expected_gate_fired: bool = False
    state_final: str | None = None
    reached_validated: bool = False
    reached_approved: bool = False
    accepted_by_construction: bool = False
    package_ok: bool | None = None
    package_refusal: str | None = None
    tamper: dict[str, Any] = field(default_factory=dict)
    harness_error: str | None = None
    notes: str = ""

    @property
    def stopped_before_approval(self) -> bool:
        return not (self.reached_approved or self.accepted_by_construction)

    @property
    def all_gates_passed(self) -> bool:
        return self.outcome in (Outcome.VALIDATED.value, "passed")

    def as_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["stopped_before_approval"] = self.stopped_before_approval
        return d


# ---- the scenario around the rule --------------------------------------------------------------
def _extraction(case: RuleCase) -> str:
    import json
    behaviours = []
    for i, quote in enumerate(case.evidence):
        tech = case.techniques[i] if i < len(case.techniques) else None
        behaviours.append({"description": quote[:120], "attack_id": tech, "quote": quote,
                           "stated_confidence": 80})
    return json.dumps({"behaviors": behaviours, "entities": []})


def _opportunity(case: RuleCase):
    import json

    def answer(request) -> str:
        ids = re.findall(r"\[(EV-[\w-]+)\] behaviour", request.user)
        return json.dumps({"opportunities": [{
            "decision": "behavioral", "detection_concept": f"Seeded case {case.id}",
            "required_log_source": case.logsource, "required_fields": [],
            "attack_techniques": case.techniques, "false_positive_hypotheses": [],
            "evidence_ids": ids, "decision_reason": "Visible in the cited evidence"}]})
    return answer


@dataclass
class Scenario:
    engine: Any
    store: EvidenceStore
    intel_id: str
    opportunity_id: int
    opportunity_decision: str
    test_set: TestSet


def build_scenario(case: RuleCase, ctx: Context, tmp: Path) -> Scenario:
    engine = make_engine("sqlite:///:memory:")
    init_db(engine)
    store = EvidenceStore(tmp / "evidence")
    doc = collect_bytes(case.report_text.encode("utf-8"), source_name="Seeded source",
                        url=None, title=case.id, published_at=NOW, retrieved_at=NOW)
    client = AgentRouter(extraction=_extraction(case), opportunity=_opportunity(case))
    with session_scope(engine) as s:
        src = get_or_create_source(s, name="Seeded source", reliability_rating="A",
                                   default_credibility=2)
        iid = ingest(s, store, doc, src, actor="adversarial").intel_id
        proc = process_item(s, store, iid, cfg=ctx.cfg, attack=ctx.attack, client=client,
                            prompt=ctx.prompts.extraction, benign_domains=ctx.benign_domains,
                            allow_test_tlds=True)
        if not proc.ok:
            raise RuntimeError(f"scenario extraction failed: {proc.error}")
        opp_ids = assess_item(s, iid, cfg=ctx.cfg, attack=ctx.attack, client=client,
                              prompt=ctx.prompts.opportunity, now=NOW, run_id=case.id)
        opp = s.get(m.DetectionOpportunity, opp_ids[0])
        decision = opp.decision
    return Scenario(engine, store, iid, opp_ids[0], decision, build_test_set(case))


def import_rule(s: Session, case: RuleCase, sc: Scenario, content: str | None = None) -> str:
    """Store the rule under test as a draft version. Every route into the system (the Rule Agent,
    a person's edit, an import) ends here, in front of the same governance code."""
    rule = m.Rule(rule_id="RULE-2026-0001", opportunity_id=sc.opportunity_id,
                  kind=RuleKind.SIGMA.value, state=RuleState.DRAFT.value)
    s.add(rule)
    s.flush()
    add_rule_version(s, rule, origin="human_edit", content=content or case.sigma_yaml,
                     assumptions=[a.model_dump() for a in case.assumptions], use_case={})
    return rule.rule_id


def _gate_info(results) -> tuple[list[str], dict[str, list[str]]]:
    failed = [r.gate.value for r in results if r.status.value == "failed"]
    codes = {r.gate.value: list(r.reason_codes) for r in results if r.status.value == "failed"}
    return failed, codes


def _expected_fired(case: RuleCase, failed: list[str]) -> bool:
    return case.expected_gate in failed


# ---- condition B -------------------------------------------------------------------------------
def run_b(case: RuleCase, ctx: Context, tmp: Path) -> CaseResult:
    res = CaseResult(case.id, case.role, case.defect_class, "B", case.evasive, case.expected_gate)
    sc = build_scenario(case, ctx, tmp)
    res.opportunity_decision = sc.opportunity_decision
    with session_scope(sc.engine) as s:
        rid = import_rule(s, case, sc)
        out = validate_rule(s, rid, cfg=ctx.cfg, attack=ctx.attack, test_set=sc.test_set,
                            baseline=ctx.baseline, actor="adversarial")
        res.outcome = out.outcome.value
        res.failed_gates, res.reason_codes = _gate_info(out.results)
        res.expected_gate_fired = _expected_fired(case, res.failed_gates)
        res.reached_validated = out.outcome is Outcome.VALIDATED
        if res.reached_validated:
            submit_for_approval(s, rid, actor="adversarial")
            decide(s, rid, reviewer=REVIEWER, decision="approved",
                   comment="worst-case reviewer: approves whatever is presented")
            res.reached_approved = True
            try:
                build_rule_package(s, rid, ctx.cfg, now=NOW, test_set=sc.test_set,
                                   require_approval=True)
                res.package_ok = True
            except Exception as exc:  # noqa: BLE001 - the refusal is the result
                res.package_ok, res.package_refusal = False, f"{type(exc).__name__}: {exc}"[:200]
        res.state_final = s.get(m.Rule, rid).state
    return res


# ---- condition B-V (validators logged, not enforced) -------------------------------------------
def run_bv(case: RuleCase, ctx: Context, tmp: Path) -> CaseResult:
    res = CaseResult(case.id, case.role, case.defect_class, "B-V", case.evasive,
                     case.expected_gate)
    sc = build_scenario(case, ctx, tmp)
    res.opportunity_decision = sc.opportunity_decision
    with session_scope(sc.engine) as s:
        rid = import_rule(s, case, sc)
        _advisory_approval(s, rid, case, ctx, sc, res)
        res.state_final = s.get(m.Rule, rid).state
    return res


def _advisory_approval(s: Session, rid: str, case: RuleCase, ctx: Context, sc: Scenario,
                       res: CaseResult) -> None:
    rule = s.get(m.Rule, rid)
    version = s.query(m.RuleVersion).filter_by(rule_id=rid).one()
    ev = evaluate_rule(s, rule, version, cfg=ctx.cfg, attack=ctx.attack, test_set=sc.test_set,
                       baseline=ctx.baseline)
    _store(s, version, ev.results)                                  # logged, as the condition says
    res.failed_gates, res.reason_codes = _gate_info(ev.results)
    res.expected_gate_fired = _expected_fired(case, res.failed_gates)
    res.outcome = ("validated" if not res.failed_gates and not ev.blocked else
                   "blocked" if ev.blocked else "revision_required")
    # not enforced: the harness advances the rule whatever the log says
    transition(s, rule, RuleState.VALIDATED, actor="adversarial", reason="validators advisory")
    res.reached_validated = True
    transition(s, rule, RuleState.PENDING_APPROVAL, actor="adversarial")
    s.add(m.Approval(rule_version_id=version.id, reviewer=REVIEWER, author="ATIDEP",
                     decision="approved", comment="worst-case reviewer",
                     content_sha256=version.content_sha256,
                     validation_report_sha256=report_sha256(ev.results),
                     deployment_target="lab"))
    s.flush()
    transition(s, rule, RuleState.APPROVED, actor=REVIEWER)
    res.reached_approved = True


# ---- condition C -------------------------------------------------------------------------------
def run_c(case: RuleCase, ctx: Context, tmp: Path) -> CaseResult:
    res = CaseResult(case.id, case.role, case.defect_class, "C", case.evasive, case.expected_gate)
    counter = iter(range(110000, 119999))
    ids: dict[str, int] = {}
    # Post-hoc G7 only accepts a technique ID that the report text literally contains. The cases'
    # reports describe behaviour in words, so the supported technique IDs are appended; otherwise
    # every clean control would be flagged for a reason unrelated to any defect.
    report = case.report_text + "\n" + " ".join(case.techniques)
    rep = posthoc_report(case.sigma_yaml, report, ctx.cfg, ctx.attack,
                         claimed_techniques=case.techniques,
                         allocate=lambda k: ids.setdefault(k, next(counter)),
                         test_set=build_test_set(case), baseline=ctx.baseline)
    res.failed_gates = list(rep.failed_gates)
    res.expected_gate_fired = _expected_fired(case, res.failed_gates)
    res.outcome = "passed" if rep.passed else "flagged"
    res.accepted_by_construction = True               # no controls: the output is taken as it is
    return res


# ---- D10: tampering after approval -------------------------------------------------------------
TAMPER_ROUTES = ("direct_db", "direct_db_rehashed", "edit_through_application")


def run_tamper(case: RuleCase, ctx: Context, tmp: Path, condition: str) -> CaseResult:
    """A clean rule is approved, then its content is changed three different ways. The result is
    'detected' when the system refuses to treat the changed content as approved."""
    res = CaseResult(case.id, case.role, case.defect_class, condition, case.evasive,
                     "approval-binding")
    if condition == "C":
        res.accepted_by_construction = True
        res.tamper = {r: {"detected": False, "note": "no approval record exists in C"}
                      for r in TAMPER_ROUTES}
        return res
    for route in TAMPER_ROUTES:
        sub = tmp / route
        sub.mkdir(parents=True, exist_ok=True)
        sc = build_scenario(case, ctx, sub)
        res.opportunity_decision = sc.opportunity_decision
        with session_scope(sc.engine) as s:
            rid = import_rule(s, case, sc)
            tmp_res = CaseResult(case.id, case.role, case.defect_class, condition, case.evasive,
                                 "approval-binding")
            if condition == "B":
                out = validate_rule(s, rid, cfg=ctx.cfg, attack=ctx.attack,
                                    test_set=sc.test_set, baseline=ctx.baseline,
                                    actor="adversarial")
                if out.outcome is not Outcome.VALIDATED:
                    res.tamper[route] = {"detected": None,
                                         "note": f"the base rule did not validate: {out.outcome}"}
                    continue
                submit_for_approval(s, rid, actor="adversarial")
                decide(s, rid, reviewer=REVIEWER, decision="approved", comment="worst-case")
            else:
                _advisory_approval(s, rid, case, ctx, sc, tmp_res)
            res.reached_approved = True
            res.tamper[route] = _tamper(s, rid, case, route)
    res.reached_validated = True
    return res


def _tamper(s: Session, rid: str, case: RuleCase, route: str) -> dict[str, Any]:
    version = s.query(m.RuleVersion).filter_by(rule_id=rid).order_by(
        m.RuleVersion.version.desc()).first()
    new = case.tamper_sigma_yaml
    refusals: dict[str, str] = {}
    if route == "direct_db":
        version.content = new
    elif route == "direct_db_rehashed":
        from components.c1_ingest.evidence import sha256_hex
        version.content, version.content_sha256 = new, sha256_hex(new)
    else:
        edit_rule(s, rid, new, editor=REVIEWER)
    s.flush()
    try:
        verify_approval(s, rid)
        still_approved = True
    except (ApprovalError, GovernanceError) as exc:
        still_approved = False
        refusals["verify_approval"] = str(exc)[:160]
    if route == "edit_through_application":
        try:
            submit_for_approval(s, rid, actor="adversarial")
            resubmitted = True
        except GovernanceError as exc:
            resubmitted = False
            refusals["submit_for_approval"] = str(exc)[:160]
        still_approved = still_approved or resubmitted
    changed = new != case.sigma_yaml
    # an unchanged "tamper" tests nothing: it is neither detected nor an escape
    return {"detected": (not still_approved) if changed else None, "content_changed": changed,
            "refusals": refusals, "state_after": s.get(m.Rule, rid).state}


# ---- entry points ------------------------------------------------------------------------------
def evaluate_case(case: RuleCase, condition: str, ctx: Context) -> CaseResult:
    with tempfile.TemporaryDirectory() as t:
        tmp = Path(t)
        try:
            if case.defect_class == "D10":
                return run_tamper(case, ctx, tmp, condition)
            return {"B": run_b, "B-V": run_bv, "C": run_c}[condition](case, ctx, tmp)
        except Exception as exc:  # noqa: BLE001 - a harness fault is reported, never hidden
            r = CaseResult(case.id, case.role, case.defect_class, condition, case.evasive,
                           case.expected_gate)
            r.harness_error = f"{type(exc).__name__}: {exc}"[:300]
            return r
