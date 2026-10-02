"""C4 orchestration: validation, state machine, approval (blueprint §17.4).

* ``validate_rule`` runs the hard gates, stores one row per gate, computes the ranking score
  only for rules that passed all of them, and moves the rule to ``validated`` (or ``blocked``).
* ``submit_for_approval`` / ``decide`` implement the approval step. An approval is bound to the
  SHA-256 of the exact rule content and to the hash of the validation report.
* ``edit_rule`` stores a new version and voids validation and approval.
* ``verify_approval`` is what deployment calls: it recomputes the content hash and refuses
  anything that no longer matches (Scenario 7).

The identity check on approvers is a guard against wiring mistakes (an agent or the system
approving), not authentication. The API layer authenticates the person.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from defusedxml import ElementTree
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.config import AppConfig
from app.db import models as m
from app.db.audit import append_audit_event
from app.services.claims import load_claims
from app.services.detection import add_rule_version, to_schema
from app.services.rule_ids import allocate_rule_id
from components.c1_ingest.evidence import sha256_hex
from components.c2_processing.attack import AttackRelease
from components.c3_detection.ioc_builder import render_lists, render_rules
from components.c4_validation.corpus import TestEvent, TestSet
from components.c4_validation.event_gates import (
    EventGateReport,
    Tier1Runner,
    Tier2Runner,
    run_event_gates,
)
from components.c4_validation.gates import GateInputs, StaticReport, run_static_gates
from components.c4_validation.ioc_gates import IocTier1Runner, synthesize_tests
from components.c4_validation.quality import describe, quality_components, quality_score
from components.c4_validation.tier2 import LabManager
from schemas.common import RULE_TRANSITIONS, RuleKind, RuleState
from schemas.ioc_bundle import IocBundle
from schemas.sigma_subset import Assumption
from schemas.validation_result import (
    ALL_GATES,
    GateId,
    GateResult,
    GateStatus,
    Outcome,
    ValidationResult,
)

RESERVED_IDENTITIES = frozenset({"system", "agent", "llm", "model", "atidep", "bot", "auto",
                                 "automation", "scheduler", "anonymous", "unknown", ""})
EDITABLE = (RuleState.DRAFT, RuleState.VALIDATED, RuleState.PENDING_APPROVAL, RuleState.APPROVED,
            RuleState.DEPLOYED, RuleState.MONITORED)


class GovernanceError(Exception):
    pass


class ApprovalError(GovernanceError):
    pass


@dataclass
class ValidationOutcome:
    rule_id: str
    version: int
    outcome: Outcome
    results: list[GateResult]
    quality_score: int | None = None
    quality_breakdown: list[dict[str, Any]] = field(default_factory=list)
    report_sha256: str = ""
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def failed(self) -> list[GateId]:
        return [r.gate for r in self.results if r.status is GateStatus.FAILED]


# ---- helpers ---------------------------------------------------------------------------------
def report_sha256(results: list[GateResult]) -> str:
    rows = sorted(([r.gate.value, r.status.value, sorted(r.reason_codes), r.tier]
                   for r in results), key=lambda x: int(x[0][1:]))
    return hashlib.sha256(json.dumps(rows, separators=(",", ":")).encode()).hexdigest()


def _rule(session: Session, rule_id: str) -> m.Rule:
    rule = session.get(m.Rule, rule_id)
    if rule is None:
        raise GovernanceError(f"unknown rule {rule_id}")
    return rule


def _current(session: Session, rule: m.Rule) -> m.RuleVersion:
    return session.scalars(select(m.RuleVersion).where(
        m.RuleVersion.rule_id == rule.rule_id,
        m.RuleVersion.version == rule.current_version)).one()


def transition(session: Session, rule: m.Rule, new: RuleState, *, actor: str,
               reason: str = "") -> None:
    old = RuleState(rule.state)
    if new not in RULE_TRANSITIONS[old]:
        raise GovernanceError(f"a rule cannot go from {old.value} to {new.value}")
    rule.state = new.value
    append_audit_event(session, actor=actor, action=f"rule.{new.value}", entity_type="rule",
                       entity_id=rule.rule_id,
                       details={"from": old.value, "version": rule.current_version,
                                "reason": reason[:300]})
    session.flush()


def _require_human(identity: str) -> str:
    who = (identity or "").strip()
    if who.casefold() in RESERVED_IDENTITIES or len(who) > 80 or who.casefold().startswith(
            ("agent:", "llm:", "system:", "model:")):
        raise ApprovalError(f"{identity!r} is not a human identity; only a person can approve")
    return who


def _utc(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def _verified_quotes(session: Session, intel_id: str, evidence_ids: list[str]) -> dict[str, str]:
    claims = {c.evidence.evidence_id: c for c in load_claims(session, intel_id)}
    return {e: claims[e].evidence.quote for e in evidence_ids
            if e in claims and claims[e].evidence.verified}


def _store(session: Session, version: m.RuleVersion, results: list[GateResult]) -> None:
    session.execute(delete(m.ValidationResultRow).where(
        m.ValidationResultRow.rule_version_id == version.id))
    for r in results:
        session.add(m.ValidationResultRow(
            rule_version_id=version.id, gate=r.gate.value, status=r.status.value,
            reason_codes=r.reason_codes, message=r.message, tier=r.tier))
    session.flush()


def load_report(session: Session, version_id: int) -> list[GateResult]:
    rows = session.scalars(select(m.ValidationResultRow).where(
        m.ValidationResultRow.rule_version_id == version_id)).all()
    return sorted((GateResult(gate=GateId(r.gate), status=GateStatus(r.status),
                              reason_codes=r.reason_codes, message=r.message, tier=r.tier)
                   for r in rows), key=lambda r: int(r.gate.value[1:]))


def _complete(results: list[GateResult]) -> list[GateResult]:
    have = {r.gate for r in results}
    full = results + [GateResult(gate=g, status=GateStatus.NOT_RUN,
                                 message="not run: an earlier gate failed")
                      for g in ALL_GATES if g not in have]
    return sorted(full, key=lambda r: int(r.gate.value[1:]))


# ---- validation ------------------------------------------------------------------------------
def loop_validator(session: Session, cfg: AppConfig, attack: AttackRelease):
    """The validator that drives the Rule Agent's repair loop (gates G1-G7, DB-backed IDs)."""
    from components.c4_validation.gates import make_loop_validator

    return make_loop_validator(
        catalog=cfg.telemetry_catalog, wazuh_mapping=cfg.wazuh_mapping, attack=attack,
        policy=cfg.policies,
        allocate=lambda key: allocate_rule_id(
            session, key, id_range=tuple(cfg.policies.deployment.custom_rule_id_range)))


def validate_rule(session: Session, rule_id: str, *, cfg: AppConfig, attack: AttackRelease,
                  test_set: TestSet | None = None, baseline: list[TestEvent] | None = None,
                  lab: LabManager | None = None, actor: str = "system") -> ValidationOutcome:
    rule = _rule(session, rule_id)
    if rule.state != RuleState.DRAFT.value:
        raise GovernanceError(f"{rule_id} is {rule.state}; only drafts are validated")
    version = _current(session, rule)
    opp_row = session.get(m.DetectionOpportunity, rule.opportunity_id)
    assert opp_row is not None
    opp = to_schema(opp_row)
    quotes = _verified_quotes(session, opp_row.intel_id, opp.evidence_ids)
    detail: dict[str, Any] = {}

    if rule.kind == RuleKind.SIGMA.value:
        inp = GateInputs(
            opp, quotes, cfg.telemetry_catalog, cfg.wazuh_mapping, attack, cfg.policies,
            lambda key: allocate_rule_id(session, key,
                                         id_range=tuple(cfg.policies.deployment.custom_rule_id_range)))
        static: StaticReport = run_static_gates(
            version.content, [Assumption(**a) for a in version.assumptions], inp)
        results = list(static.results)
        events: EventGateReport | None = None
        if static.passed and static.ir is not None and static.conversion is not None:
            if test_set is None or baseline is None:
                raise GovernanceError("a test set and a benign baseline are needed for G8-G11")
            runners: list[Any] = [Tier1Runner(static.ir, cfg.wazuh_mapping)]
            if lab is not None:
                runners.append(Tier2Runner(lab, static.conversion.xml,
                                           static.conversion.rule_ids))
            events = run_event_gates(static.ir, test_set, baseline, runners, cfg.policies)
            results += events.results
            detail = {"events": events.details, "conversion": static.conversion.report}
        blocked = static.blocked
        defects = [d.model_dump() for d in static.defects + (events.defects if events else [])]
        detail["defects"] = defects
        detail["static_stats"] = static.stats
    else:
        results, blocked, detail, events, static = _validate_ioc(
            session, rule, version, opp_row.intel_id, cfg, baseline, lab)
    results = _complete(results)
    outcome = ValidationResult(results=results).outcome
    score: int | None = None
    breakdown: list[dict[str, Any]] = []
    if outcome is Outcome.VALIDATED:
        score, breakdown = _score(version, rule, static, events, cfg)
        version.quality_score = score
    _store(session, version, results)
    digest = report_sha256(results)
    old = RuleState(rule.state)
    if outcome is Outcome.VALIDATED:
        transition(session, rule, RuleState.VALIDATED, actor=actor, reason="all hard gates passed")
    elif outcome is Outcome.BLOCKED or blocked:
        transition(session, rule, RuleState.BLOCKED, actor=actor, reason="telemetry unavailable")
    append_audit_event(session, actor=actor, action="validate.completed", entity_type="rule",
                       entity_id=rule_id,
                       details={"version": version.version, "outcome": outcome.value,
                                "failed": [g.value for g in
                                           (r.gate for r in results
                                            if r.status is GateStatus.FAILED)],
                                "report_sha256": digest, "state_before": old.value,
                                "quality_score": score,
                                "tier": max((r.tier or 0) for r in results)})
    return ValidationOutcome(rule_id, version.version, outcome, results, score, breakdown, digest,
                             detail)


def _score(version: m.RuleVersion, rule: m.Rule, static: StaticReport | None,
           events: EventGateReport | None, cfg: AppConfig) -> tuple[int, list[dict[str, Any]]]:
    counts = (events.details.get("counts") if events else None) or {}
    uc = version.use_case or {}
    if static is not None and static.ir is not None:
        comp = quality_components(
            ir=static.ir, evidence_stats=static.stats.get("evidence", {}),
            falsepositives=uc.get("known_false_positives") or [],
            triage_present=bool(uc.get("triage_guidance")),
            tags=static.ir.tags, counts=counts,
            warnings=len(static.conversion.report.get("warnings", [])) if static.conversion else 0)
    else:                                                    # IOC bundle: everything is traced
        n = sum(counts.values()) if counts else 0
        comp = {"evidence_coverage": 100.0, "specificity": 100.0, "fp_analysis": 60.0,
                "attack_mapping_precision": 0.0,
                "test_coverage": min(100.0, 100.0 * n / 9.0), "lint_cleanliness": 100.0}
    return quality_score(comp, cfg.scoring), describe(comp, cfg.scoring)


def _validate_ioc(session: Session, rule: m.Rule, version: m.RuleVersion, intel_id: str,
                  cfg: AppConfig, baseline: list[TestEvent] | None, lab: LabManager | None):
    doc = json.loads(version.content)
    results: list[GateResult] = []
    blocked = False
    detail: dict[str, Any] = {"build_report": doc.get("report", {})}

    def add(gate: GateId, ok: bool, msg: str, codes: list[str] | None = None) -> None:
        results.append(GateResult(
            gate=gate, status=GateStatus.PASSED if ok else GateStatus.FAILED,
            reason_codes=[] if ok else (codes or [f"{gate.value}_FAILED"]), message=msg))

    try:
        bundle = IocBundle.model_validate(doc["bundle"])
    except (ValueError, KeyError) as exc:
        add(GateId.G1, False, f"the bundle does not validate: {str(exc)[:200]}", ["G1_BUNDLE"])
        return results, False, detail, None, None
    add(GateId.G1, True, "bundle schema is valid")
    add(GateId.G2, bool(bundle.entries) and bundle.intel_id == intel_id,
        f"{len(bundle.entries)} entries", ["G2_BUNDLE_METADATA"])
    # G4: each entry's evidence is a verified segment of this item
    verified = {c.evidence.evidence_id for c in load_claims(session, intel_id)
                if c.evidence.verified}
    missing = [e.value for e in bundle.entries if e.evidence_id not in verified]
    add(GateId.G4, not missing, "every entry links to a verified quotation" if not missing
        else f"entries without verified evidence: {missing[:3]}", ["G4_UNSUPPORTED_ENTRY"])
    # G3: rendering works and the XML is well-formed
    ids: dict[str, int] = {}

    def allocate(key: str) -> int:
        ids[key] = allocate_rule_id(session, key,
                                    id_range=tuple(cfg.policies.deployment.custom_rule_id_range))
        return ids[key]

    lists = render_lists(bundle.entries, cfg.policies)
    rendered = render_rules({bundle.bundle_id: bundle.entries}, policy=cfg.policies,
                            allocate=allocate)
    try:
        if rendered.xml:
            ElementTree.fromstring(rendered.xml)
        add(GateId.G3, bool(rendered.xml), "lists and rules render" if rendered.xml
            else "the bundle renders no rule", ["G3_NO_RULES"])
    except Exception as exc:  # noqa: BLE001
        add(GateId.G3, False, f"the rendered XML is not well-formed: {exc}", ["G3_XML"])
    add(GateId.G5, True, "fixed fields from the catalog; no free-form field")
    sources = cfg.telemetry_catalog.get("logsources", {})
    needed = {"ioc-template:dns-domain": "windows_dns_query",
              "ioc-template:net-ipv4": "windows_network_connection"}
    needed |= {k: "windows_process_creation" for k in ids if k.startswith("ioc:")}
    down = sorted({s for k, s in needed.items() if k in ids and
                   not sources.get(s, {}).get("available")})
    blocked = bool(down)
    add(GateId.G6, not down, "telemetry available for every rendered rule" if not down
        else f"telemetry not available: {down}", ["G6_TELEMETRY_UNAVAILABLE"])
    add(GateId.G7, True, "not applicable to an indicator bundle")
    events = None
    if all(r.status is GateStatus.PASSED for r in results if r.gate is not GateId.G6) \
            and not blocked and baseline is not None:
        ts = synthesize_tests(bundle.entries)       # a bundle is always tested on its own events
        runners: list[Any] = [IocTier1Runner(bundle.entries)]
        if lab is not None:
            runners.append(Tier2Runner(lab, rendered.xml, list(rendered.rule_ids.values()), lists))
        events = run_event_gates(None, ts, baseline, runners, cfg.policies)
        results += events.results
        detail["events"] = events.details
        detail["defects"] = [d.model_dump() for d in events.defects]
    elif baseline is None and not blocked and all(
            r.status is GateStatus.PASSED for r in results if r.gate is not GateId.G6):
        raise GovernanceError("a benign baseline is needed for G11")
    return results, blocked, detail, events, None


# ---- approval ----------------------------------------------------------------------------------
def submit_for_approval(session: Session, rule_id: str, *, actor: str = "system") -> None:
    rule = _rule(session, rule_id)
    version = _current(session, rule)
    report = load_report(session, version.id)
    if ValidationResult(results=report).outcome is not Outcome.VALIDATED:
        raise GovernanceError("only a rule whose current version passed every gate can be "
                              "submitted for approval")
    transition(session, rule, RuleState.PENDING_APPROVAL, actor=actor)


def decide(session: Session, rule_id: str, *, reviewer: str, decision: str, comment: str = "",
           author: str = "ATIDEP", deployment_target: str | None = "lab",
           rollback_ref: str | None = None) -> m.Approval:
    if decision not in ("approved", "rejected"):
        raise GovernanceError("decision must be 'approved' or 'rejected'")
    who = _require_human(reviewer)
    rule = _rule(session, rule_id)
    if rule.state != RuleState.PENDING_APPROVAL.value:
        raise GovernanceError(f"{rule_id} is {rule.state}; it must be pending approval")
    version = _current(session, rule)
    if sha256_hex(version.content) != version.content_sha256:
        raise ApprovalError("the stored rule content no longer matches its hash")
    report = load_report(session, version.id)
    if ValidationResult(results=report).outcome is not Outcome.VALIDATED:
        raise GovernanceError("the validation report no longer shows every gate passed")
    approval = m.Approval(
        rule_version_id=version.id, reviewer=who, author=author, decision=decision,
        comment=comment, content_sha256=version.content_sha256,
        validation_report_sha256=report_sha256(report), deployment_target=deployment_target,
        rollback_ref=rollback_ref)
    session.add(approval)
    session.flush()
    transition(session, rule, RuleState.APPROVED if decision == "approved" else RuleState.REJECTED,
               actor=who, reason=comment)
    append_audit_event(session, actor=who, action=f"approval.{decision}", entity_type="rule",
                       entity_id=rule_id,
                       details={"version": version.version, "content_sha256":
                                version.content_sha256, "approval_id": approval.id,
                                "reviewer": who, "author": author})
    return approval


def edit_rule(session: Session, rule_id: str, content: str, *, editor: str,
              assumptions: list[dict] | None = None, use_case: dict | None = None
              ) -> m.RuleVersion:
    """A human edit: new version, validation voided, any approval no longer applies."""
    who = _require_human(editor)
    rule = _rule(session, rule_id)
    state = RuleState(rule.state)
    if state not in EDITABLE:
        raise GovernanceError(f"a {state.value} rule cannot be edited")
    previous = _current(session, rule)
    version = add_rule_version(session, rule, origin="human_edit", content=content,
                               assumptions=assumptions if assumptions is not None
                               else previous.assumptions,
                               use_case=use_case if use_case is not None else previous.use_case)
    if state in (RuleState.APPROVED, RuleState.DEPLOYED, RuleState.MONITORED):
        transition(session, rule, RuleState.REVISED, actor=who, reason="edit after approval")
        transition(session, rule, RuleState.DRAFT, actor=who, reason="new version")
        append_audit_event(session, actor=who, action="approval.voided", entity_type="rule",
                           entity_id=rule_id, details={"new_version": version.version})
    elif state in (RuleState.VALIDATED, RuleState.PENDING_APPROVAL):
        transition(session, rule, RuleState.DRAFT, actor=who, reason="edit voids validation")
    append_audit_event(session, actor=who, action="rule.edited", entity_type="rule",
                       entity_id=rule_id,
                       details={"version": version.version,
                                "content_sha256": version.content_sha256})
    return version


def verify_approval(session: Session, rule_id: str) -> m.Approval:
    """Called before any deployment. Returns the approval that covers the current content,
    or raises. The content hash is recomputed from the stored text, so a change made behind
    the application's back is caught (Scenario 7)."""
    rule = _rule(session, rule_id)
    if rule.state not in (RuleState.APPROVED.value, RuleState.DEPLOYED.value,
                          RuleState.MONITORED.value):
        raise ApprovalError(f"{rule_id} is {rule.state}; it is not approved")
    version = _current(session, rule)
    actual = sha256_hex(version.content)
    if actual != version.content_sha256:
        raise ApprovalError("the rule content was changed after it was stored (hash mismatch)")
    approval = session.scalars(select(m.Approval).where(
        m.Approval.rule_version_id == version.id,
        m.Approval.decision == "approved").order_by(m.Approval.id.desc())).first()
    if approval is None:
        raise ApprovalError("no approval covers the current version")
    if approval.content_sha256 != actual:
        raise ApprovalError("the approval was given for different content")
    if report_sha256(load_report(session, version.id)) != approval.validation_report_sha256:
        raise ApprovalError("the validation report changed after approval")
    return approval
