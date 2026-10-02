"""C3 orchestration and persistence (blueprint §17.3).

* ``assess_item``: Opportunity Agent -> override -> ``detection_opportunities`` rows.
* ``create_ioc_rule``: deterministic IOC bundle -> ``rules`` (kind ``ioc_list``) + version.
* ``create_sigma_rule``: Rule Agent repair loop -> ``rules`` (kind ``sigma``) + one version per
  attempt, with every model call logged.

A rule produced here is always a ``draft``. Validation, approval and deployment are separate
steps with their own checks.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.config import AppConfig
from app.db import models as m
from app.db.audit import append_audit_event
from app.services.claims import load_claims
from app.services.model_runs import log_calls
from components.c1_ingest.evidence import sha256_hex
from components.c2_processing.attack import AttackRelease
from components.c3_detection.ioc_builder import build_bundle
from components.c3_detection.opportunity import (
    OpportunityContext,
    run_opportunity_agent,
)
from components.c3_detection.rule_agent import (
    RuleContext,
    RuleLoopResult,
    Validator,
    generate_rule,
    use_case_for,
)
from components.llm.client import LLMClient
from components.llm.prompts import Prompt
from schemas.common import ProcessingStatus, RuleKind, RuleState
from schemas.detection_opportunity import Decision, DetectionOpportunity

REVIEW_DAYS = 180
REJECTING = frozenset({Decision.NOT_RELEVANT, Decision.INSUFFICIENT_EVIDENCE,
                       Decision.EXPIRED_OR_LOW_VALUE})


class DetectionError(Exception):
    pass


def _utc(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


# ---- opportunities -------------------------------------------------------------------------
def assess_item(session: Session, intel_id: str, *, cfg: AppConfig, attack: AttackRelease,
                client: LLMClient, prompt: Prompt, now: datetime | None = None,
                seed: int | None = None, run_id: str = "assess", actor: str = "system"
                ) -> list[int]:
    """Returns the IDs of the stored opportunities. An item gets a decision only once."""
    item = session.get(m.IntelligenceItem, intel_id)
    if item is None:
        raise DetectionError(f"unknown item {intel_id}")
    if item.status != ProcessingStatus.PRIORITISED.value:
        raise DetectionError(f"{intel_id} is {item.status}; only prioritised items are assessed")
    claims = load_claims(session, intel_id)
    support = 100.0 * sum(c.evidence.verified for c in claims) / len(claims) if claims else 0.0
    ctx = OpportunityContext(intel_id, item.title, claims, support, item.intelligence_confidence,
                             now or datetime.now(UTC))
    res = run_opportunity_agent(client, ctx, prompt=prompt, policy=cfg.policies,
                                catalog=cfg.telemetry_catalog, attack=attack, seed=seed)
    log_calls(session, run_id=run_id, agent="opportunity", intel_id=intel_id, calls=res.calls,
              prompt=prompt)
    if res.error:
        item.processing = {**item.processing, "last_error": f"opportunity: {res.error}"[:300]}
        append_audit_event(session, actor=actor, action="assess.failed",
                           entity_type="intelligence_item", entity_id=intel_id,
                           details={"error": res.error[:300]})
        session.flush()
        return []
    ids: list[int] = []
    for o in res.opportunities:
        row = m.DetectionOpportunity(
            intel_id=intel_id, decision=o.decision.value, detectable=o.detectable,
            detection_concept=o.detection_concept, required_log_source=o.required_log_source,
            required_fields=o.required_fields, attack_techniques=o.attack_techniques,
            false_positive_hypotheses=o.false_positive_hypotheses, evidence_ids=o.evidence_ids,
            decision_reason=o.decision_reason, llm_stated_confidence=o.llm_stated_confidence,
            override_applied=o.override_applied, override_reason=o.override_reason)
        session.add(row)
        session.flush()
        ids.append(row.opportunity_id)
    decisions = {o.decision for o in res.opportunities}
    generating = any(o.generates_rule for o in res.opportunities)
    rejected = (not decisions) or (not generating and decisions <= REJECTING)
    item.status = (ProcessingStatus.REJECTED if rejected else ProcessingStatus.ASSESSED).value
    item.processing = {k: v for k, v in item.processing.items() if k != "last_error"}
    append_audit_event(
        session, actor=actor, action="assess.completed", entity_type="intelligence_item",
        entity_id=intel_id,
        details={"opportunities": ids, "decisions": sorted(d.value for d in decisions),
                 "overrides": sum(o.override_applied for o in res.opportunities),
                 "status": item.status})
    session.flush()
    return ids


def to_schema(row: m.DetectionOpportunity) -> DetectionOpportunity:
    return DetectionOpportunity(
        detectable=row.detectable, decision=Decision(row.decision),
        detection_concept=row.detection_concept, required_log_source=row.required_log_source,
        required_fields=row.required_fields, attack_techniques=row.attack_techniques,
        false_positive_hypotheses=row.false_positive_hypotheses, evidence_ids=row.evidence_ids,
        decision_reason=row.decision_reason, llm_stated_confidence=row.llm_stated_confidence,
        override_applied=row.override_applied, override_reason=row.override_reason)


# ---- rules ---------------------------------------------------------------------------------
def _next_rule_id(session: Session, year: int) -> str:
    prefix = f"RULE-{year}-"
    last = session.scalars(select(func.max(m.Rule.rule_id)).where(
        m.Rule.rule_id.like(prefix + "%"))).first()
    return f"{prefix}{(int(last.rsplit('-', 1)[1]) + 1) if last else 1:04d}"


def add_rule_version(session: Session, rule: m.Rule, *, origin: str, content: str,
                     assumptions: list | None = None, use_case: dict | None = None
                     ) -> m.RuleVersion:
    last = session.scalars(select(func.max(m.RuleVersion.version)).where(
        m.RuleVersion.rule_id == rule.rule_id)).first() or 0
    row = m.RuleVersion(rule_id=rule.rule_id, version=last + 1, origin=origin, content=content,
                        content_sha256=sha256_hex(content), assumptions=assumptions or [],
                        use_case=use_case or {})
    session.add(row)
    rule.current_version = last + 1
    session.flush()
    return row


def _opportunity(session: Session, opportunity_id: int) -> m.DetectionOpportunity:
    row = session.get(m.DetectionOpportunity, opportunity_id)
    if row is None:
        raise DetectionError(f"unknown opportunity {opportunity_id}")
    return row


def create_ioc_rule(session: Session, opportunity_id: int, *, cfg: AppConfig,
                    benign_domains: list[str], now: datetime | None = None,
                    actor: str = "system") -> str:
    opp = _opportunity(session, opportunity_id)
    if opp.decision != Decision.IOC_BASED.value:
        raise DetectionError(f"opportunity {opportunity_id} is {opp.decision}, not ioc_based")
    built = build_bundle(opp.intel_id, load_claims(session, opp.intel_id),
                         now=now or datetime.now(UTC), benign_domains=benign_domains,
                         policy=cfg.policies, catalog=cfg.telemetry_catalog)
    if not built.bundle.entries:
        raise DetectionError("the bundle would be empty; nothing to detect")
    rule = m.Rule(rule_id=_next_rule_id(session, datetime.now(UTC).year),
                  opportunity_id=opportunity_id, kind=RuleKind.IOC_LIST.value,
                  state=RuleState.DRAFT.value)
    session.add(rule)
    session.flush()
    content = json.dumps({"bundle": json.loads(built.bundle.model_dump_json()),
                          "report": built.report}, sort_keys=True, indent=2)
    add_rule_version(session, rule, origin="ioc_builder", content=content)
    append_audit_event(session, actor=actor, action="rule.created", entity_type="rule",
                       entity_id=rule.rule_id,
                       details={"kind": "ioc_list", "entries": len(built.bundle.entries),
                                "excluded": built.report["excluded"]})
    return rule.rule_id


def rule_context_for(session: Session, opportunity_id: int, cfg: AppConfig, *,
                     author: str = "ATIDEP", today=None) -> RuleContext:
    opp_row = _opportunity(session, opportunity_id)
    opp = to_schema(opp_row)
    log_source = opp.required_log_source or ""
    info = cfg.telemetry_catalog.get("logsources", {}).get(log_source)
    if not info or "sigma_category" not in info:
        raise DetectionError(f"log source {log_source!r} cannot be converted in the v0 subset")
    claims = {c.evidence.evidence_id: c for c in load_claims(session, opp_row.intel_id)}
    quotes = {eid: claims[eid].evidence.quote for eid in opp.evidence_ids
              if eid in claims and claims[eid].evidence.verified}
    item = session.get(m.IntelligenceItem, opp_row.intel_id)
    refs = tuple(r for r in (item.url if item else None,) if r)
    extra = {"today": today} if today else {}
    return RuleContext(intel_id=opp_row.intel_id, opportunity_id=opportunity_id, opportunity=opp,
                       quotes=quotes, allowed_fields=list(info.get("fields", [])),
                       sigma_category=info["sigma_category"], author=author, references=refs,
                       **extra)


def create_sigma_rule(session: Session, opportunity_id: int, *, cfg: AppConfig, client: LLMClient,
                      prompt: Prompt, validate: Validator, seed: int | None = None,
                      run_id: str = "rule", owner: str = "researcher",
                      review_date: str | None = None, intelligence_confidence: int | None = None,
                      actor: str = "system", ctx: RuleContext | None = None
                      ) -> tuple[str | None, RuleLoopResult]:
    """Runs the repair loop and stores what it produced. Returns (rule_id or None, result)."""
    ctx = ctx or rule_context_for(session, opportunity_id, cfg)
    item = session.get(m.IntelligenceItem, ctx.intel_id)
    if intelligence_confidence is None and item is not None:
        intelligence_confidence = item.intelligence_confidence
    review_date = review_date or (
        datetime.now(UTC) + timedelta(days=REVIEW_DAYS)).date().isoformat()
    result = generate_rule(client, ctx, validate, prompt=prompt, seed=seed,
                           max_repairs=cfg.policies.rule_generation.repair_max_attempts)
    for n, attempt in enumerate(result.attempts):
        log_calls(session, run_id=run_id, agent="rule", intel_id=ctx.intel_id,
                  calls=attempt.calls, prompt=prompt, repair_attempt=n)
    final = result.final
    if final is None:
        append_audit_event(session, actor=actor, action="rule.no_draft", entity_type="opportunity",
                           entity_id=str(opportunity_id),
                           details={"error": (result.attempts[0].schema_error or "")[:300]})
        session.flush()
        return None, result
    rule = m.Rule(rule_id=_next_rule_id(session, datetime.now(UTC).year),
                  opportunity_id=opportunity_id, kind=RuleKind.SIGMA.value,
                  state=RuleState.DRAFT.value)
    session.add(rule)
    session.flush()
    for attempt in result.attempts:
        if attempt.output is None or attempt.sigma_yaml is None:
            continue
        uc = use_case_for(attempt.output, ctx, confidence=intelligence_confidence, owner=owner,
                          review_date=review_date)
        add_rule_version(session, rule, origin=attempt.origin, content=attempt.sigma_yaml,
                         assumptions=[a.model_dump() for a in attempt.output.assumptions],
                         use_case=uc)
    if result.status == "blocked":
        rule.state = RuleState.BLOCKED.value
    append_audit_event(
        session, actor=actor, action=f"rule.{result.status}", entity_type="rule",
        entity_id=rule.rule_id,
        details={"attempts": len(result.attempts), "first_pass_valid": result.first_pass_valid,
                 "repairs_used": result.repairs_used, "opportunity": opportunity_id})
    session.flush()
    return rule.rule_id, result

