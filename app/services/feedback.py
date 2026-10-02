"""Alerts, analyst dispositions, statistics and the Improvement Agent (blueprint §17.5.2).

Alerts from the lab manager are stored with the few features the statistics need. The
Improvement Agent works on aggregates only, and what it changes becomes a new rule version that
must pass all gates and be approved again; nothing it proposes reaches the manager by itself.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import yaml
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import AppConfig
from app.db import models as m
from app.db.audit import append_audit_event
from app.services.detection import add_rule_version
from app.services.governance import GovernanceError, transition
from app.services.model_runs import log_calls
from components.c5_deployment.feedback import (
    DISPOSITIONS,
    RuleStats,
    alert_features,
    compute_stats,
)
from components.c5_deployment.improvement import (
    APPLIED,
    Recommendation,
    apply_recommendations,
    run_improvement_agent,
)
from components.llm.client import LLMClient
from components.llm.prompts import Prompt
from schemas.common import RuleKind, RuleState
from schemas.sigma_subset import Assumption

LIVE = (RuleState.DEPLOYED.value, RuleState.MONITORED.value)
REVISABLE = (RuleState.APPROVED.value, *LIVE)


def _ts(value: str | None) -> datetime | None:
    if not value:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            return datetime.strptime(value, fmt).astimezone(UTC)
        except ValueError:
            continue
    return None


def _deployments(session: Session, rule_id: str) -> list[m.Deployment]:
    return list(session.scalars(
        select(m.Deployment).join(m.RuleVersion, m.RuleVersion.id == m.Deployment.rule_version_id)
        .where(m.RuleVersion.rule_id == rule_id, m.Deployment.mode == "lab",
               m.Deployment.status == "ok").order_by(m.Deployment.id)))


def ingest_alerts(session: Session, rule_id: str, alerts: list[dict[str, Any]], *,
                  actor: str = "system") -> int:
    """Store alerts of this rule's Wazuh rules (others are ignored); returns how many were new."""
    rule = session.get(m.Rule, rule_id)
    if rule is None:
        raise GovernanceError(f"unknown rule {rule_id}")
    deployments = _deployments(session, rule_id)
    if not deployments:
        raise GovernanceError(f"{rule_id} has no successful lab deployment")
    dep = deployments[-1]
    wanted = set(dep.wazuh_rule_ids)
    known = set(session.scalars(select(m.DetectionResult.alert_ref).where(
        m.DetectionResult.deployment_id == dep.id)))
    new = 0
    for alert in alerts:
        try:
            feats = alert_features(alert)
        except (KeyError, TypeError, ValueError):
            continue
        ref = str(feats.pop("alert_id") or f"{feats['timestamp']}:{feats['rule_id']}")
        if feats["rule_id"] not in wanted or ref in known:
            continue
        known.add(ref)
        session.add(m.DetectionResult(
            deployment_id=dep.id, alert_ref=ref, event_time=_ts(feats["timestamp"]),
            disposition="unknown", rule_id_fired=feats["rule_id"], features=feats))
        new += 1
    if new and rule.state == RuleState.DEPLOYED.value:
        transition(session, rule, RuleState.MONITORED, actor=actor, reason="first alerts")
    append_audit_event(session, actor=actor, action="feedback.alerts_ingested",
                       entity_type="rule", entity_id=rule_id, details={"new": new})
    session.flush()
    return new


def set_disposition(session: Session, result_id: int, disposition: str, analyst: str,
                    notes: str = "") -> None:
    if disposition not in DISPOSITIONS:
        raise GovernanceError(f"disposition must be one of {DISPOSITIONS}")
    if not analyst.strip():
        raise GovernanceError("an analyst name is required")
    row = session.get(m.DetectionResult, result_id)
    if row is None:
        raise GovernanceError(f"unknown alert record {result_id}")
    row.disposition, row.analyst, row.notes = disposition, analyst.strip(), notes[:1000]
    append_audit_event(session, actor=analyst.strip(), action="feedback.disposition",
                       entity_type="detection_result", entity_id=str(result_id),
                       details={"disposition": disposition})
    session.flush()


def rule_stats(session: Session, rule_id: str, *, min_cluster: int = 2) -> RuleStats:
    rows = []
    for dep in _deployments(session, rule_id):
        for r in session.scalars(select(m.DetectionResult).where(
                m.DetectionResult.deployment_id == dep.id)):
            rows.append({**(r.features or {}), "disposition": r.disposition})
    return compute_stats(rows, min_cluster=min_cluster)


@dataclass
class ImprovementReport:
    stats: RuleStats
    accepted: list[Recommendation] = field(default_factory=list)
    rejected: list[tuple[Recommendation, str]] = field(default_factory=list)
    applied: list[Recommendation] = field(default_factory=list)
    new_version: int | None = None
    skipped: str | None = None
    error: str | None = None


def improve_rule(session: Session, rule_id: str, client: LLMClient, prompt: Prompt,
                 cfg: AppConfig, *, now: datetime, apply: bool = True, seed: int | None = None,
                 run_id: str = "improve", actor: str = "system") -> ImprovementReport:
    rule = session.get(m.Rule, rule_id)
    if rule is None:
        raise GovernanceError(f"unknown rule {rule_id}")
    stats = rule_stats(session, rule_id)
    report = ImprovementReport(stats)
    if rule.state not in LIVE:
        raise GovernanceError(f"{rule_id} is {rule.state}; only a live rule is improved")
    if rule.kind != RuleKind.SIGMA.value:
        report.skipped = "indicator bundles are rebuilt by the expiry sweep, not tuned"
        return report
    if stats.alerts == 0:
        report.skipped = "no alerts yet; nothing to learn from"
        return report
    version = session.scalars(select(m.RuleVersion).where(
        m.RuleVersion.rule_id == rule_id, m.RuleVersion.version == rule.current_version)).one()
    doc = yaml.safe_load(version.content)
    category = doc["logsource"]["category"]
    allowed = next((set(info.get("fields", [])) for info in
                    cfg.telemetry_catalog.get("logsources", {}).values()
                    if info.get("sigma_category") == category), set())
    created = rule.created_at if rule.created_at.tzinfo else rule.created_at.replace(tzinfo=UTC)
    res = run_improvement_agent(client, version.content, stats, prompt=prompt,
                                allowed_fields=allowed, rule_age_days=(now - created).days,
                                seed=seed)
    log_calls(session, run_id=run_id, agent="improvement", intel_id=None, calls=res.calls,
              prompt=prompt)
    report.accepted, report.rejected, report.error = res.accepted, res.rejected, res.error
    todo = [r for r in res.accepted if r.action in APPLIED]
    if apply and todo:
        change = apply_recommendations(version.content, todo, stats,
                                       [Assumption(**a) for a in version.assumptions])
        new = add_rule_version(session, rule, origin="improvement", content=change.sigma_yaml,
                               assumptions=[a.model_dump() for a in change.assumptions],
                               use_case=version.use_case)
        transition(session, rule, RuleState.REVISED, actor=actor, reason="improvement")
        transition(session, rule, RuleState.DRAFT, actor=actor, reason="new version")
        report.applied, report.new_version = todo, new.version
        append_audit_event(session, actor=actor, action="improvement.applied",
                           entity_type="rule", entity_id=rule_id,
                           details={"new_version": new.version, "changes": change.descriptions,
                                    "recommendations": json.loads(json.dumps(
                                        [r.model_dump(mode="json") for r in todo]))})
    else:
        append_audit_event(session, actor=actor, action="improvement.recommended",
                           entity_type="rule", entity_id=rule_id,
                           details={"accepted": len(res.accepted), "rejected": len(res.rejected)})
    session.flush()
    return report
