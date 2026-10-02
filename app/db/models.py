"""SQLite schema: the 15 tables of blueprint §39.

CHECK constraints are generated from the same enums the Pydantic schemas use, so the two
cannot drift apart.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from schemas.claim import ClaimKind, IndicatorContext
from schemas.common import Band, ProcessingStatus, RuleKind, RuleState
from schemas.detection_opportunity import Decision
from schemas.effort_cost_record import Component, Condition, ResultStatus
from schemas.validation_result import GateId, GateStatus


def _now() -> datetime:
    return datetime.now(UTC)


def _in(column: str, values: Any) -> str:
    items = ", ".join("'" + (v.value if isinstance(v, StrEnum) else str(v)) + "'" for v in values)
    return f"{column} IN ({items})"


def _range(column: str, low: float, high: float) -> str:
    return f"{column} >= {low} AND {column} <= {high}"


class Base(DeclarativeBase):
    type_annotation_map = {dict[str, Any]: JSON, list[Any]: JSON}


class Source(Base):
    __tablename__ = "sources"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String, unique=True)
    source_type: Mapped[str] = mapped_column(String)
    url: Mapped[str | None] = mapped_column(String)
    reliability_rating: Mapped[str] = mapped_column(String)
    default_credibility: Mapped[int] = mapped_column(Integer, default=3)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    __table_args__ = (
        CheckConstraint(_in("reliability_rating", "ABCDEF")),
        CheckConstraint(_range("default_credibility", 1, 6)),
    )


class IntelligenceItem(Base):
    __tablename__ = "intelligence_items"
    intel_id: Mapped[str] = mapped_column(String, primary_key=True)
    source_id: Mapped[int] = mapped_column(ForeignKey("sources.id"))
    title: Mapped[str] = mapped_column(String)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    retrieved_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    raw_sha256: Mapped[str] = mapped_column(String(64), unique=True)
    sanitised_sha256: Mapped[str] = mapped_column(String(64))
    sanitisation_stripped: Mapped[list[Any]] = mapped_column(JSON, default=list)
    cluster_id: Mapped[str | None] = mapped_column(String)
    tlp: Mapped[str] = mapped_column(String, default="CLEAR")
    credibility_rating: Mapped[int] = mapped_column(Integer, default=3)
    intelligence_confidence: Mapped[int | None] = mapped_column(Integer)
    priority_score: Mapped[float | None] = mapped_column(Float)
    priority_band: Mapped[str | None] = mapped_column(String)
    priority_components: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String, default=ProcessingStatus.INGESTED.value)
    processing: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    __table_args__ = (
        CheckConstraint(_range("credibility_rating", 1, 6)),
        CheckConstraint("intelligence_confidence IS NULL OR "
                        + _range("intelligence_confidence", 0, 100)),
        CheckConstraint("priority_score IS NULL OR " + _range("priority_score", 0, 100)),
        CheckConstraint("priority_band IS NULL OR " + _in("priority_band", Band)),
        CheckConstraint(_in("status", ProcessingStatus)),
    )


class EvidenceSegment(Base):
    __tablename__ = "evidence_segments"
    evidence_id: Mapped[str] = mapped_column(String, primary_key=True)
    intel_id: Mapped[str] = mapped_column(ForeignKey("intelligence_items.intel_id"))
    quote: Mapped[str] = mapped_column(Text)
    char_start: Mapped[int] = mapped_column(Integer)
    char_end: Mapped[int] = mapped_column(Integer)
    source_sha256: Mapped[str] = mapped_column(String(64))
    verified: Mapped[bool] = mapped_column(Boolean, default=False)
    __table_args__ = (CheckConstraint("char_start >= 0 AND char_end > char_start"),)


class Claim(Base):
    __tablename__ = "claims"
    claim_id: Mapped[str] = mapped_column(String, primary_key=True)
    intel_id: Mapped[str] = mapped_column(ForeignKey("intelligence_items.intel_id"))
    evidence_id: Mapped[str] = mapped_column(ForeignKey("evidence_segments.evidence_id"))
    kind: Mapped[str] = mapped_column(String)
    type: Mapped[str | None] = mapped_column(String)
    value: Mapped[str | None] = mapped_column(String)
    refanged_from: Mapped[str | None] = mapped_column(String)
    description: Mapped[str | None] = mapped_column(Text)
    attack_id: Mapped[str | None] = mapped_column(String)
    valid: Mapped[bool] = mapped_column(Boolean, default=True)
    context: Mapped[str] = mapped_column(String, default=IndicatorContext.UNKNOWN.value)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    llm_stated_confidence: Mapped[int | None] = mapped_column(Integer)
    __table_args__ = (
        CheckConstraint(_in("kind", ClaimKind)),
        CheckConstraint(_in("context", IndicatorContext)),
        CheckConstraint("llm_stated_confidence IS NULL OR "
                        + _range("llm_stated_confidence", 0, 100)),
    )


class DetectionOpportunity(Base):
    __tablename__ = "detection_opportunities"
    opportunity_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    intel_id: Mapped[str] = mapped_column(ForeignKey("intelligence_items.intel_id"))
    decision: Mapped[str] = mapped_column(String)
    detectable: Mapped[bool] = mapped_column(Boolean)
    detection_concept: Mapped[str | None] = mapped_column(Text)
    required_log_source: Mapped[str | None] = mapped_column(String)
    required_fields: Mapped[list[Any]] = mapped_column(JSON, default=list)
    attack_techniques: Mapped[list[Any]] = mapped_column(JSON, default=list)
    false_positive_hypotheses: Mapped[list[Any]] = mapped_column(JSON, default=list)
    evidence_ids: Mapped[list[Any]] = mapped_column(JSON, default=list)
    decision_reason: Mapped[str] = mapped_column(Text)
    llm_stated_confidence: Mapped[int | None] = mapped_column(Integer)
    override_applied: Mapped[bool] = mapped_column(Boolean, default=False)
    override_reason: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    __table_args__ = (CheckConstraint(_in("decision", Decision)),)


class Rule(Base):
    __tablename__ = "rules"
    rule_id: Mapped[str] = mapped_column(String, primary_key=True)
    opportunity_id: Mapped[int] = mapped_column(
        ForeignKey("detection_opportunities.opportunity_id"))
    kind: Mapped[str] = mapped_column(String)
    state: Mapped[str] = mapped_column(String, default=RuleState.DRAFT.value)
    current_version: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now,
                                                 onupdate=_now)
    __table_args__ = (CheckConstraint(_in("kind", RuleKind)),
                      CheckConstraint(_in("state", RuleState)))


class RuleVersion(Base):
    __tablename__ = "rule_versions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    rule_id: Mapped[str] = mapped_column(ForeignKey("rules.rule_id"))
    version: Mapped[int] = mapped_column(Integer)
    origin: Mapped[str] = mapped_column(String)
    content: Mapped[str] = mapped_column(Text)
    content_sha256: Mapped[str] = mapped_column(String(64))
    assumptions: Mapped[list[Any]] = mapped_column(JSON, default=list)
    quality_score: Mapped[int | None] = mapped_column(Integer)  # ranking only
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    __table_args__ = (
        UniqueConstraint("rule_id", "version"),
        CheckConstraint(_in("origin", ["llm_initial", "llm_repair_1", "llm_repair_2",
                                       "human_edit", "improvement", "ioc_builder"])),
        CheckConstraint("version >= 1"),
        CheckConstraint("quality_score IS NULL OR " + _range("quality_score", 0, 100)),
    )


class ValidationResultRow(Base):
    __tablename__ = "validation_results"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    rule_version_id: Mapped[int] = mapped_column(ForeignKey("rule_versions.id"))
    gate: Mapped[str] = mapped_column(String)
    status: Mapped[str] = mapped_column(String)
    reason_codes: Mapped[list[Any]] = mapped_column(JSON, default=list)
    message: Mapped[str] = mapped_column(Text, default="")
    tier: Mapped[int | None] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    __table_args__ = (CheckConstraint(_in("gate", GateId)),
                      CheckConstraint(_in("status", GateStatus)))


class Approval(Base):
    __tablename__ = "approvals"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    rule_version_id: Mapped[int] = mapped_column(ForeignKey("rule_versions.id"))
    reviewer: Mapped[str] = mapped_column(String)
    author: Mapped[str] = mapped_column(String)
    decision: Mapped[str] = mapped_column(String)
    comment: Mapped[str] = mapped_column(Text, default="")
    content_sha256: Mapped[str] = mapped_column(String(64))
    validation_report_sha256: Mapped[str] = mapped_column(String(64))
    deployment_target: Mapped[str | None] = mapped_column(String)
    rollback_ref: Mapped[str | None] = mapped_column(String)
    decided_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    __table_args__ = (CheckConstraint(_in("decision", ["approved", "rejected"])),)


class Deployment(Base):
    __tablename__ = "deployments"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    rule_version_id: Mapped[int] = mapped_column(ForeignKey("rule_versions.id"))
    approval_id: Mapped[int | None] = mapped_column(ForeignKey("approvals.id"))
    mode: Mapped[str] = mapped_column(String)
    package_sha256: Mapped[str] = mapped_column(String(64))
    package_path: Mapped[str | None] = mapped_column(String)
    status: Mapped[str] = mapped_column(String)
    wazuh_rule_ids: Mapped[list[Any]] = mapped_column(JSON, default=list)
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    __table_args__ = (
        CheckConstraint(_in("mode", ["export", "dry_run", "lab"])),
        CheckConstraint(_in("status", ["ok", "failed", "rolled_back"])),
        # a lab deployment must reference an approval
        CheckConstraint("mode != 'lab' OR approval_id IS NOT NULL"),
    )


class DetectionResult(Base):
    __tablename__ = "detection_results"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    deployment_id: Mapped[int] = mapped_column(ForeignKey("deployments.id"))
    alert_ref: Mapped[str | None] = mapped_column(String)
    event_time: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    disposition: Mapped[str] = mapped_column(String, default="unknown")
    analyst: Mapped[str | None] = mapped_column(String)
    notes: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    __table_args__ = (CheckConstraint(
        _in("disposition", ["true_positive", "false_positive", "benign_true_positive",
                            "unknown"])),)


class ModelRun(Base):
    __tablename__ = "model_runs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    run_id: Mapped[str] = mapped_column(String)
    intel_id: Mapped[str | None] = mapped_column(ForeignKey("intelligence_items.intel_id"))
    agent: Mapped[str] = mapped_column(String)
    repair_attempt: Mapped[int] = mapped_column(Integer, default=0)
    provider: Mapped[str] = mapped_column(String)
    model: Mapped[str] = mapped_column(String)
    model_version: Mapped[str | None] = mapped_column(String)
    temperature: Mapped[float | None] = mapped_column(Float)
    seed: Mapped[int | None] = mapped_column(Integer)
    prompt_version: Mapped[str] = mapped_column(String)
    prompt_sha256: Mapped[str] = mapped_column(String(64))
    input_tokens: Mapped[int] = mapped_column(Integer, default=0)
    output_tokens: Mapped[int] = mapped_column(Integer, default=0)
    latency_ms: Mapped[int | None] = mapped_column(Integer)
    estimated_cost: Mapped[float | None] = mapped_column(Float)
    schema_valid: Mapped[bool] = mapped_column(Boolean)
    retry_count: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    __table_args__ = (
        CheckConstraint(_in("agent", ["extraction", "opportunity", "rule", "improvement",
                                      "single_prompt_baseline"])),
        CheckConstraint("repair_attempt >= 0"),
    )


class EffortCostRecord(Base):
    __tablename__ = "effort_cost_records"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    run_id: Mapped[str] = mapped_column(String)
    intel_id: Mapped[str | None] = mapped_column(ForeignKey("intelligence_items.intel_id"))
    condition: Mapped[str] = mapped_column(String)
    component: Mapped[str] = mapped_column(String)
    activity: Mapped[str | None] = mapped_column(String)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    ended_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    analyst_active_seconds: Mapped[float] = mapped_column(Float, default=0.0)
    cpu_pct_avg: Mapped[float | None] = mapped_column(Float)
    mem_mb_peak: Mapped[float | None] = mapped_column(Float)
    api_calls: Mapped[int] = mapped_column(Integer, default=0)
    input_tokens: Mapped[int] = mapped_column(Integer, default=0)
    output_tokens: Mapped[int] = mapped_column(Integer, default=0)
    price_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    result_status: Mapped[str] = mapped_column(String, default=ResultStatus.OK.value)
    __table_args__ = (
        CheckConstraint(_in("condition", Condition)),
        CheckConstraint(_in("component", Component)),
        CheckConstraint(_in("result_status", ResultStatus)),
        CheckConstraint("ended_at >= started_at"),
        CheckConstraint("analyst_active_seconds >= 0"),
    )


class AuditEvent(Base):
    """Append-only, hash-chained (blueprint §17.4.4). See app/db/audit.py."""

    __tablename__ = "audit_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    actor: Mapped[str] = mapped_column(String)
    action: Mapped[str] = mapped_column(String)
    entity_type: Mapped[str] = mapped_column(String)
    entity_id: Mapped[str] = mapped_column(String)
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    prev_hash: Mapped[str] = mapped_column(String(64))
    event_hash: Mapped[str] = mapped_column(String(64), unique=True)


class ExperimentRun(Base):
    __tablename__ = "experiment_runs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    condition: Mapped[str] = mapped_column(String)
    intel_id: Mapped[str] = mapped_column(ForeignKey("intelligence_items.intel_id"))
    run_number: Mapped[int] = mapped_column(Integer)
    order_set: Mapped[str] = mapped_column(String)  # X = manual-first, Y = agentic-first
    seed: Mapped[int | None] = mapped_column(Integer)
    model_id: Mapped[str | None] = mapped_column(String)
    prompt_set_sha256: Mapped[str | None] = mapped_column(String(64))
    output_ref: Mapped[str | None] = mapped_column(String)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    __table_args__ = (
        UniqueConstraint("condition", "intel_id", "run_number"),
        CheckConstraint(_in("condition", Condition)),
        CheckConstraint(_in("order_set", ["X", "Y"])),
        CheckConstraint("run_number >= 1"),
    )


TABLE_NAMES = tuple(sorted(Base.metadata.tables))
