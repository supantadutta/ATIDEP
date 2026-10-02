"""Detection-opportunity decision (blueprint §17.3.1)."""

from __future__ import annotations

from enum import StrEnum
from typing import Self

from pydantic import Field, model_validator

from schemas.common import AttackId, Score100, Strict


class Decision(StrEnum):
    IOC_BASED = "ioc_based"
    BEHAVIORAL = "behavioral"
    CORRELATION = "correlation"  # recorded, not generated in the MVP
    HUNTING_ONLY = "hunting_only"
    ADDITIONAL_TELEMETRY = "additional_telemetry_required"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"
    NOT_RELEVANT = "not_relevant"
    EXPIRED_OR_LOW_VALUE = "expired_or_low_value"


# A detection opportunity exists for these decisions.
DETECTABLE_DECISIONS = frozenset({Decision.IOC_BASED, Decision.BEHAVIORAL, Decision.CORRELATION})
# These decisions lead to rule or list generation in the MVP.
GENERATING_DECISIONS = frozenset({Decision.IOC_BASED, Decision.BEHAVIORAL})


class DetectionOpportunity(Strict):
    detectable: bool
    decision: Decision
    detection_concept: str | None = None
    required_log_source: str | None = None
    required_fields: list[str] = Field(default_factory=list)
    attack_techniques: list[AttackId] = Field(default_factory=list)
    false_positive_hypotheses: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    decision_reason: str = Field(min_length=1)
    # recorded for analysis only; never used by the override or any gate
    llm_stated_confidence: Score100 | None = None
    # set when the deterministic override changed the model's decision
    override_applied: bool = False
    override_reason: str | None = None

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        if self.detectable != (self.decision in DETECTABLE_DECISIONS):
            raise ValueError(
                f"detectable={self.detectable} is inconsistent with decision {self.decision.value}"
            )
        if self.detectable and not self.evidence_ids:
            raise ValueError("a detectable opportunity needs at least one evidence_id")
        if self.decision in GENERATING_DECISIONS and not self.required_log_source:
            raise ValueError("a generating decision needs required_log_source")
        if self.override_applied and not self.override_reason:
            raise ValueError("override_applied requires override_reason")
        return self

    @property
    def generates_rule(self) -> bool:
        return self.decision in GENERATING_DECISIONS
