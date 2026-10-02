"""Shared types and conventions (blueprint §16.1).

* Every confidence, reliability, and score value is on a 0-100 scale. No 0-1 probabilities.
* Timestamps are timezone-aware (UTC).
* The model's own stated confidence is stored for analysis but never feeds a decision.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, StringConstraints

Score100 = Annotated[int, Field(ge=0, le=100)]
Score100F = Annotated[float, Field(ge=0.0, le=100.0)]
Sha256 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
AttackId = Annotated[str, StringConstraints(pattern=r"^T\d{4}(\.\d{3})?$")]
UtcDatetime = AwareDatetime

GENESIS_HASH = "0" * 64


class Strict(BaseModel):
    """Base model: unknown fields are errors, so schema drift fails loudly."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class SourceType(StrEnum):
    FEED = "feed"
    ADVISORY = "advisory"
    REPORT = "report"
    UPLOAD = "upload"


class Tlp(StrEnum):
    CLEAR = "CLEAR"
    GREEN = "GREEN"
    AMBER = "AMBER"
    AMBER_STRICT = "AMBER+STRICT"
    RED = "RED"


class ProcessingStatus(StrEnum):
    INGESTED = "ingested"
    SANITISED = "sanitised"
    NORMALIZED = "normalized"
    ENRICHED = "enriched"
    PRIORITISED = "prioritised"
    ASSESSED = "assessed"
    REJECTED = "rejected"
    FAILED = "failed"


class Band(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RuleKind(StrEnum):
    SIGMA = "sigma"
    IOC_LIST = "ioc_list"


class RuleState(StrEnum):
    """Approval state machine (blueprint §17.4.3)."""

    DRAFT = "draft"
    VALIDATED = "validated"
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    DEPLOYED = "deployed"
    MONITORED = "monitored"
    REVISED = "revised"
    REJECTED = "rejected"
    BLOCKED = "blocked"
    RETIRED = "retired"


# Allowed transitions. Anything not listed is refused.
RULE_TRANSITIONS: dict[RuleState, frozenset[RuleState]] = {
    RuleState.DRAFT: frozenset({RuleState.VALIDATED, RuleState.REJECTED, RuleState.BLOCKED}),
    RuleState.VALIDATED: frozenset({RuleState.PENDING_APPROVAL}),
    RuleState.PENDING_APPROVAL: frozenset({RuleState.APPROVED, RuleState.REJECTED}),
    RuleState.APPROVED: frozenset({RuleState.DEPLOYED, RuleState.REVISED}),
    RuleState.DEPLOYED: frozenset({RuleState.MONITORED, RuleState.REVISED, RuleState.RETIRED}),
    RuleState.MONITORED: frozenset({RuleState.REVISED, RuleState.RETIRED}),
    RuleState.REVISED: frozenset({RuleState.DRAFT}),
    RuleState.REJECTED: frozenset(),
    RuleState.BLOCKED: frozenset(),
    RuleState.RETIRED: frozenset(),
}


def can_transition(src: RuleState, dst: RuleState) -> bool:
    return dst in RULE_TRANSITIONS[src]
