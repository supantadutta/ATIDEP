"""Metadata model for generated Sigma drafts and the converter's refusal codes
(blueprint §17.3.2, §20.2). The detection logic itself is validated by pySigma and the
converter (gates G1 and G3); this model covers the metadata that gate G2 requires.
"""

from __future__ import annotations

from datetime import date
from enum import StrEnum
from typing import Any, Literal, Self
from uuid import UUID

from pydantic import Field, field_validator, model_validator

from schemas.common import Strict


class LogsourceCategory(StrEnum):
    """Log sources the v0 Wazuh-compatible subset can convert."""

    PROCESS_CREATION = "process_creation"
    NETWORK_CONNECTION = "network_connection"
    DNS_QUERY = "dns_query"


class UnsupportedReason(StrEnum):
    """Stable reason codes for constructs outside the subset. The converter refuses with
    one of these instead of approximating."""

    UNSUPPORTED_LOGSOURCE = "UNSUPPORTED_LOGSOURCE"
    UNSUPPORTED_MODIFIER = "UNSUPPORTED_MODIFIER"
    UNSUPPORTED_AGGREGATION = "UNSUPPORTED_AGGREGATION"
    UNSUPPORTED_CORRELATION = "UNSUPPORTED_CORRELATION"
    EXPANSION_TOO_LARGE = "EXPANSION_TOO_LARGE"


class Level(StrEnum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Logsource(Strict):
    category: str = Field(min_length=1)
    product: str | None = None
    service: str | None = None


class Assumption(Strict):
    """A condition not stated in the report, declared with its justification (G4).
    ``covers`` lists the detection values the assumption stands behind."""

    statement: str = Field(min_length=1)
    justification: str = Field(min_length=1)
    covers: list[str] = Field(default_factory=list)


class SigmaDraft(Strict):
    id: UUID
    title: str = Field(min_length=1)
    # Generated rules always start experimental (blueprint §17.3.2).
    status: Literal["experimental"] = "experimental"
    description: str = Field(min_length=1)
    author: str = Field(min_length=1)
    date: date
    references: list[str] = Field(min_length=1)
    tags: list[str] = Field(min_length=1)
    logsource: Logsource
    detection: dict[str, Any]
    falsepositives: list[str] = Field(min_length=1)
    level: Level
    assumptions: list[Assumption] = Field(default_factory=list)

    @field_validator("tags")
    @classmethod
    def _attack_tags(cls, tags: list[str]) -> list[str]:
        if not any(t.startswith("attack.") for t in tags):
            raise ValueError("at least one attack.* tag is required")
        return tags

    @model_validator(mode="after")
    def _has_condition(self) -> Self:
        if "condition" not in self.detection:
            raise ValueError("detection must contain a condition")
        return self
