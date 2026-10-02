"""IOC bundle: the artefact for indicator detections (blueprint §16.3, §17.3.4).

Indicator detections become a Wazuh CDB list plus a rule template, not one Sigma rule per
indicator. The bundle is built only from verified, refanged, allowlist-filtered indicators.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Self

from pydantic import Field, model_validator

from schemas.claim import IndicatorType
from schemas.common import Strict, UtcDatetime


class ExclusionReason(StrEnum):
    BENIGN_ALLOWLIST = "benign_allowlist"
    RESERVED_RANGE = "reserved_range"
    EXPIRED = "expired"
    UNVERIFIED_EVIDENCE = "unverified_evidence"
    INVALID_FORMAT = "invalid_format"
    DUPLICATE = "duplicate"
    UNSUPPORTED_BY_TARGET = "unsupported_by_target"
    NO_THREAT_CONTEXT = "no_threat_context"


class IocEntry(Strict):
    type: IndicatorType
    value: str = Field(min_length=1)
    evidence_id: str = Field(min_length=1)
    expires_at: UtcDatetime


class ExcludedIoc(Strict):
    value: str = Field(min_length=1)
    reason: ExclusionReason


class IocBundle(Strict):
    bundle_id: str = Field(pattern=r"^IOC-\d{4}-\d{4}$")
    intel_id: str = Field(pattern=r"^TI-\d{4}-\d{4}$")
    entries: list[IocEntry] = Field(default_factory=list)
    excluded: list[ExcludedIoc] = Field(default_factory=list)

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        keys = [(e.type, e.value.lower()) for e in self.entries]
        if len(keys) != len(set(keys)):
            raise ValueError("duplicate indicator in bundle entries")
        included = {e.value.lower() for e in self.entries}
        clash = included & {x.value.lower() for x in self.excluded}
        if clash:
            raise ValueError(f"indicator both included and excluded: {sorted(clash)}")
        return self
