"""Evidence-linked claims (blueprint §16.2, §17.2.2).

Every extracted statement carries a verbatim quote. A claim whose quote did not verify
against the sanitised source is kept (so it can be counted as an unsupported extraction)
but is never usable for scoring or rule generation.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Self

from pydantic import Field, model_validator

from schemas.common import AttackId, Score100, Sha256, Strict, UtcDatetime


class ClaimKind(StrEnum):
    INDICATOR = "indicator"
    BEHAVIOR = "behavior"
    ENTITY = "entity"


class IndicatorType(StrEnum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"


class EntityType(StrEnum):
    TOOL = "tool"
    MALWARE = "malware"
    PRODUCT = "product"
    VULNERABILITY = "vulnerability"
    SECTOR = "sector"


class IndicatorContext(StrEnum):
    MALICIOUS = "malicious"
    REFERENCE_ONLY = "reference_only"  # e.g. benign-allowlisted: never enters a detection list
    UNKNOWN = "unknown"


class Evidence(Strict):
    evidence_id: str = Field(min_length=1)
    quote: str = Field(min_length=1)
    char_start: int = Field(ge=0)
    char_end: int = Field(ge=0)
    source_sha256: Sha256
    verified: bool = False

    @model_validator(mode="after")
    def _span_is_ordered(self) -> Self:
        if self.char_end <= self.char_start:
            raise ValueError("char_end must be greater than char_start")
        return self


class Claim(Strict):
    claim_id: str = Field(min_length=1)
    kind: ClaimKind
    evidence: Evidence

    # indicator / entity
    type: IndicatorType | EntityType | None = None
    value: str | None = None
    refanged_from: str | None = None
    valid: bool = True
    context: IndicatorContext = IndicatorContext.UNKNOWN
    expires_at: UtcDatetime | None = None

    # behaviour
    description: str | None = None
    attack_id: AttackId | None = None

    # recorded for analysis only; never an input to a score or a gate
    llm_stated_confidence: Score100 | None = None

    @model_validator(mode="after")
    def _fields_match_kind(self) -> Self:
        if self.kind is ClaimKind.INDICATOR:
            if not isinstance(self.type, IndicatorType) or not self.value:
                raise ValueError("an indicator claim needs an indicator type and a value")
        elif self.kind is ClaimKind.ENTITY:
            if not isinstance(self.type, EntityType) or not self.value:
                raise ValueError("an entity claim needs an entity type and a value")
        elif not self.description:
            raise ValueError("a behavior claim needs a description")
        if self.kind is not ClaimKind.BEHAVIOR and self.attack_id is not None:
            raise ValueError("attack_id is only valid on behavior claims")
        if self.kind is not ClaimKind.INDICATOR and self.expires_at is not None:
            raise ValueError("expires_at is only valid on indicator claims")
        return self

    @property
    def usable(self) -> bool:
        """Usable for scoring and rule generation: quote verified and, for indicators, valid
        and not reference-only."""
        if not self.evidence.verified:
            return False
        if self.kind is ClaimKind.INDICATOR:
            return self.valid and self.context is not IndicatorContext.REFERENCE_ONLY
        return True
