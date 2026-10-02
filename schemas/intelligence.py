"""Intelligence record and priority (blueprint §16.2, §17.2.5)."""

from __future__ import annotations

from decimal import ROUND_HALF_UP, Decimal
from typing import Literal, Self

from pydantic import Field, model_validator

from schemas.claim import Claim
from schemas.common import (
    Band,
    ProcessingStatus,
    Score100,
    Score100F,
    Sha256,
    SourceType,
    Strict,
    Tlp,
    UtcDatetime,
)

# Admiralty mappings (config/scoring.yaml holds the same values; a test keeps them in sync).
RELIABILITY_SCORE: dict[str, int] = {"A": 100, "B": 80, "C": 60, "D": 40, "E": 20, "F": 50}
CREDIBILITY_SCORE: dict[int, int] = {1: 100, 2: 80, 3: 60, 4: 40, 5: 20, 6: 50}

# Half-open bands on the score rounded to one decimal:
# low [0,40), medium [40,60), high [60,80), critical [80,100]
BAND_LOWER_BOUNDS: tuple[tuple[Band, float], ...] = (
    (Band.CRITICAL, 80.0),
    (Band.HIGH, 60.0),
    (Band.MEDIUM, 40.0),
    (Band.LOW, 0.0),
)


def round_score(score: float) -> float:
    """Round to one decimal, half up, on the decimal representation (79.95 -> 80.0)."""
    return float(Decimal(str(score)).quantize(Decimal("0.1"), rounding=ROUND_HALF_UP))


def band_for_score(score: float) -> Band:
    rounded = round_score(score)
    if not 0.0 <= rounded <= 100.0:
        raise ValueError(f"score out of range: {score}")
    for band, lower in BAND_LOWER_BOUNDS:
        if rounded >= lower:
            return band
    raise AssertionError("unreachable")


class Source(Strict):
    name: str = Field(min_length=1)
    url: str | None = None
    source_type: SourceType
    retrieved_at: UtcDatetime
    published_at: UtcDatetime | None = None
    reliability_rating: Literal["A", "B", "C", "D", "E", "F"]
    reliability_score: Score100

    @model_validator(mode="after")
    def _score_matches_rating(self) -> Self:
        if self.reliability_score != RELIABILITY_SCORE[self.reliability_rating]:
            raise ValueError("reliability_score does not match the Admiralty reliability_rating")
        return self


class Classification(Strict):
    tlp: Tlp = Tlp.CLEAR
    credibility_rating: Literal[1, 2, 3, 4, 5, 6] = 3
    confidence: Score100
    language: str = "en"


class Sanitisation(Strict):
    raw_sha256: Sha256
    sanitised_sha256: Sha256
    stripped: list[str] = Field(default_factory=list)


class Priority(Strict):
    score: Score100F
    band: Band
    components: dict[str, float] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _band_matches_score(self) -> Self:
        expected = band_for_score(self.score)
        if self.band is not expected:
            raise ValueError(f"band {self.band.value} does not match score {self.score} "
                             f"(expected {expected.value})")
        return self


class Processing(Strict):
    status: ProcessingStatus = ProcessingStatus.INGESTED
    component_versions: dict[str, str] = Field(default_factory=dict)
    model: str | None = None
    prompt_sha256: Sha256 | None = None


class IntelligenceItem(Strict):
    intel_id: str = Field(pattern=r"^TI-\d{4}-\d{4}$")
    title: str = Field(min_length=1)
    source: Source
    classification: Classification
    sanitisation: Sanitisation
    claims: list[Claim] = Field(default_factory=list)
    target_sectors: list[str] = Field(default_factory=list)
    affected_products: list[str] = Field(default_factory=list)
    vulnerabilities: list[str] = Field(default_factory=list)
    priority: Priority | None = None
    processing: Processing = Field(default_factory=Processing)

    @model_validator(mode="after")
    def _claim_ids_unique(self) -> Self:
        ids = [c.claim_id for c in self.claims]
        if len(ids) != len(set(ids)):
            raise ValueError("claim_id values must be unique within an item")
        return self

    @property
    def evidence_support_pct(self) -> float:
        """Share of claims whose quotes verified (0-100). An item with no claims scores 0."""
        if not self.claims:
            return 0.0
        return 100.0 * sum(c.evidence.verified for c in self.claims) / len(self.claims)

    @property
    def unsupported_claims(self) -> list[Claim]:
        return [c for c in self.claims if not c.evidence.verified]
