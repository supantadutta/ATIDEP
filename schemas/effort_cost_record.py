"""Effort and cost instrumentation record (blueprint §22.2, §23).

The application measures; the paper analyses. ``analyst_active_seconds`` comes from the
analyst timer and is the primary efficiency endpoint (hypothesis H1).
"""

from __future__ import annotations

from enum import StrEnum
from typing import Self

from pydantic import Field, model_validator

from schemas.common import Strict, UtcDatetime


class Condition(StrEnum):
    """Experimental conditions (blueprint §27.1)."""

    MANUAL = "A"
    ATIDEP = "B"
    SINGLE_PROMPT = "C"
    ATIDEP_NO_VALIDATORS = "B-V"
    ATIDEP_NO_REPAIR = "B-R"


class Component(StrEnum):
    INGEST = "c1_ingest"
    PROCESSING = "c2_processing"
    DETECTION = "c3_detection"
    VALIDATION = "c4_validation"
    DEPLOY_FEEDBACK = "c5_deploy_feedback"
    ANALYST = "analyst"  # human time in any condition


class ResultStatus(StrEnum):
    OK = "ok"
    FAILED = "failed"
    RETRIED = "retried"


class EffortCostRecord(Strict):
    run_id: str = Field(min_length=1)
    intel_id: str | None = Field(default=None, pattern=r"^TI-\d{4}-\d{4}$")
    condition: Condition
    component: Component
    activity: str | None = None
    started_at: UtcDatetime
    ended_at: UtcDatetime
    analyst_active_seconds: float = Field(default=0.0, ge=0.0)
    cpu_pct_avg: float | None = Field(default=None, ge=0.0, le=100.0)
    mem_mb_peak: float | None = Field(default=None, ge=0.0)
    api_calls: int = Field(default=0, ge=0)
    input_tokens: int = Field(default=0, ge=0)
    output_tokens: int = Field(default=0, ge=0)
    price_snapshot: dict[str, float] = Field(default_factory=dict)
    result_status: ResultStatus = ResultStatus.OK

    @model_validator(mode="after")
    def _times_and_active_time(self) -> Self:
        if self.ended_at < self.started_at:
            raise ValueError("ended_at is before started_at")
        wall = (self.ended_at - self.started_at).total_seconds()
        if self.analyst_active_seconds > wall + 1e-6:
            raise ValueError("analyst_active_seconds cannot exceed the wall-clock duration")
        return self

    @property
    def duration_seconds(self) -> float:
        return (self.ended_at - self.started_at).total_seconds()
