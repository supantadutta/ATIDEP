"""Hard-gate validation results (blueprint §17.4.1).

Safety properties are pass/fail. The quality score exists only to rank rules that have
already passed every gate; the model refuses to carry a score for any other outcome, so a
failed rule can never look "eligible" because of a high score.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Self

from pydantic import Field, model_validator

from schemas.common import Score100, Strict


class GateId(StrEnum):
    G1 = "G1"  # YAML, Sigma schema, pySigma parse
    G2 = "G2"  # required metadata
    G3 = "G3"  # Wazuh-compatible subset / converter accepts
    G4 = "G4"  # evidence traceability
    G5 = "G5"  # field validity (no invented fields)
    G6 = "G6"  # telemetry availability
    G7 = "G7"  # ATT&CK mapping
    G8 = "G8"  # positive test
    G9 = "G9"  # negative test
    G10 = "G10"  # benign look-alike test
    G11 = "G11"  # breadth guard


ALL_GATES: tuple[GateId, ...] = tuple(GateId)
# G1-G5 and G7 run inside the bounded repair loop; a failure can be repaired by rewriting.
REPAIRABLE_GATES = frozenset({GateId.G1, GateId.G2, GateId.G3, GateId.G4, GateId.G5, GateId.G7})
# G6 cannot be fixed by rewriting a rule: the telemetry is not available.
BLOCKING_GATES = frozenset({GateId.G6})


class GateStatus(StrEnum):
    PASSED = "passed"
    FAILED = "failed"
    NOT_RUN = "not_run"


class Outcome(StrEnum):
    VALIDATED = "validated"
    REVISION_REQUIRED = "revision_required"
    BLOCKED = "blocked"
    INCOMPLETE = "incomplete"


class Defect(Strict):
    """One structured defect handed back to the Rule Agent in the repair loop. It names the
    gate, a stable code, the location in the rule and a short message; it never carries
    report text."""

    gate: GateId
    code: str = Field(min_length=1)
    path: str = ""
    message: str = Field(min_length=1, max_length=400)


class GateResult(Strict):
    gate: GateId
    status: GateStatus
    reason_codes: list[str] = Field(default_factory=list)
    message: str = ""
    tier: int | None = Field(default=None, ge=0, le=3)  # test tier for G8-G11

    @model_validator(mode="after")
    def _failed_has_reason(self) -> Self:
        if self.status is GateStatus.FAILED and not (self.reason_codes or self.message):
            raise ValueError("a failed gate must say why")
        return self


class ValidationResult(Strict):
    results: list[GateResult]
    # Ranking only. Allowed only when every gate passed.
    quality_score: Score100 | None = None

    @model_validator(mode="after")
    def _unique_gates_and_score_rule(self) -> Self:
        gates = [r.gate for r in self.results]
        if len(gates) != len(set(gates)):
            raise ValueError("each gate may appear once per validation result")
        if self.quality_score is not None and self.outcome is not Outcome.VALIDATED:
            raise ValueError("a quality score is only allowed when every hard gate has passed")
        return self

    @property
    def failed(self) -> list[GateId]:
        return [r.gate for r in self.results if r.status is GateStatus.FAILED]

    @property
    def outcome(self) -> Outcome:
        by_gate = {r.gate: r.status for r in self.results}
        if by_gate.get(GateId.G6) is GateStatus.FAILED:
            return Outcome.BLOCKED
        if self.failed:
            return Outcome.REVISION_REQUIRED
        if any(by_gate.get(g) is not GateStatus.PASSED for g in ALL_GATES):
            return Outcome.INCOMPLETE
        return Outcome.VALIDATED

    @property
    def repairable_failures(self) -> list[GateId]:
        return [g for g in self.failed if g in REPAIRABLE_GATES]

    @property
    def may_enter_pending_approval(self) -> bool:
        return self.outcome is Outcome.VALIDATED
