from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from schemas.claim import Claim, ClaimKind, Evidence, IndicatorContext, IndicatorType
from schemas.common import Band, RuleState, can_transition
from schemas.detection_opportunity import Decision, DetectionOpportunity
from schemas.effort_cost_record import Component, Condition, EffortCostRecord
from schemas.intelligence import (
    Classification,
    IntelligenceItem,
    Priority,
    Sanitisation,
    Source,
    band_for_score,
    round_score,
)
from schemas.ioc_bundle import ExcludedIoc, ExclusionReason, IocBundle, IocEntry
from schemas.sigma_subset import SigmaDraft
from schemas.validation_result import (
    ALL_GATES,
    GateId,
    GateResult,
    GateStatus,
    Outcome,
    ValidationResult,
)

H = "a" * 64
NOW = datetime(2026, 10, 2, 10, 0, tzinfo=UTC)


def evidence(verified=True, eid="EV-001"):
    return Evidence(evidence_id=eid, quote="encoded powershell", char_start=10, char_end=30,
                    source_sha256=H, verified=verified)


# ---- priority bands: half-open intervals (blueprint §17.2.5) -----------------------------
@pytest.mark.parametrize("score,band", [
    (0, Band.LOW), (39.9, Band.LOW), (40.0, Band.MEDIUM), (59.9, Band.MEDIUM),
    (60.0, Band.HIGH), (79.9, Band.HIGH), (79.94, Band.HIGH), (79.95, Band.CRITICAL),
    (80.0, Band.CRITICAL), (100, Band.CRITICAL),
])
def test_band_boundaries(score, band):
    assert band_for_score(score) is band


def test_v2_example_score_79_75_has_a_band():
    # v2 left 79.75 in a gap between "60-79" and "80-100".
    assert round_score(79.75) == 79.8
    assert band_for_score(79.75) is Band.HIGH


def test_band_out_of_range():
    with pytest.raises(ValueError):
        band_for_score(100.1)
    with pytest.raises(ValueError):
        band_for_score(-0.1)


def test_priority_band_must_match_score():
    Priority(score=79.8, band=Band.HIGH)
    with pytest.raises(ValidationError):
        Priority(score=79.8, band=Band.CRITICAL)


# ---- source / intelligence --------------------------------------------------------------
def source(**kw):
    base = dict(name="s", source_type="feed", retrieved_at=NOW, reliability_rating="B",
                reliability_score=80)
    return Source(**{**base, **kw})


def test_reliability_score_must_match_rating():
    source()
    with pytest.raises(ValidationError):
        source(reliability_score=70)


def test_confidence_is_0_to_100_integer_scale():
    Classification(confidence=75)
    for bad in (-1, 101):
        with pytest.raises(ValidationError):
            Classification(confidence=bad)


def test_naive_datetimes_rejected():
    with pytest.raises(ValidationError):
        source(retrieved_at=datetime(2026, 10, 2, 10, 0))


def behavior(cid="CL-1", verified=True, **kw):
    base = dict(claim_id=cid, kind=ClaimKind.BEHAVIOR, description="Encoded PowerShell",
                attack_id="T1059.001", evidence=evidence(verified, f"EV-{cid}"))
    return Claim(**{**base, **kw})


def indicator(cid="CL-2", verified=True, **kw):
    base = dict(claim_id=cid, kind=ClaimKind.INDICATOR, type=IndicatorType.DOMAIN,
                value="example.invalid", evidence=evidence(verified, f"EV-{cid}"))
    return Claim(**{**base, **kw})


def item(claims):
    return IntelligenceItem(
        intel_id="TI-2026-0001", title="t", source=source(),
        classification=Classification(confidence=75),
        sanitisation=Sanitisation(raw_sha256=H, sanitised_sha256=H), claims=claims)


def test_evidence_support_rate_and_unsupported_claims():
    it = item([behavior("CL-1"), indicator("CL-2", verified=False)])
    assert it.evidence_support_pct == 50.0
    assert [c.claim_id for c in it.unsupported_claims] == ["CL-2"]
    assert item([]).evidence_support_pct == 0.0


def test_duplicate_claim_ids_rejected():
    with pytest.raises(ValidationError):
        item([behavior("CL-1"), indicator("CL-1")])


def test_claim_shape_rules():
    with pytest.raises(ValidationError):
        Claim(claim_id="x", kind=ClaimKind.INDICATOR, evidence=evidence())  # no type/value
    with pytest.raises(ValidationError):
        Claim(claim_id="x", kind=ClaimKind.BEHAVIOR, evidence=evidence())  # no description
    with pytest.raises(ValidationError):
        behavior(attack_id="T10")  # malformed ATT&CK id
    with pytest.raises(ValidationError):
        indicator(attack_id="T1059.001")  # attack_id only on behaviours
    with pytest.raises(ValidationError):
        behavior(expires_at=NOW)  # expiry only on indicators


def test_evidence_span_must_be_ordered():
    with pytest.raises(ValidationError):
        Evidence(evidence_id="e", quote="q", char_start=5, char_end=5, source_sha256=H)


def test_unverified_or_reference_only_claims_are_not_usable():
    assert behavior().usable
    assert not behavior(verified=False).usable
    assert indicator().usable
    assert not indicator(context=IndicatorContext.REFERENCE_ONLY).usable
    assert not indicator(valid=False).usable
    assert not indicator(verified=False).usable


def test_unknown_fields_are_errors():
    with pytest.raises(ValidationError):
        Classification(confidence=1, surprise=True)


# ---- IOC bundle -------------------------------------------------------------------------
def test_ioc_bundle_rejects_duplicates_and_clashes():
    e = IocEntry(type=IndicatorType.DOMAIN, value="Bad.example", evidence_id="EV-1",
                 expires_at=NOW + timedelta(days=30))
    IocBundle(bundle_id="IOC-2026-0001", intel_id="TI-2026-0001", entries=[e])
    with pytest.raises(ValidationError):
        IocBundle(bundle_id="IOC-2026-0001", intel_id="TI-2026-0001", entries=[e, e])
    with pytest.raises(ValidationError):
        IocBundle(bundle_id="IOC-2026-0001", intel_id="TI-2026-0001", entries=[e],
                  excluded=[ExcludedIoc(value="bad.example",
                                        reason=ExclusionReason.BENIGN_ALLOWLIST)])


# ---- opportunity ------------------------------------------------------------------------
def opp(**kw):
    base = dict(detectable=True, decision=Decision.BEHAVIORAL, decision_reason="r",
                required_log_source="windows_process_creation", evidence_ids=["EV-1"])
    return DetectionOpportunity(**{**base, **kw})


def test_opportunity_consistency():
    assert opp().generates_rule
    with pytest.raises(ValidationError):
        opp(detectable=False)  # inconsistent with decision
    with pytest.raises(ValidationError):
        opp(evidence_ids=[])
    with pytest.raises(ValidationError):
        opp(required_log_source=None)
    with pytest.raises(ValidationError):
        opp(override_applied=True)  # needs a reason
    no = opp(detectable=False, decision=Decision.ADDITIONAL_TELEMETRY, evidence_ids=[],
             override_applied=True, override_reason="4104 unavailable")
    assert not no.generates_rule


# ---- Sigma draft metadata ---------------------------------------------------------------
def sigma(**kw):
    base = dict(id="8d2f0c6e-1b7a-4b52-9d52-0a8f2f5d6c11", title="Encoded PowerShell",
                description="d", author="atidep", date="2026-10-02", references=["https://x"],
                tags=["attack.execution", "attack.t1059.001"],
                logsource={"category": "process_creation", "product": "windows"},
                detection={"selection": {"CommandLine|contains": " -enc "},
                           "condition": "selection"},
                falsepositives=["admin automation"], level="medium")
    return SigmaDraft(**{**base, **kw})


def test_sigma_draft_rules():
    assert sigma().status == "experimental"
    with pytest.raises(ValidationError):
        sigma(status="stable")  # generated rules start experimental
    with pytest.raises(ValidationError):
        sigma(tags=["windows"])
    with pytest.raises(ValidationError):
        sigma(detection={"selection": {}})  # no condition


# ---- hard gates (blueprint §17.4.1) -----------------------------------------------------
def results(**status):
    out = []
    for g in ALL_GATES:
        s = status.get(g.value, GateStatus.PASSED)
        out.append(GateResult(gate=g, status=s, reason_codes=["X"] if s is GateStatus.FAILED
                              else []))
    return out


def test_all_gates_passed_is_validated():
    v = ValidationResult(results=results(), quality_score=88)
    assert v.outcome is Outcome.VALIDATED and v.may_enter_pending_approval


def test_any_failed_gate_means_revision_required():
    v = ValidationResult(results=results(G8=GateStatus.FAILED))
    assert v.outcome is Outcome.REVISION_REQUIRED
    assert not v.may_enter_pending_approval
    assert v.failed == [GateId.G8] and v.repairable_failures == []


def test_missing_telemetry_blocks_even_if_everything_else_passes():
    v = ValidationResult(results=results(G6=GateStatus.FAILED))
    assert v.outcome is Outcome.BLOCKED  # Scenario 5
    assert v.repairable_failures == []  # rewriting cannot fix unavailable telemetry


def test_repairable_failures():
    v = ValidationResult(results=results(G5=GateStatus.FAILED, G4=GateStatus.FAILED))
    assert set(v.repairable_failures) == {GateId.G4, GateId.G5}


def test_missing_or_unrun_gates_are_incomplete():
    assert ValidationResult(results=results()[:-1]).outcome is Outcome.INCOMPLETE
    assert ValidationResult(
        results=results(G10=GateStatus.NOT_RUN)).outcome is Outcome.INCOMPLETE


@pytest.mark.parametrize("bad", ["G1", "G6", "G8", "G11"])
def test_quality_score_can_never_rescue_a_failed_gate(bad):
    # v2 flaw: a rule scoring 0 on the functional test could still reach 90.
    with pytest.raises(ValidationError):
        ValidationResult(results=results(**{bad: GateStatus.FAILED}), quality_score=100)


def test_gate_results_validation():
    with pytest.raises(ValidationError):
        GateResult(gate=GateId.G1, status=GateStatus.FAILED)  # must say why
    with pytest.raises(ValidationError):
        ValidationResult(results=results() + results()[:1])  # duplicate gate


# ---- effort records ---------------------------------------------------------------------
def test_effort_record_rules():
    kw = dict(run_id="r1", condition=Condition.MANUAL, component=Component.ANALYST,
              started_at=NOW, ended_at=NOW + timedelta(minutes=10))
    assert EffortCostRecord(**kw, analyst_active_seconds=500).duration_seconds == 600
    with pytest.raises(ValidationError):
        EffortCostRecord(**kw, analyst_active_seconds=601)  # active time > wall-clock
    with pytest.raises(ValidationError):
        EffortCostRecord(**{**kw, "ended_at": NOW - timedelta(seconds=1)})


# ---- approval state machine -------------------------------------------------------------
def test_state_machine_cannot_skip_validation_or_approval():
    path = [RuleState.DRAFT, RuleState.VALIDATED, RuleState.PENDING_APPROVAL,
            RuleState.APPROVED, RuleState.DEPLOYED, RuleState.MONITORED]
    assert all(can_transition(a, b) for a, b in zip(path, path[1:], strict=False))
    assert not can_transition(RuleState.DRAFT, RuleState.APPROVED)
    assert not can_transition(RuleState.VALIDATED, RuleState.DEPLOYED)
    assert not can_transition(RuleState.PENDING_APPROVAL, RuleState.DEPLOYED)
    assert not can_transition(RuleState.REJECTED, RuleState.DRAFT)
    assert not can_transition(RuleState.BLOCKED, RuleState.VALIDATED)
