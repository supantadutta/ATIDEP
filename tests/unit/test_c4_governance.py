import copy
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import select, update

from app.config import load_config
from app.db import models as m
from app.db.audit import verify_audit_chain
from app.db.session import init_db, make_engine, session_scope
from app.services.detection import assess_item, create_ioc_rule, create_sigma_rule
from app.services.governance import (
    ApprovalError,
    GovernanceError,
    decide,
    edit_rule,
    load_report,
    loop_validator,
    report_sha256,
    submit_for_approval,
    validate_rule,
    verify_approval,
)
from app.services.ingest import get_or_create_source, ingest
from app.services.process import process_item
from components.c1_ingest.collect import collect_bytes
from components.c1_ingest.evidence import EvidenceStore, sha256_hex
from components.c2_processing.attack import load_release
from components.c2_processing.indicators import load_benign_domains
from components.c4_validation.corpus import load_baseline, load_test_set
from components.llm.client import ScriptedClient
from components.llm.prompts import compose_prompt, load_prompt
from schemas.common import RuleState
from schemas.validation_result import GateId, GateStatus, Outcome

CFG = load_config()
ATTACK = load_release()
EVENTS = Path(__file__).resolve().parents[1] / "events"
TEST_SET = load_test_set(EVENTS)
BASELINE = load_baseline(EVENTS / "benign_baseline" / "baseline.jsonl")
NOW = datetime(2026, 10, 2, 9, 0, tzinfo=UTC)
EXTRACT = load_prompt("extraction_v1")
OPP_PROMPT = load_prompt("opportunity_v1")
RULE_PROMPT = compose_prompt("rule_v1", ["rule_v1", "sigma_subset_v0"])
BENIGN = load_benign_domains()
Q_PS = "ran powershell.exe -enc JABzAD0A to download a second stage"
REPORT = (
    "<html><body><p>The actor ran powershell.exe -enc JABzAD0A to download a second stage from "
    "hxxps://stage[.]bad-host[.]net/payload.bin and then beaconed to 1.2.3.4 before calling "
    "back to 5.6.7.8.</p><p>Dropper hash: 44d88612fea8a8f36de82e1278abb02f.</p></body></html>")
EXTRACTION = json.dumps({"behaviors": [{
    "description": "PowerShell encoded command downloads a second stage", "attack_id": "T1059.001",
    "quote": Q_PS, "stated_confidence": 90}], "entities": []})


def sigma(detection=None, assumptions=None, **kw):
    base = {
        "title": "Encoded PowerShell command line",
        "description": "Detects PowerShell started with an encoded command.",
        "tags": ["attack.execution", "attack.t1059.001"],
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection": detection or {
            "selection": {"Image|endswith": "\\powershell.exe", "CommandLine|contains": "-enc"},
            "flt": {"ParentImage|endswith": "\\ccmexec.exe"},
            "condition": "selection and not flt"},
        "falsepositives": ["Administrative automation", "Software deployment"], "level": "high",
        "assumptions": [{"statement": "Exclude SCCM client", "justification": "Known admin tool",
                         "covers": ["ccmexec.exe"]}] if assumptions is None else assumptions,
        "objective": "Find encoded PowerShell.", "threat_scenario": "Loader stage.",
        "expected_result": "Alert on encoded commands.", "triage_guidance": "Decode the payload.",
        "test_requirements": "One positive, one negative."}
    return json.dumps({**base, **kw})


@pytest.fixture()
def world(tmp_path):
    engine = make_engine("sqlite:///:memory:")
    init_db(engine)
    store = EvidenceStore(tmp_path / "evidence")
    doc = collect_bytes(REPORT.encode(), source_name="Vendor A", url="https://vendor.example/r1",
                        published_at=NOW, retrieved_at=NOW)
    with session_scope(engine) as s:
        src = get_or_create_source(s, name="Vendor A", reliability_rating="A",
                                   default_credibility=2)
        iid = ingest(s, store, doc, src).intel_id
        process_item(s, store, iid, cfg=CFG, attack=ATTACK, client=ScriptedClient([EXTRACTION]),
                     prompt=EXTRACT, allow_test_tlds=True)
        from app.services.claims import load_claims
        beh = next(c.evidence.evidence_id for c in load_claims(s, iid) if c.description)
        opps = json.dumps({"opportunities": [
            {"decision": "behavioral", "detection_concept": "Encoded PowerShell",
             "required_log_source": "windows_process_creation",
             "required_fields": ["Image", "CommandLine"], "attack_techniques": ["T1059.001"],
             "false_positive_hypotheses": ["admin scripts"], "evidence_ids": [beh],
             "decision_reason": "Visible in process events"},
            {"decision": "ioc_based", "detection_concept": "Known infrastructure",
             "decision_reason": "The report lists infrastructure"}]})
        ids = assess_item(s, iid, cfg=CFG, attack=ATTACK, client=ScriptedClient([opps]),
                          prompt=OPP_PROMPT, now=NOW)
    return engine, iid, ids


def make_sigma_rule(engine, opp_id, draft=None):
    with session_scope(engine) as s:
        rid, res = create_sigma_rule(
            s, opp_id, cfg=CFG, client=ScriptedClient([draft or sigma()] * 3),
            prompt=RULE_PROMPT, validate=loop_validator(s, CFG, ATTACK))
    return rid, res


def validate(engine, rid, **kw):
    with session_scope(engine) as s:
        return validate_rule(s, rid, cfg=CFG, attack=ATTACK, test_set=TEST_SET,
                             baseline=BASELINE, **kw)


def state(engine, rid):
    with session_scope(engine) as s:
        return s.get(m.Rule, rid).state


# ---- validation of a Sigma rule ------------------------------------------------------------
def test_a_sound_rule_passes_the_loop_then_all_eleven_gates_and_is_ranked(world):
    engine, _, ids = world
    rid, res = make_sigma_rule(engine, ids[0])
    assert res.status == "passed" and res.first_pass_valid
    out = validate(engine, rid)
    assert out.outcome is Outcome.VALIDATED and not out.failed
    assert [r.gate for r in out.results] == list(GateId)
    assert all(r.status is GateStatus.PASSED for r in out.results)
    assert 0 <= out.quality_score <= 100 and len(out.quality_breakdown) == 6
    assert {r.tier for r in out.results if r.gate in (GateId.G8, GateId.G9, GateId.G10,
                                                      GateId.G11)} == {1}
    assert state(engine, rid) == RuleState.VALIDATED.value
    with session_scope(engine) as s:
        v = s.scalars(select(m.RuleVersion).where(m.RuleVersion.rule_id == rid)).one()
        assert v.quality_score == out.quality_score
        rows = s.scalars(select(m.ValidationResultRow).where(
            m.ValidationResultRow.rule_version_id == v.id)).all()
        assert len(rows) == 11 and report_sha256(load_report(s, v.id)) == out.report_sha256
        assert verify_audit_chain(s).ok


def test_a_rule_that_fails_a_gate_gets_no_score_and_stays_a_draft(world):
    engine, _, ids = world
    no_filter = sigma(detection={"selection": {"Image|endswith": "\\powershell.exe",
                                               "CommandLine|contains": "-enc"},
                                 "condition": "selection"}, assumptions=[])
    rid, _ = make_sigma_rule(engine, ids[0], no_filter)
    out = validate(engine, rid)
    assert out.outcome is Outcome.REVISION_REQUIRED and out.quality_score is None
    assert out.failed == [GateId.G10]
    assert state(engine, rid) == RuleState.DRAFT.value
    with session_scope(engine) as s:
        v = s.scalars(select(m.RuleVersion).where(m.RuleVersion.rule_id == rid)).one()
        assert v.quality_score is None
        g10 = s.scalars(select(m.ValidationResultRow).where(
            m.ValidationResultRow.rule_version_id == v.id,
            m.ValidationResultRow.gate == "G10")).one()
        assert g10.status == "failed" and "G10_MATCHED_LOOKALIKE" in g10.reason_codes
        assert g10.tier == 1
    with pytest.raises(GovernanceError, match="pending"):
        with session_scope(engine) as s:
            decide(s, rid, reviewer="alice", decision="approved")


def test_static_failures_leave_the_event_gates_not_run(world):
    engine, _, ids = world
    invented = sigma(detection={"selection": {"ScriptBlockText|contains": "-enc"},
                                "condition": "selection"}, assumptions=[])
    rid, res = make_sigma_rule(engine, ids[0], invented)
    assert res.status == "exhausted" and res.repairs_used == 2 and rid      # the loop gave up
    out = validate(engine, rid)
    by = {r.gate: r.status for r in out.results}
    assert by[GateId.G8] is GateStatus.NOT_RUN and by[GateId.G11] is GateStatus.NOT_RUN
    assert out.outcome is Outcome.REVISION_REQUIRED and by[GateId.G5] is GateStatus.FAILED
    assert out.quality_score is None and state(engine, rid) == RuleState.DRAFT.value


def test_unavailable_telemetry_blocks_the_rule(world):
    engine, _, ids = world
    rid, _ = make_sigma_rule(engine, ids[0])
    cfg = copy.deepcopy(CFG)
    cfg.telemetry_catalog["logsources"]["windows_process_creation"]["available"] = False
    with session_scope(engine) as s:
        out = validate_rule(s, rid, cfg=cfg, attack=ATTACK, test_set=TEST_SET, baseline=BASELINE)
    assert out.outcome is Outcome.BLOCKED and out.quality_score is None
    assert state(engine, rid) == RuleState.BLOCKED.value
    with pytest.raises(GovernanceError, match="only drafts"):
        validate(engine, rid)


def test_event_gates_need_a_test_set_and_a_baseline(world):
    engine, _, ids = world
    rid, _ = make_sigma_rule(engine, ids[0])
    with pytest.raises(GovernanceError, match="test set"), session_scope(engine) as s:
        validate_rule(s, rid, cfg=CFG, attack=ATTACK)


def test_validating_twice_replaces_the_report_rows(world):
    engine, _, ids = world
    rid, _ = make_sigma_rule(engine, ids[0])
    first = validate(engine, rid)
    assert first.outcome is Outcome.VALIDATED
    with session_scope(engine) as s:                     # a validated rule is not re-validated
        with pytest.raises(GovernanceError, match="only drafts"):
            validate_rule(s, rid, cfg=CFG, attack=ATTACK, test_set=TEST_SET, baseline=BASELINE)


# ---- approval ---------------------------------------------------------------------------------
def validated_rule(world):
    engine, _, ids = world
    rid, _ = make_sigma_rule(engine, ids[0])
    assert validate(engine, rid).outcome is Outcome.VALIDATED
    return engine, rid


def test_only_a_person_can_approve_and_the_approval_binds_content_and_report(world):
    engine, rid = validated_rule(world)
    with session_scope(engine) as s:
        submit_for_approval(s, rid)
    for who in ["system", "agent:rule", "LLM", "atidep", "", "model:qwen"]:
        with pytest.raises(ApprovalError, match="human"), session_scope(engine) as s:
            decide(s, rid, reviewer=who, decision="approved")
    with session_scope(engine) as s:
        a = decide(s, rid, reviewer="Dr. Rahman", decision="approved", comment="Looks right",
                   author="researcher")
        v = s.scalars(select(m.RuleVersion).where(m.RuleVersion.rule_id == rid)).one()
        assert a.content_sha256 == v.content_sha256 == sha256_hex(v.content)
        assert a.validation_report_sha256 == report_sha256(load_report(s, v.id))
        assert (a.reviewer, a.author, a.decision) == ("Dr. Rahman", "researcher", "approved")
        assert s.get(m.Rule, rid).state == RuleState.APPROVED.value
        assert verify_approval(s, rid).id == a.id
        actions = [e.action for e in s.scalars(select(m.AuditEvent))]
        assert "approval.approved" in actions and verify_audit_chain(s).ok


def test_the_state_machine_blocks_shortcuts(world):
    engine, _, ids = world
    rid, _ = make_sigma_rule(engine, ids[0])
    with pytest.raises(GovernanceError, match="passed every gate"), session_scope(engine) as s:
        submit_for_approval(s, rid)                                   # never validated
    with pytest.raises(GovernanceError, match="pending approval"), session_scope(engine) as s:
        decide(s, rid, reviewer="alice", decision="approved")         # still a draft
    validate(engine, rid)
    with pytest.raises(GovernanceError, match="pending approval"), session_scope(engine) as s:
        decide(s, rid, reviewer="alice", decision="approved")         # validated, not submitted
    with session_scope(engine) as s:
        submit_for_approval(s, rid)
    with pytest.raises(GovernanceError, match="must be"), session_scope(engine) as s:
        decide(s, rid, reviewer="alice", decision="maybe")
    with session_scope(engine) as s:
        decide(s, rid, reviewer="alice", decision="approved")
    with pytest.raises(GovernanceError, match="pending approval"), session_scope(engine) as s:
        decide(s, rid, reviewer="bob", decision="approved")           # already decided
    with session_scope(engine) as s:
        assert verify_approval(s, rid).reviewer == "alice"
    with pytest.raises(GovernanceError, match="unknown rule"), session_scope(engine) as s:
        verify_approval(s, "RULE-9999-9999")


def test_a_rejection_is_final(world):
    engine, rid = validated_rule(world)
    with session_scope(engine) as s:
        submit_for_approval(s, rid)
        decide(s, rid, reviewer="alice", decision="rejected", comment="too noisy")
    assert state(engine, rid) == RuleState.REJECTED.value
    with pytest.raises(ApprovalError, match="not approved"), session_scope(engine) as s:
        verify_approval(s, rid)
    with pytest.raises(GovernanceError, match="cannot be edited"), session_scope(engine) as s:
        edit_rule(s, rid, "title: x", editor="alice")


def test_tampering_with_stored_content_is_caught_before_deployment(world):
    engine, rid = validated_rule(world)
    with session_scope(engine) as s:
        submit_for_approval(s, rid)
        decide(s, rid, reviewer="alice", decision="approved")
    with session_scope(engine) as s:                                  # a change behind our back
        s.execute(update(m.RuleVersion).where(m.RuleVersion.rule_id == rid).values(
            content="title: something else entirely\n"))
    with pytest.raises(ApprovalError, match="hash mismatch"), session_scope(engine) as s:
        verify_approval(s, rid)
    with session_scope(engine) as s:                  # even if the stored hash is also rewritten
        s.execute(update(m.RuleVersion).where(m.RuleVersion.rule_id == rid).values(
            content_sha256=sha256_hex("title: something else entirely\n")))
    with pytest.raises(ApprovalError, match="different content"), session_scope(engine) as s:
        verify_approval(s, rid)


def test_an_edit_after_approval_creates_a_version_and_voids_the_approval(world):
    engine, rid = validated_rule(world)
    with session_scope(engine) as s:
        submit_for_approval(s, rid)
        decide(s, rid, reviewer="alice", decision="approved")
        v1 = s.scalars(select(m.RuleVersion).where(m.RuleVersion.rule_id == rid)).one()
        edited = v1.content.replace("level: high", "level: critical")
        v2 = edit_rule(s, rid, edited, editor="alice")
        assert v2.version == 2 and v2.origin == "human_edit" and v2.content_sha256 != v1.content_sha256
        assert s.get(m.Rule, rid).state == RuleState.DRAFT.value
        assert any(e.action == "approval.voided" for e in s.scalars(select(m.AuditEvent)))
    with pytest.raises(ApprovalError, match="not approved"), session_scope(engine) as s:
        verify_approval(s, rid)
    with pytest.raises(GovernanceError, match="passed every gate"), session_scope(engine) as s:
        submit_for_approval(s, rid)                       # the new version has no report yet
    out = validate(engine, rid)                           # re-run the gates on version 2
    assert out.version == 2 and out.outcome is Outcome.VALIDATED


def test_an_edit_while_pending_returns_the_rule_to_draft(world):
    engine, rid = validated_rule(world)
    with session_scope(engine) as s:
        submit_for_approval(s, rid)
        v = s.scalars(select(m.RuleVersion).where(m.RuleVersion.rule_id == rid)).one()
        edit_rule(s, rid, v.content + "\n", editor="alice")
        assert s.get(m.Rule, rid).state == RuleState.DRAFT.value
    with pytest.raises(ApprovalError, match="human"), session_scope(engine) as s:
        edit_rule(s, rid, "x", editor="system")


# ---- IOC bundles ------------------------------------------------------------------------------
def make_ioc(engine, opp_id):
    with session_scope(engine) as s:
        return create_ioc_rule(s, opp_id, cfg=CFG, benign_domains=BENIGN, now=NOW)


def test_an_ioc_bundle_passes_all_gates_on_synthesised_events(world):
    engine, _, ids = world
    rid = make_ioc(engine, ids[1])
    out = validate(engine, rid)
    assert out.outcome is Outcome.VALIDATED, [(r.gate.value, r.message) for r in out.results
                                              if r.status is not GateStatus.PASSED]
    assert out.details["events"]["counts"]["positive"] >= 3
    assert out.details["events"]["baseline_matches"] == 0
    assert state(engine, rid) == RuleState.VALIDATED.value
    with session_scope(engine) as s:
        submit_for_approval(s, rid)
        decide(s, rid, reviewer="alice", decision="approved")
        assert verify_approval(s, rid)


def test_an_ioc_bundle_with_untraceable_evidence_fails_g4(world):
    engine, _, ids = world
    rid = make_ioc(engine, ids[1])
    with session_scope(engine) as s:
        v = s.scalars(select(m.RuleVersion).where(m.RuleVersion.rule_id == rid)).one()
        doc = json.loads(v.content)
        doc["bundle"]["entries"][0]["evidence_id"] = "EV-9999-9999-999"
        s.execute(update(m.RuleVersion).where(m.RuleVersion.id == v.id).values(
            content=json.dumps(doc), content_sha256=sha256_hex(json.dumps(doc))))
    out = validate(engine, rid)
    assert out.outcome is Outcome.REVISION_REQUIRED and GateId.G4 in out.failed
    by = {r.gate: r.status for r in out.results}
    assert by[GateId.G8] is GateStatus.NOT_RUN


def test_an_ioc_bundle_is_blocked_when_a_rendered_rules_telemetry_is_off(world):
    engine, _, ids = world
    rid = make_ioc(engine, ids[1])
    cfg = copy.deepcopy(CFG)
    cfg.telemetry_catalog["logsources"]["windows_network_connection"]["available"] = False
    with session_scope(engine) as s:
        out = validate_rule(s, rid, cfg=cfg, attack=ATTACK, test_set=None, baseline=BASELINE)
    assert out.outcome is Outcome.BLOCKED and state(engine, rid) == RuleState.BLOCKED.value


def test_a_corrupt_ioc_bundle_fails_g1(world):
    engine, _, ids = world
    rid = make_ioc(engine, ids[1])
    with session_scope(engine) as s:
        v = s.scalars(select(m.RuleVersion).where(m.RuleVersion.rule_id == rid)).one()
        s.execute(update(m.RuleVersion).where(m.RuleVersion.id == v.id).values(
            content=json.dumps({"bundle": {"bundle_id": "nope"}, "report": {}})))
    out = validate(engine, rid)
    assert GateId.G1 in out.failed and out.outcome is Outcome.REVISION_REQUIRED
