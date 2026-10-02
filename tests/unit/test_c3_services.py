import json
from datetime import UTC, datetime

import pytest
import yaml
from sqlalchemy import select

from app.config import load_config
from app.db import models as m
from app.db.audit import verify_audit_chain
from app.db.session import init_db, make_engine, session_scope
from app.services.claims import load_claims
from app.services.detection import (
    DetectionError,
    assess_item,
    create_ioc_rule,
    create_sigma_rule,
    rule_context_for,
)
from app.services.ingest import get_or_create_source, ingest
from app.services.process import process_item
from components.c1_ingest.collect import collect_bytes
from components.c1_ingest.evidence import EvidenceStore, sha256_hex
from components.c2_processing.attack import load_release
from components.c2_processing.indicators import load_benign_domains
from components.c3_detection.rule_agent import LoopCheck
from components.llm.client import ScriptedClient
from components.llm.prompts import compose_prompt, load_prompt
from schemas.common import ProcessingStatus, RuleState
from schemas.sigma_subset import Assumption
from schemas.validation_result import Defect, GateId

CFG = load_config()
ATTACK = load_release()
NOW = datetime(2026, 10, 2, 9, 0, tzinfo=UTC)
EXTRACT = load_prompt("extraction_v1")
OPP_PROMPT = load_prompt("opportunity_v1")
RULE_PROMPT = compose_prompt("rule_v1", ["rule_v1", "sigma_subset_v0"])
BENIGN = load_benign_domains()

REPORT = (
    "<html><head><title>Operation Example</title></head><body>"
    "<p>The actor ran powershell.exe -enc JABzAD0A to download a second stage from "
    "hxxps://stage[.]bad-host[.]net/payload.bin and then beaconed to 1.2.3.4 before calling "
    "back to 5.6.7.8.</p>"
    "<p>Dropper hash: 44d88612fea8a8f36de82e1278abb02f. Exploited CVE-2025-12345 in Microsoft "
    "Exchange.</p><p>The operators used Cobalt Strike for lateral movement against financial "
    "sector targets.</p></body></html>")
Q_PS = "ran powershell.exe -enc JABzAD0A to download a second stage"
EXTRACTION = json.dumps({"behaviors": [{
    "description": "PowerShell encoded command downloads a second stage", "attack_id": "T1059.001",
    "quote": Q_PS, "stated_confidence": 90}], "entities": []})


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
    return engine, store, iid


def opp_json(*items):
    return json.dumps({"opportunities": list(items)})


def behavioural(evidence_id, **kw):
    return {"decision": "behavioral", "detection_concept": "Encoded PowerShell",
            "required_log_source": "windows_process_creation",
            "required_fields": ["Image", "CommandLine"], "attack_techniques": ["T1059.001"],
            "false_positive_hypotheses": ["admin scripts"], "evidence_ids": [evidence_id],
            "decision_reason": "Visible in process events", "llm_stated_confidence": 90, **kw}


def behaviour_evidence(engine, iid):
    with session_scope(engine) as s:
        return next(c.evidence.evidence_id for c in load_claims(s, iid) if c.description)


IOC = {"decision": "ioc_based", "detection_concept": "Known infrastructure",
       "required_log_source": "windows_network_connection", "evidence_ids": [],
       "decision_reason": "Report lists infrastructure", "llm_stated_confidence": 70}


def assess(engine, iid, outputs):
    with session_scope(engine) as s:
        return assess_item(s, iid, cfg=CFG, attack=ATTACK, client=ScriptedClient(outputs),
                           prompt=OPP_PROMPT, now=NOW, seed=1)


# ---- claims round trip ---------------------------------------------------------------------
def test_claims_round_trip_through_the_database(world):
    engine, _, iid = world
    with session_scope(engine) as s:
        claims = load_claims(s, iid)
        assert len(claims) >= 6 and all(c.evidence.verified for c in claims)
        beh = next(c for c in claims if c.description)
        assert beh.attack_id == "T1059.001" and beh.usable
        assert {c.evidence.evidence_id for c in claims} >= {"EV-2026-0001-001"}


# ---- assessing -----------------------------------------------------------------------------
def test_assess_stores_override_checked_opportunities_and_updates_the_item(world):
    engine, _, iid = world
    ids = assess(engine, iid, [opp_json(behavioural(behaviour_evidence(engine, iid)), IOC)])
    assert len(ids) == 2
    with session_scope(engine) as s:
        rows = s.scalars(select(m.DetectionOpportunity).order_by(
            m.DetectionOpportunity.opportunity_id)).all()
        assert [r.decision for r in rows] == ["behavioral", "ioc_based"]
        ioc = rows[1]
        assert ioc.required_log_source in {"windows_network_connection", "windows_dns_query",
                                           "windows_process_creation"}
        assert ioc.evidence_ids and ioc.detectable
        assert s.get(m.IntelligenceItem, iid).status == ProcessingStatus.ASSESSED.value
        runs = s.scalars(select(m.ModelRun).where(m.ModelRun.agent == "opportunity")).all()
        assert len(runs) == 1 and runs[0].schema_valid
        assert verify_audit_chain(s).ok


def test_an_item_with_only_non_generating_decisions_is_rejected(world):
    engine, _, iid = world
    nr = {"decision": "not_relevant", "decision_reason": "Other sector entirely"}
    assess(engine, iid, [opp_json(nr)])
    with session_scope(engine) as s:
        assert s.get(m.IntelligenceItem, iid).status == ProcessingStatus.REJECTED.value


def test_no_opportunities_means_the_item_is_rejected(world):
    engine, _, iid = world
    assert assess(engine, iid, [opp_json()]) == []
    with session_scope(engine) as s:
        assert s.get(m.IntelligenceItem, iid).status == ProcessingStatus.REJECTED.value


def test_a_model_that_cannot_produce_valid_output_leaves_the_item_for_retry(world):
    engine, _, iid = world
    assert assess(engine, iid, ["nonsense"] * 3) == []
    with session_scope(engine) as s:
        item = s.get(m.IntelligenceItem, iid)
        assert item.status == ProcessingStatus.PRIORITISED.value
        assert "opportunity" in item.processing["last_error"]
        assert s.scalars(select(m.DetectionOpportunity)).first() is None
        assert [r.schema_valid for r in s.scalars(select(m.ModelRun).where(
            m.ModelRun.agent == "opportunity"))] == [False, False, False]
    ids = assess(engine, iid, [opp_json(behavioural(behaviour_evidence(engine, iid)))])                      # retry works
    assert len(ids) == 1
    with session_scope(engine) as s:
        assert "last_error" not in s.get(m.IntelligenceItem, iid).processing


def test_only_prioritised_items_can_be_assessed(world):
    engine, _, iid = world
    assess(engine, iid, [opp_json(behavioural(behaviour_evidence(engine, iid)))])
    with pytest.raises(DetectionError, match="only prioritised"):
        assess(engine, iid, [opp_json(behavioural(behaviour_evidence(engine, iid)))])
    with pytest.raises(DetectionError, match="unknown item"):
        assess(engine, "TI-2026-9999", [])


# ---- IOC rules -----------------------------------------------------------------------------
def test_ioc_rule_stores_the_bundle_as_a_draft_with_its_build_report(world):
    engine, _, iid = world
    ids = assess(engine, iid, [opp_json(IOC)])
    with session_scope(engine) as s:
        rid = create_ioc_rule(s, ids[0], cfg=CFG, benign_domains=BENIGN, now=NOW)
    with session_scope(engine) as s:
        rule = s.get(m.Rule, rid)
        assert rule.kind == "ioc_list" and rule.state == RuleState.DRAFT.value
        v = s.scalars(select(m.RuleVersion).where(m.RuleVersion.rule_id == rid)).one()
        assert v.origin == "ioc_builder" and v.content_sha256 == sha256_hex(v.content)
        doc = json.loads(v.content)
        values = {e["value"] for e in doc["bundle"]["entries"]}
        assert {"1.2.3.4", "5.6.7.8", "44d88612fea8a8f36de82e1278abb02f"} <= values
        assert doc["bundle"]["bundle_id"] == "IOC-2026-0001"
        assert doc["report"]["included"] == len(values)
        assert verify_audit_chain(s).ok


def test_ioc_rule_refuses_other_decisions_and_empty_bundles(world):
    engine, _, iid = world
    ids = assess(engine, iid, [opp_json(behavioural(behaviour_evidence(engine, iid)))])
    with session_scope(engine) as s, pytest.raises(DetectionError, match="not ioc_based"):
        create_ioc_rule(s, ids[0], cfg=CFG, benign_domains=BENIGN, now=NOW)
    with session_scope(engine) as s, pytest.raises(DetectionError, match="unknown opportunity"):
        create_ioc_rule(s, 999, cfg=CFG, benign_domains=BENIGN, now=NOW)


def test_ioc_rule_after_all_indicators_expired_is_refused(world):
    engine, _, iid = world
    ids = assess(engine, iid, [opp_json(IOC)])
    far = datetime(2030, 1, 1, tzinfo=UTC)
    with session_scope(engine) as s, pytest.raises(DetectionError, match="empty"):
        create_ioc_rule(s, ids[0], cfg=CFG, benign_domains=BENIGN, now=far)


# ---- Sigma rules ---------------------------------------------------------------------------
def sigma_draft(**kw):
    base = {
        "title": "Encoded PowerShell command line",
        "description": "Detects PowerShell started with an encoded command.",
        "tags": ["attack.execution", "attack.t1059.001"],
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection": {"selection": {"Image|endswith": "\\powershell.exe",
                                    "CommandLine|contains": "-enc"}, "condition": "selection"},
        "falsepositives": ["Administrative automation"], "level": "high",
        "assumptions": [{"statement": "Exclude SCCM", "justification": "Common admin tool",
                         "covers": ["ccmexec.exe"]}],
        "objective": "Find encoded PowerShell.", "threat_scenario": "Loader stage.",
        "expected_result": "Alert on encoded commands.", "triage_guidance": "Decode the payload.",
        "test_requirements": "One positive, one negative."}
    return json.dumps({**base, **kw})


def passing(sigma_yaml, assumptions, ctx):
    return LoopCheck()


def create(engine, opp_id, outputs, validator):
    with session_scope(engine) as s:
        return create_sigma_rule(s, opp_id, cfg=CFG, client=ScriptedClient(outputs),
                                 prompt=RULE_PROMPT, validate=validator, seed=2)


def test_rule_context_takes_quotes_and_fields_from_verified_evidence_and_the_catalog(world):
    engine, _, iid = world
    ids = assess(engine, iid, [opp_json(behavioural(behaviour_evidence(engine, iid)))])
    with session_scope(engine) as s:
        ctx = rule_context_for(s, ids[0], CFG)
        assert ctx.sigma_category == "process_creation" and ctx.references == (
            "https://vendor.example/r1",)
        assert ctx.allowed_fields[:2] == ["Image", "CommandLine"]
        assert ctx.quotes == {behaviour_evidence(engine, iid): Q_PS}


def test_a_passing_first_draft_is_stored_as_one_draft_version_with_use_case(world):
    engine, _, iid = world
    ids = assess(engine, iid, [opp_json(behavioural(behaviour_evidence(engine, iid)))])
    rid, res = create(engine, ids[0], [sigma_draft()], passing)
    assert res.status == "passed" and rid
    with session_scope(engine) as s:
        rule = s.get(m.Rule, rid)
        assert rule.kind == "sigma" and rule.state == "draft" and rule.current_version == 1
        v = s.scalars(select(m.RuleVersion).where(m.RuleVersion.rule_id == rid)).one()
        assert v.origin == "llm_initial" and v.content_sha256 == sha256_hex(v.content)
        doc = yaml.safe_load(v.content)
        assert doc["status"] == "experimental" and doc["references"] == [
            "https://vendor.example/r1"]
        assert v.assumptions[0]["covers"] == ["ccmexec.exe"]
        assert v.use_case["confidence"] == 80 and v.use_case["rule_owner"] == "researcher"
        assert v.use_case["review_date"] > "2026"
        runs = s.scalars(select(m.ModelRun).where(m.ModelRun.agent == "rule")).all()
        assert [r.repair_attempt for r in runs] == [0]
        assert verify_audit_chain(s).ok


def test_each_repair_attempt_is_its_own_version_and_model_runs_record_the_attempt(world):
    engine, _, iid = world
    ids = assess(engine, iid, [opp_json(behavioural(behaviour_evidence(engine, iid)))])
    bad = LoopCheck(defects=[Defect(gate=GateId.G5, code="G5_UNKNOWN_FIELD", path="x",
                                    message="unknown field")])
    checks = [bad, bad, LoopCheck()]

    def validator(y, a, c):
        return checks.pop(0)

    rid, res = create(engine, ids[0], [sigma_draft(), sigma_draft(level="medium"),
                                       sigma_draft(level="low")], validator)
    assert res.status == "passed" and res.repairs_used == 2
    with session_scope(engine) as s:
        versions = s.scalars(select(m.RuleVersion).where(m.RuleVersion.rule_id == rid)
                             .order_by(m.RuleVersion.version)).all()
        assert [v.origin for v in versions] == ["llm_initial", "llm_repair_1", "llm_repair_2"]
        assert [yaml.safe_load(v.content)["level"] for v in versions] == ["high", "medium", "low"]
        assert s.get(m.Rule, rid).current_version == 3
        assert [r.repair_attempt for r in s.scalars(select(m.ModelRun).where(
            m.ModelRun.agent == "rule").order_by(m.ModelRun.id))] == [0, 1, 2]
        events = [e.action for e in s.scalars(select(m.AuditEvent))]
        assert "rule.passed" in events


def test_a_blocked_rule_becomes_blocked_and_never_needs_a_repair(world):
    engine, _, iid = world
    ids = assess(engine, iid, [opp_json(behavioural(behaviour_evidence(engine, iid)))])

    def blocked(y, a, c):
        return LoopCheck(defects=[Defect(gate=GateId.G6, code="G6_UNAVAILABLE", path="logsource",
                                         message="telemetry not available")], blocked=True)

    rid, res = create(engine, ids[0], [sigma_draft()], blocked)
    assert res.status == "blocked"
    with session_scope(engine) as s:
        assert s.get(m.Rule, rid).state == RuleState.BLOCKED.value


def test_exhausted_repairs_leave_a_draft_for_a_human_to_edit(world):
    engine, _, iid = world
    ids = assess(engine, iid, [opp_json(behavioural(behaviour_evidence(engine, iid)))])
    bad = LoopCheck(defects=[Defect(gate=GateId.G3, code="G3_X", message="cannot convert")])
    rid, res = create(engine, ids[0], [sigma_draft()] * 3, lambda y, a, c: bad)
    assert res.status == "exhausted"
    with session_scope(engine) as s:
        assert s.get(m.Rule, rid).state == RuleState.DRAFT.value
        assert any(e.action == "rule.exhausted" for e in s.scalars(select(m.AuditEvent)))


def test_no_draft_creates_no_rule_but_the_calls_are_logged(world):
    engine, _, iid = world
    ids = assess(engine, iid, [opp_json(behavioural(behaviour_evidence(engine, iid)))])
    rid, res = create(engine, ids[0], ["nonsense"] * 3, passing)
    assert rid is None and res.status == "no_draft"
    with session_scope(engine) as s:
        assert s.scalars(select(m.Rule)).first() is None
        assert len(s.scalars(select(m.ModelRun).where(m.ModelRun.agent == "rule")).all()) == 3
        assert any(e.action == "rule.no_draft" for e in s.scalars(select(m.AuditEvent)))


def test_log_sources_outside_the_subset_cannot_be_turned_into_a_rule_context(world):
    engine, _, iid = world
    unavailable = behavioural(behaviour_evidence(engine, iid),
                              required_log_source="windows_powershell_script_block")
    ids = assess(engine, iid, [opp_json(unavailable)])
    with session_scope(engine) as s:
        # the override already turned it into 'additional telemetry required'
        assert s.get(m.DetectionOpportunity, ids[0]).decision == "additional_telemetry_required"
        with pytest.raises(DetectionError, match="cannot be converted"):
            rule_context_for(s, ids[0], CFG)


def test_the_validator_sees_the_assembled_rule_and_the_assumptions(world):
    engine, _, iid = world
    ids = assess(engine, iid, [opp_json(behavioural(behaviour_evidence(engine, iid)))])
    seen = {}

    def validator(y, a, c):
        seen.update(yaml=y, assumptions=a, ctx=c)
        return LoopCheck()

    create(engine, ids[0], [sigma_draft()], validator)
    assert yaml.safe_load(seen["yaml"])["title"].startswith("Encoded")
    assert isinstance(seen["assumptions"][0], Assumption)
    assert seen["ctx"].intel_id == iid
