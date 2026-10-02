from datetime import UTC, datetime

import pytest
from sqlalchemy import inspect
from sqlalchemy.exc import IntegrityError

from app.db import models as m
from app.db.session import init_db, make_engine, session_scope

NOW = datetime(2026, 10, 2, 10, 0, tzinfo=UTC)
H = "a" * 64


@pytest.fixture
def engine():
    e = make_engine("sqlite:///:memory:")
    init_db(e)
    return e


def seed(s):
    s.add(m.Source(name="feed", source_type="feed", reliability_rating="B"))
    s.flush()
    s.add(m.IntelligenceItem(intel_id="TI-2026-0001", source_id=1, title="t", retrieved_at=NOW,
                             raw_sha256=H, sanitised_sha256=H))
    s.flush()  # no relationship() is declared, so insert parents explicitly before children
    s.add(m.DetectionOpportunity(intel_id="TI-2026-0001", decision="behavioral",
                                 detectable=True, decision_reason="r"))
    s.flush()
    s.add(m.Rule(rule_id="RULE-1", opportunity_id=1, kind="sigma"))
    s.flush()
    s.add(m.RuleVersion(rule_id="RULE-1", version=1, origin="llm_initial", content="x",
                        content_sha256=H))
    s.flush()


def test_has_exactly_the_17_tables_of_the_blueprint(engine):
    assert set(inspect(engine).get_table_names()) == set(m.TABLE_NAMES)
    assert len(m.TABLE_NAMES) == 17


def test_foreign_keys_are_enforced(engine):
    with pytest.raises(IntegrityError), session_scope(engine) as s:
        s.add(m.EvidenceSegment(evidence_id="EV-1", intel_id="TI-MISSING", quote="q",
                                char_start=0, char_end=1, source_sha256=H))


def test_enum_checks_reject_bad_values(engine):
    with pytest.raises(IntegrityError), session_scope(engine) as s:
        seed(s)
        s.add(m.ValidationResultRow(rule_version_id=1, gate="G99", status="passed"))
    with pytest.raises(IntegrityError), session_scope(engine) as s:
        s.add(m.Source(name="x", source_type="feed", reliability_rating="Z"))


def test_quality_score_range_and_version_uniqueness(engine):
    with pytest.raises(IntegrityError), session_scope(engine) as s:
        seed(s)
        s.add(m.RuleVersion(rule_id="RULE-1", version=2, origin="llm_repair_1", content="y",
                            content_sha256=H, quality_score=101))
    with pytest.raises(IntegrityError), session_scope(engine) as s:
        seed(s)
        s.add(m.RuleVersion(rule_id="RULE-1", version=1, origin="human_edit", content="y",
                            content_sha256=H))


def test_lab_deployment_requires_an_approval(engine):
    with pytest.raises(IntegrityError), session_scope(engine) as s:
        seed(s)
        s.add(m.Deployment(rule_version_id=1, approval_id=None, mode="lab", package_sha256=H,
                           status="ok"))
    with session_scope(engine) as s:  # a dry run needs none
        seed(s)
        s.add(m.Deployment(rule_version_id=1, mode="dry_run", package_sha256=H, status="ok"))


def test_duplicate_raw_content_is_refused(engine):
    with pytest.raises(IntegrityError), session_scope(engine) as s:
        seed(s)
        s.add(m.IntelligenceItem(intel_id="TI-2026-0002", source_id=1, title="dup",
                                 retrieved_at=NOW, raw_sha256=H, sanitised_sha256=H))


def test_experiment_run_uniqueness_and_order_set(engine):
    with pytest.raises(IntegrityError), session_scope(engine) as s:
        seed(s)
        for _ in range(2):
            s.add(m.ExperimentRun(condition="B", intel_id="TI-2026-0001", run_number=1,
                                  order_set="Y"))
            s.flush()
    with pytest.raises(IntegrityError), session_scope(engine) as s:
        seed(s)
        s.add(m.ExperimentRun(condition="B", intel_id="TI-2026-0001", run_number=1,
                              order_set="Z"))


def test_round_trip(engine):
    with session_scope(engine) as s:
        seed(s)
        s.add(m.EvidenceSegment(evidence_id="EV-1", intel_id="TI-2026-0001", quote="q",
                                char_start=0, char_end=4, source_sha256=H, verified=True))
        s.flush()
        s.add(m.Claim(claim_id="CL-1", intel_id="TI-2026-0001", evidence_id="EV-1",
                      kind="behavior", description="d", attack_id="T1059.001"))
    with session_scope(engine) as s:
        c = s.get(m.Claim, "CL-1")
        assert c.attack_id == "T1059.001" and c.valid is True
