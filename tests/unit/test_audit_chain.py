import pytest
from sqlalchemy import text

from app.db.audit import append_audit_event, verify_audit_chain
from app.db.session import init_db, make_engine, session_scope


@pytest.fixture
def engine():
    e = make_engine("sqlite:///:memory:")
    init_db(e)
    return e


def fill(engine, n=4):
    with session_scope(engine) as s:
        for i in range(n):
            append_audit_event(s, actor="tester", action="rule.validated", entity_type="rule",
                               entity_id=f"RULE-{i}", details={"gates": "G1-G11", "i": i})


def test_empty_and_valid_chains_verify(engine):
    with session_scope(engine) as s:
        assert verify_audit_chain(s).ok
    fill(engine)
    with session_scope(engine) as s:
        report = verify_audit_chain(s)
        assert report.ok and report.checked == 4


def test_altering_an_event_is_detected(engine):
    fill(engine)
    with engine.begin() as c:
        c.execute(text("UPDATE audit_events SET actor='mallory' WHERE id=2"))
    with session_scope(engine) as s:
        report = verify_audit_chain(s)
        assert not report.ok and report.first_bad_id == 2


def test_deleting_an_event_is_detected(engine):
    fill(engine)
    with engine.begin() as c:
        c.execute(text("DELETE FROM audit_events WHERE id=2"))
    with session_scope(engine) as s:
        report = verify_audit_chain(s)
        assert not report.ok and report.first_bad_id == 3
