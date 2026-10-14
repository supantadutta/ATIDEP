from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select

from app.db import models as m
from app.db.audit import verify_audit_chain
from app.db.session import init_db, make_engine, session_scope
from app.services import timers
from app.services.costs import summary
from app.services.timers import TimerError, compute_totals

T0 = datetime(2026, 10, 2, 9, 0, tzinfo=UTC)


def at(seconds):
    return T0 + timedelta(seconds=seconds)


@pytest.fixture()
def engine():
    e = make_engine("sqlite:///:memory:")
    init_db(e)
    return e


def run_timer(s, beats, *, stop_at, pauses=(), resumes=()):
    sid = timers.start(s, analyst="alice", intel_id=None, condition="A", activity="reading",
                       now=at(0))
    events = sorted([(b, "beat") for b in beats] + [(p, "pause") for p in pauses]
                    + [(r, "resume") for r in resumes])
    for t, kind in events:
        {"beat": timers.heartbeat, "pause": timers.pause, "resume": timers.resume}[kind](
            s, sid, at(t))
    return sid, timers.stop(s, sid, at(stop_at))


def test_continuous_work_counts_in_full(engine):
    with session_scope(engine) as s:
        _, rec = run_timer(s, [60, 120, 180, 240], stop_at=300)
        assert rec.analyst_active_seconds == 300 and rec.component == "analyst"
        assert (rec.ended_at - rec.started_at).total_seconds() == 300


def test_a_long_silence_counts_for_at_most_the_idle_limit(engine):
    with session_scope(engine) as s:
        _, rec = run_timer(s, [60, 660], stop_at=720)       # nothing between 60 s and 660 s
        assert rec.analyst_active_seconds == 60 + 120 + 60   # 0-60, then capped at 120, then 60
        assert (rec.ended_at - rec.started_at).total_seconds() == 720    # wall clock is separate


def test_gaps_cut_short_by_the_idle_limit_are_counted_and_stored(engine):
    with session_scope(engine) as s:
        _, rec = run_timer(s, [60, 600, 660], stop_at=1200)   # a 540 s and a 540 s gap, both cut
        assert rec.idle_capped_gaps == 2
        assert rec.idle_capped_seconds == (540 - 120) + (540 - 120)
        assert rec.analyst_active_seconds == 60 + 120 + 60 + 120
        stop = s.scalars(select(m.AuditEvent).where(m.AuditEvent.action == "timer.stop")).one()
        assert stop.details["idle_capped_gaps"] == 2


def test_regular_heartbeats_keep_a_long_block_whole(engine):
    """The failure the review found: with no heartbeat, 20 uninterrupted minutes counted 2."""
    with session_scope(engine) as s:
        beats = list(range(30, 1200, 30))
        _, rec = run_timer(s, beats, stop_at=1200)
        assert rec.analyst_active_seconds == 1200 and rec.idle_capped_gaps == 0
    with session_scope(engine) as s:
        _, rec = run_timer(s, [], stop_at=1200)
        assert rec.analyst_active_seconds == 120 and rec.idle_capped_gaps == 1   # the old result


def test_a_pause_is_excluded_until_the_resume(engine):
    with session_scope(engine) as s:
        _, rec = run_timer(s, [60], pauses=[100], resumes=[1000], stop_at=1060)
        # 0-60 work, 60-100 work (40), pause 100-1000 excluded, 1000-1060 work (60)
        assert rec.analyst_active_seconds == 60 + 40 + 60


def test_totals_report_the_state():
    class E:
        def __init__(self, kind, t):
            self.kind, self.ts = kind, at(t)
    assert compute_totals([]).state == "stopped"
    assert compute_totals([E("start", 0), E("heartbeat", 30)]).state == "running"
    assert compute_totals([E("start", 0), E("pause", 30)]).state == "paused"
    assert compute_totals([E("start", 0), E("stop", 30)]).active_seconds == 30


def test_the_rules_of_the_protocol(engine):
    with session_scope(engine) as s:
        sid = timers.start(s, analyst="alice", intel_id=None, condition="B", activity="review_approval",
                           now=at(0))
        assert timers.running_session(s, "alice") == sid
        with pytest.raises(TimerError, match="already has a timer"):
            timers.start(s, analyst="alice", intel_id=None, condition="A", activity="reading")
        timers.start(s, analyst="bob", intel_id=None, condition="A", activity="reading", now=at(0))
        timers.pause(s, sid, at(10))
        with pytest.raises(TimerError, match="paused"):
            timers.heartbeat(s, sid, at(20))
        with pytest.raises(TimerError, match="already paused"):
            timers.pause(s, sid, at(20))
        timers.resume(s, sid, at(30))
        with pytest.raises(TimerError, match="not paused"):
            timers.resume(s, sid, at(31))
        timers.stop(s, sid, at(40))
        with pytest.raises(TimerError, match="already stopped"):
            timers.stop(s, sid, at(50))
        assert timers.running_session(s, "alice") is None
        with pytest.raises(TimerError, match="unknown timer"):
            timers.heartbeat(s, "nope")


def test_how_a_session_ended_is_recorded_and_validated(engine):
    with session_scope(engine) as s:
        sid = timers.start(s, analyst="alice", intel_id=None, condition="A", activity="reading",
                           now=at(0))
        with pytest.raises(TimerError, match="disposition"):
            timers.stop(s, sid, at(10), "maybe")
        assert timers.stop(s, sid, at(10), "accepted").disposition == "accepted"
        sid2 = timers.start(s, analyst="alice", intel_id=None, condition="A", activity="reading",
                            now=at(20))
        assert timers.stop(s, sid2, at(30)).disposition is None


def test_platform_upkeep_can_be_timed_without_an_item_under_condition_b(engine):
    with session_scope(engine) as s:
        sid = timers.start(s, analyst="alice", intel_id=None, condition="B",
                           activity="operations", now=at(0))
        rec = timers.stop(s, sid, at(90))
        assert rec.activity == "operations" and rec.intel_id is None
        assert rec.analyst_active_seconds == 90


@pytest.mark.parametrize("kw,msg", [
    (dict(condition="C", activity="reading", analyst="a"), "only in conditions"),
    (dict(condition="B-V", activity="reading", analyst="a"), "only in conditions"),
    (dict(condition="A", activity="napping", analyst="a"), "activity"),
    (dict(condition="A", activity="reading", analyst=" "), "analyst name"),
    (dict(condition="A", activity="reading", analyst="a", intel_id="TI-2026-0042"), "unknown item"),
])
def test_invalid_timers_are_refused(engine, kw, msg):
    with session_scope(engine) as s, pytest.raises(TimerError, match=msg):
        timers.start(s, **{"intel_id": None, **kw})


def test_every_start_pause_resume_and_stop_is_logged_and_the_chain_holds(engine):
    with session_scope(engine) as s:
        run_timer(s, [60], pauses=[100], resumes=[200], stop_at=260)
        actions = [e.action for e in s.scalars(select(m.AuditEvent))]
        assert actions == ["timer.start", "timer.pause", "timer.resume", "timer.stop"]
        kinds = [e.kind for e in s.scalars(select(m.TimerEvent).order_by(m.TimerEvent.id))]
        assert kinds == ["start", "heartbeat", "pause", "resume", "stop"]
        assert verify_audit_chain(s).ok


# ---- measured quantities ------------------------------------------------------------------------------
def model_run(**kw):
    base = dict(run_id="r", agent="extraction", provider="ollama", model="q", prompt_version="p",
                prompt_sha256="a" * 64, schema_valid=True, retry_count=0, usage_source="provider")
    return m.ModelRun(**{**base, **kw})


def test_the_summary_reports_quantities_and_prices_nothing(engine):
    with session_scope(engine) as s:
        run_timer(s, [60, 120], stop_at=180)                 # 3 active minutes in condition A
        s.add(m.Source(name="V", source_type="report", reliability_rating="B"))
        s.flush()
        s.add(model_run(input_tokens=1000, output_tokens=200, latency_ms=900))
        s.add(model_run(input_tokens=500, output_tokens=50, latency_ms=400, schema_valid=False,
                        retry_count=1))
        s.add(model_run(agent="rule", provider="cloud-openai", model="big",
                        input_tokens=2_000_000, output_tokens=1_000_000, latency_ms=5000))
        s.add(model_run(input_tokens=700, output_tokens=70, latency_ms=800, replayed=True,
                        usage_source="estimated"))
        s.flush()
    with session_scope(engine) as s:
        out = summary(s)
    assert out["analyst_active_minutes"] == 3.0
    ext = out["agents"]["extraction"]
    assert ext["calls"] == 3 and ext["input_tokens"] == 2200 and ext["schema_invalid"] == 1
    assert ext["replayed_calls"] == 1 and ext["latency_ms"] == 1300      # a replay waited for nothing
    assert out["tokens"] == {"input": 2_002_200, "output": 1_000_320}
    assert out["by_locality"]["cloud"]["calls"] == 1 and out["by_locality"]["local"]["calls"] == 3
    assert out["usage_sources"] == {"estimated": 1, "provider": 3}
    assert out["analyst"]["A"]["active_seconds"] == 180
    assert out["items"] == 0 and out["approved_rules"] == 0 and out["deployed_rules"] == 0
    # the application holds no rate and no price, so no money appears anywhere
    flat = repr(out).lower()
    assert "currency" not in flat and "labour" not in flat and "per_item" not in flat


def test_platform_upkeep_is_reported_apart_from_per_item_analyst_time(engine):
    with session_scope(engine) as s:
        run_timer(s, [60], stop_at=100)                      # one item session in condition A
        sid = timers.start(s, analyst="bob", intel_id=None, condition="B", activity="operations",
                           now=at(0))
        timers.stop(s, sid, at(90))
        out = summary(s)
    assert out["analyst_active_minutes"] == pytest.approx(100 / 60, abs=0.01)
    assert out["platform_upkeep"]["active_seconds"] == 90 and "B" not in out["analyst"]


def test_approved_rules_are_distinct_current_rules_not_approval_rows(engine):
    from tests.unit.test_db import seed
    with session_scope(engine) as s:
        seed(s)
        rule = s.get(m.Rule, "RULE-1")
        v1 = s.query(m.RuleVersion).filter_by(rule_id="RULE-1").one()
        for _ in range(2):               # re-approved after an edit: two rows, one rule
            s.add(m.Approval(rule_version_id=v1.id, reviewer="r", author="a", decision="approved",
                             content_sha256="b" * 64, validation_report_sha256="c" * 64))
        rule.state = "approved"
        s.flush()
        assert summary(s)["approved_rules"] == 1
        s.add(m.Deployment(rule_version_id=v1.id, approval_id=1, mode="lab", status="ok",
                           package_sha256="d" * 64))
        s.add(m.Deployment(rule_version_id=v1.id, approval_id=1, mode="dry_run", status="ok",
                           package_sha256="d" * 64))
        s.flush()
        assert summary(s)["deployed_rules"] == 1
