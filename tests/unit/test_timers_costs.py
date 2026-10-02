from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select

from app.config import load_config
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


# ---- cost summary -----------------------------------------------------------------------------------
def test_the_summary_reports_tokens_minutes_and_cost_per_accepted_rule(engine):
    cfg = load_config()
    with session_scope(engine) as s:
        run_timer(s, [60, 120], stop_at=180)                 # 3 active minutes in condition A
        s.add(m.Source(name="V", source_type="report", reliability_rating="B"))
        s.flush()
        s.add(m.ModelRun(run_id="r", agent="extraction", provider="ollama", model="q",
                         prompt_version="p", prompt_sha256="a" * 64, input_tokens=1000,
                         output_tokens=200, latency_ms=900, schema_valid=True, retry_count=0))
        s.add(m.ModelRun(run_id="r", agent="extraction", provider="ollama", model="q",
                         prompt_version="p", prompt_sha256="a" * 64, input_tokens=500,
                         output_tokens=50, latency_ms=400, schema_valid=False, retry_count=1))
        s.add(m.ModelRun(run_id="r", agent="rule", provider="cloudco", model="big",
                         prompt_version="p", prompt_sha256="a" * 64, input_tokens=2_000_000,
                         output_tokens=1_000_000, latency_ms=5000, schema_valid=True,
                         retry_count=0))
        s.flush()
    cfg.cost_rates["cloud_ai"].update(input_cost_per_million_tokens=10,
                                      output_cost_per_million_tokens=30)
    with session_scope(engine) as s:
        out = summary(s, cfg)
    assert out["currency"] == "BDT" and out["analyst_active_minutes"] == 3.0
    ext = out["agents"]["extraction"]
    assert ext["calls"] == 2 and ext["input_tokens"] == 1500 and ext["schema_invalid"] == 1
    assert out["tokens"] == {"input": 2_001_500, "output": 1_000_250}
    assert out["cost"]["tokens"] == pytest.approx(2 * 10 + 1 * 30)       # only the cloud call
    assert out["cost"]["labour"] == pytest.approx(3 / 60 * 800)          # 3 minutes at 800/hour
    assert out["analyst"]["A"]["analyst_active_seconds"] == 180
    assert out["items"] == 0 and out["cost"]["per_item"] is None
    assert out["cost"]["per_accepted_rule"] is None
