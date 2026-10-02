"""Analyst timer (blueprint §23): the primary efficiency endpoint of H1.

Rules for *active time*: the timer runs only while the analyst works on the item; every
heartbeat the interface sends while the analyst is active extends it; after
``IDLE_SECONDS`` without one it auto-pauses (so a gap counts for at most that long);
explicit pauses are excluded; every start, pause, resume and stop is logged. Wall-clock time is
the span from start to stop and is kept separately. The same protocol serves the manual
condition (A) and the review of ATIDEP output (B).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import models as m
from app.db.audit import append_audit_event
from schemas.effort_cost_record import Component, Condition, ResultStatus

IDLE_SECONDS = 120.0
ACTIVITIES = ("reading", "extraction", "opportunity_decision", "rule_writing", "validation",
              "testing", "review_approval", "editing", "packaging", "other")
TIMED_CONDITIONS = (Condition.MANUAL.value, Condition.ATIDEP.value)


class TimerError(Exception):
    pass


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


@dataclass(frozen=True)
class Totals:
    active_seconds: float
    wall_seconds: float
    state: str                 # running | paused | stopped


def _events(session: Session, session_id: str) -> list[m.TimerEvent]:
    return list(session.scalars(select(m.TimerEvent).where(
        m.TimerEvent.session_id == session_id).order_by(m.TimerEvent.id)))


def compute_totals(events: list[m.TimerEvent], idle: float = IDLE_SECONDS) -> Totals:
    """Active seconds are the sum, over consecutive events while the timer is running, of the
    gap capped at ``idle``. Time after a pause (until the resume) and after the stop is not
    counted."""
    if not events:
        return Totals(0.0, 0.0, "stopped")
    active, running = 0.0, False
    prev: datetime | None = None
    for e in events:
        ts = _aware(e.ts)
        if running and prev is not None:
            active += min((ts - prev).total_seconds(), idle)
        running = e.kind in ("start", "heartbeat", "resume")
        prev = ts
    last = events[-1]
    state = "stopped" if last.kind == "stop" else "paused" if last.kind == "pause" else "running"
    wall = (_aware(last.ts) - _aware(events[0].ts)).total_seconds()
    return Totals(active, wall, state)


def _log(session: Session, base: m.TimerEvent, kind: str, now: datetime) -> m.TimerEvent:
    ev = m.TimerEvent(session_id=base.session_id, analyst=base.analyst, intel_id=base.intel_id,
                      condition=base.condition, activity=base.activity, kind=kind, ts=now)
    session.add(ev)
    session.flush()
    return ev


def running_session(session: Session, analyst: str) -> str | None:
    """The analyst's open timer, if any (running or paused)."""
    ids = list(session.scalars(select(m.TimerEvent.session_id).where(
        m.TimerEvent.analyst == analyst, m.TimerEvent.kind == "start")))
    for sid in reversed(ids):
        if compute_totals(_events(session, sid)).state != "stopped":
            return sid
    return None


def start(session: Session, *, analyst: str, intel_id: str | None, condition: str,
          activity: str, now: datetime | None = None) -> str:
    if condition not in TIMED_CONDITIONS:
        raise TimerError(f"human time is measured only in conditions {TIMED_CONDITIONS}")
    if activity not in ACTIVITIES:
        raise TimerError(f"activity must be one of {ACTIVITIES}")
    if not analyst.strip():
        raise TimerError("an analyst name is required")
    if running_session(session, analyst):
        raise TimerError("this analyst already has a timer open; stop it first")
    if intel_id is not None and session.get(m.IntelligenceItem, intel_id) is None:
        raise TimerError(f"unknown item {intel_id}")
    now = _aware(now or datetime.now(UTC))
    sid = uuid.uuid4().hex[:12]
    base = m.TimerEvent(session_id=sid, analyst=analyst.strip(), intel_id=intel_id,
                        condition=condition, activity=activity, kind="start", ts=now)
    session.add(base)
    session.flush()
    append_audit_event(session, actor=analyst, action="timer.start", entity_type="timer",
                       entity_id=sid, details={"intel_id": intel_id, "condition": condition,
                                               "activity": activity})
    return sid


def _open(session: Session, session_id: str) -> tuple[list[m.TimerEvent], Totals]:
    events = _events(session, session_id)
    if not events:
        raise TimerError(f"unknown timer {session_id}")
    totals = compute_totals(events)
    if totals.state == "stopped":
        raise TimerError("this timer is already stopped")
    return events, totals


def heartbeat(session: Session, session_id: str, now: datetime | None = None) -> Totals:
    events, totals = _open(session, session_id)
    if totals.state == "paused":
        raise TimerError("this timer is paused; resume it first")
    _log(session, events[0], "heartbeat", _aware(now or datetime.now(UTC)))
    return compute_totals(_events(session, session_id))


def pause(session: Session, session_id: str, now: datetime | None = None) -> Totals:
    events, totals = _open(session, session_id)
    if totals.state == "paused":
        raise TimerError("this timer is already paused")
    _log(session, events[0], "pause", _aware(now or datetime.now(UTC)))
    append_audit_event(session, actor=events[0].analyst, action="timer.pause",
                       entity_type="timer", entity_id=session_id, details={})
    return compute_totals(_events(session, session_id))


def resume(session: Session, session_id: str, now: datetime | None = None) -> Totals:
    events, totals = _open(session, session_id)
    if totals.state != "paused":
        raise TimerError("this timer is not paused")
    _log(session, events[0], "resume", _aware(now or datetime.now(UTC)))
    append_audit_event(session, actor=events[0].analyst, action="timer.resume",
                       entity_type="timer", entity_id=session_id, details={})
    return compute_totals(_events(session, session_id))


def stop(session: Session, session_id: str, now: datetime | None = None
         ) -> m.EffortCostRecord:
    events, _ = _open(session, session_id)
    base = events[0]
    _log(session, base, "stop", _aware(now or datetime.now(UTC)))
    totals = compute_totals(_events(session, session_id))
    rec = m.EffortCostRecord(
        run_id=f"timer-{session_id}", intel_id=base.intel_id, condition=base.condition,
        component=Component.ANALYST.value, activity=base.activity,
        started_at=_aware(base.ts), ended_at=_aware(base.ts) + _delta(totals.wall_seconds),
        analyst_active_seconds=min(totals.active_seconds, totals.wall_seconds),
        result_status=ResultStatus.OK.value)
    session.add(rec)
    session.flush()
    append_audit_event(session, actor=base.analyst, action="timer.stop", entity_type="timer",
                       entity_id=session_id,
                       details={"active_seconds": round(totals.active_seconds, 1),
                                "wall_seconds": round(totals.wall_seconds, 1)})
    return rec


def _delta(seconds: float):
    from datetime import timedelta
    return timedelta(seconds=seconds)
