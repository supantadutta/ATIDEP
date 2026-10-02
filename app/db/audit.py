"""Tamper-evident audit trail (blueprint §17.4.4).

Each event stores the SHA-256 of the previous event, so changing, deleting or reordering any
earlier event breaks the chain. ``verify_audit_chain`` re-computes it.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import AuditEvent
from schemas.common import GENESIS_HASH


def _canonical(prev_hash: str, ts: datetime, actor: str, action: str, entity_type: str,
               entity_id: str, details: dict[str, Any]) -> str:
    # Naive datetimes come back from SQLite; normalise to UTC ISO so hashes are stable.
    stamp = ts.replace(tzinfo=None).isoformat(timespec="microseconds")
    return json.dumps([prev_hash, stamp, actor, action, entity_type, entity_id, details],
                      sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def compute_event_hash(prev_hash: str, ts: datetime, actor: str, action: str,
                       entity_type: str, entity_id: str, details: dict[str, Any]) -> str:
    payload = _canonical(prev_hash, ts, actor, action, entity_type, entity_id, details)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def append_audit_event(session: Session, *, actor: str, action: str, entity_type: str,
                       entity_id: str, details: dict[str, Any] | None = None,
                       ts: datetime | None = None) -> AuditEvent:
    from datetime import UTC

    details = details or {}
    ts = ts or datetime.now(UTC)
    last = session.scalars(select(AuditEvent).order_by(AuditEvent.id.desc()).limit(1)).first()
    prev_hash = last.event_hash if last else GENESIS_HASH
    event = AuditEvent(
        ts=ts, actor=actor, action=action, entity_type=entity_type, entity_id=entity_id,
        details=details, prev_hash=prev_hash,
        event_hash=compute_event_hash(prev_hash, ts, actor, action, entity_type, entity_id,
                                      details),
    )
    session.add(event)
    session.flush()
    return event


@dataclass(frozen=True)
class ChainReport:
    ok: bool
    checked: int
    first_bad_id: int | None = None
    reason: str = ""


def verify_audit_chain(session: Session) -> ChainReport:
    prev = GENESIS_HASH
    n = 0
    for ev in session.scalars(select(AuditEvent).order_by(AuditEvent.id)):
        n += 1
        if ev.prev_hash != prev:
            return ChainReport(False, n, ev.id, "prev_hash does not match the previous event")
        expected = compute_event_hash(ev.prev_hash, ev.ts, ev.actor, ev.action, ev.entity_type,
                                      ev.entity_id, ev.details)
        if ev.event_hash != expected:
            return ChainReport(False, n, ev.id, "event content does not match its hash")
        prev = ev.event_hash
    return ChainReport(True, n)
