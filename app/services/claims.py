"""Database rows -> schema objects for claims (the inverse of what ``process`` persists)."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import models as m
from schemas.claim import (
    Claim,
    ClaimKind,
    EntityType,
    Evidence,
    IndicatorContext,
    IndicatorType,
)


def _utc(dt):
    from datetime import UTC

    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def load_claims(session: Session, intel_id: str) -> list[Claim]:
    rows = session.execute(
        select(m.Claim, m.EvidenceSegment)
        .join(m.EvidenceSegment, m.EvidenceSegment.evidence_id == m.Claim.evidence_id)
        .where(m.Claim.intel_id == intel_id).order_by(m.Claim.claim_id)).all()
    out: list[Claim] = []
    for c, ev in rows:
        kind = ClaimKind(c.kind)
        typ = None
        if c.type:
            typ = IndicatorType(c.type) if kind is ClaimKind.INDICATOR else EntityType(c.type)
        out.append(Claim(
            claim_id=c.claim_id, kind=kind, type=typ, value=c.value,
            refanged_from=c.refanged_from, valid=c.valid, context=IndicatorContext(c.context),
            expires_at=_utc(c.expires_at), description=c.description, attack_id=c.attack_id,
            llm_stated_confidence=c.llm_stated_confidence,
            evidence=Evidence(evidence_id=ev.evidence_id, quote=ev.quote, char_start=ev.char_start,
                              char_end=ev.char_end, source_sha256=ev.source_sha256,
                              verified=ev.verified)))
    return out
