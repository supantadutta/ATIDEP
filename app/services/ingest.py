"""Persist collected documents: evidence store, database row, duplicate handling, audit event
(blueprint §17.1 steps 3-7)."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db import models as m
from app.db.audit import append_audit_event
from components.c1_ingest.collect import Collected
from components.c1_ingest.evidence import EvidenceStore, fingerprint, sha256_hex, similarity
from schemas.common import ProcessingStatus

NEAR_DUPLICATE_THRESHOLD = 0.85


class IngestStatus(StrEnum):
    NEW = "new"
    NEAR_DUPLICATE = "near_duplicate"
    DUPLICATE = "duplicate"


@dataclass(frozen=True)
class IngestOutcome:
    status: IngestStatus
    intel_id: str
    duplicate_of: str | None = None
    cluster_id: str | None = None


def get_or_create_source(session: Session, *, name: str, source_type: str = "report",
                         url: str | None = None, reliability_rating: str = "C",
                         default_credibility: int = 3) -> m.Source:
    existing = session.scalars(select(m.Source).where(m.Source.name == name)).first()
    if existing:
        return existing
    src = m.Source(name=name, source_type=source_type, url=url,
                   reliability_rating=reliability_rating, default_credibility=default_credibility)
    session.add(src)
    session.flush()
    return src


def _next_intel_id(session: Session, year: int) -> str:
    prefix = f"TI-{year}-"
    last = session.scalars(select(func.max(m.IntelligenceItem.intel_id))
                           .where(m.IntelligenceItem.intel_id.like(prefix + "%"))).first()
    n = int(last.rsplit("-", 1)[1]) + 1 if last else 1
    return f"{prefix}{n:04d}"


def ingest(session: Session, store: EvidenceStore, doc: Collected, source: m.Source, *,
           actor: str = "system") -> IngestOutcome:
    raw_sha = sha256_hex(doc.raw)
    text_sha = sha256_hex(doc.text)

    dup = session.scalars(select(m.IntelligenceItem).where(
        (m.IntelligenceItem.raw_sha256 == raw_sha)
        | (m.IntelligenceItem.sanitised_sha256 == text_sha))).first()
    if dup:
        append_audit_event(session, actor=actor, action="ingest.duplicate",
                           entity_type="intelligence_item", entity_id=dup.intel_id,
                           details={"raw_sha256": raw_sha, "source": doc.source_name,
                                    "url": doc.url})
        return IngestOutcome(IngestStatus.DUPLICATE, dup.intel_id, duplicate_of=dup.intel_id)

    fp = fingerprint(doc.text)
    cluster = None
    near = None
    for other in session.scalars(select(m.IntelligenceItem).where(
            m.IntelligenceItem.fingerprint != None)):  # noqa: E711 - SQL NULL test
        if other.fingerprint and similarity(fp, other.fingerprint) >= NEAR_DUPLICATE_THRESHOLD:
            near = other
            cluster = other.cluster_id or other.intel_id
            if other.cluster_id is None:
                other.cluster_id = cluster
            break

    store.save_raw(doc.raw)
    store.save_text(raw_sha, doc.text)
    intel_id = _next_intel_id(session, datetime.now(UTC).year)
    session.add(m.IntelligenceItem(
        intel_id=intel_id, source_id=source.id, title=doc.title, published_at=doc.published_at,
        retrieved_at=doc.retrieved_at, raw_sha256=raw_sha, sanitised_sha256=text_sha,
        sanitisation_stripped=doc.sanitised.stripped, url=doc.url, fingerprint=fp,
        cluster_id=cluster, credibility_rating=source.default_credibility,
        status=ProcessingStatus.SANITISED.value,
        processing={"kind": doc.kind.value}))
    session.flush()
    append_audit_event(session, actor=actor, action="ingest.accepted",
                       entity_type="intelligence_item", entity_id=intel_id,
                       details={"raw_sha256": raw_sha, "sanitised_sha256": text_sha,
                                "stripped": doc.sanitised.stripped, "source": doc.source_name,
                                "url": doc.url,
                                "near_duplicate_of": near.intel_id if near else None})
    status = IngestStatus.NEAR_DUPLICATE if near else IngestStatus.NEW
    return IngestOutcome(status, intel_id, duplicate_of=near.intel_id if near else None,
                         cluster_id=cluster)
