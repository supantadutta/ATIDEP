"""C2 orchestration: sanitised item -> evidence-linked claims -> priority (blueprint §17.2).

Order of work:

1. load the sanitised text from the evidence store and check it still matches its recorded hash;
2. deterministic extraction (indicators, CVE IDs), then the Extraction Agent if a model client is
   given;
3. nothing is written until all extraction has finished, so a model failure leaves the item
   in ``sanitised`` and the step can simply be run again;
4. persist evidence segments, claims and model-run records, correlate with earlier items,
   compute the transparent priority, set ``prioritised`` and write an audit event.
"""

from __future__ import annotations

import uuid
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC
from urllib.parse import urlsplit

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.config import AppConfig
from app.db import models as m
from app.db.audit import append_audit_event
from app.services.model_runs import log_calls
from components.c1_ingest.evidence import EvidenceStore, sha256_hex
from components.c2_processing.attack import AttackRelease
from components.c2_processing.evidence import ClaimFactory
from components.c2_processing.extraction_agent import ExtractionStats, run_extraction
from components.c2_processing.indicators import (
    extract_cves,
    extract_indicators,
    load_benign_domains,
)
from components.c2_processing.logsources import candidate_logsources
from components.c2_processing.scoring import PriorityResult, ScoreInputs, score_priority
from components.llm.client import LLMClient, LLMError
from components.llm.prompts import Prompt
from schemas.claim import Claim, ClaimKind, EntityType, IndicatorType
from schemas.common import ProcessingStatus

PROCESSABLE = (ProcessingStatus.SANITISED.value, ProcessingStatus.FAILED.value)


class ProcessingError(Exception):
    pass


@dataclass
class ProcessOutcome:
    """Result of one processing run. A model outage is a normal, retryable outcome, so it is
    returned (and recorded in the audit log) rather than raised: raising would roll back the
    caller's transaction together with the record of the failure."""

    intel_id: str
    claims: int
    verified_claims: int
    unsupported_claims: int
    independent_sources: int
    priority: PriorityResult | None
    extraction: ExtractionStats | None
    extraction_errors: list[str] = field(default_factory=list)
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None


def _host(url: str | None) -> str | None:
    return urlsplit(url).hostname if url else None


def _indicator_class(t: IndicatorType) -> str:
    return "hash" if t in (IndicatorType.MD5, IndicatorType.SHA1, IndicatorType.SHA256) \
        else "ip" if t in (IndicatorType.IPV4, IndicatorType.IPV6) else t.value


def primary_type(claims: list[Claim], half_lives: dict[str, float]) -> str:
    """Recency class of an item. Behaviour if any usable behaviour claim exists (the item is
    mainly about what an actor does); otherwise the most numerous usable indicator class, the
    more perishable class winning a tie."""
    if any(c.usable and c.kind is ClaimKind.BEHAVIOR for c in claims):
        return "behavior"
    counts = Counter(_indicator_class(c.type) for c in claims
                     if c.usable and c.kind is ClaimKind.INDICATOR)
    if not counts:
        return "behavior"
    return sorted(counts, key=lambda k: (-counts[k], half_lives.get(k, 365)))[0]


def _sightings(session: Session, intel_id: str, source_id: int, cluster_id: str | None,
               values: set[tuple[str, str]]) -> dict[int, str]:
    """Other sources whose items contain one of these indicators or CVEs.

    Not independent, so not counted: the item's own source, and every source that published an
    item of the same near-duplicate cluster (a syndicated copy cannot be corroborated by the
    publisher it was copied from). Returns {source_id: intel_id of one corroborating item}."""
    if not values:
        return {}
    excluded = {source_id}
    if cluster_id:
        excluded |= set(session.scalars(select(m.IntelligenceItem.source_id).where(
            (m.IntelligenceItem.cluster_id == cluster_id)
            | (m.IntelligenceItem.intel_id == cluster_id))))
    found: dict[int, str] = {}
    rows = session.execute(
        select(m.Claim.type, m.Claim.value, m.IntelligenceItem.intel_id,
               m.IntelligenceItem.source_id, m.IntelligenceItem.cluster_id)
        .join(m.IntelligenceItem, m.IntelligenceItem.intel_id == m.Claim.intel_id)
        .join(m.EvidenceSegment, m.EvidenceSegment.evidence_id == m.Claim.evidence_id)
        .where(m.Claim.intel_id != intel_id, m.Claim.kind != ClaimKind.BEHAVIOR.value,
               m.Claim.context != "reference_only", m.EvidenceSegment.verified.is_(True)))
    for ctype, cvalue, other_id, other_source, other_cluster in rows:
        if (ctype, cvalue) not in values or other_source in excluded:
            continue
        if cluster_id and (other_cluster == cluster_id or other_id == cluster_id):
            continue
        found.setdefault(other_source, other_id)
    return found


def process_item(session: Session, store: EvidenceStore, intel_id: str, *, cfg: AppConfig,
                 attack: AttackRelease, client: LLMClient | None = None,
                 prompt: Prompt | None = None, benign_domains: list[str] | None = None,
                 allow_test_tlds: bool = False, seed: int | None = None,
                 reprocess: bool = False, actor: str = "system") -> ProcessOutcome:
    item = session.get(m.IntelligenceItem, intel_id)
    if item is None:
        raise ProcessingError(f"unknown item {intel_id}")
    if item.status not in PROCESSABLE and not reprocess:
        raise ProcessingError(f"{intel_id} is {item.status}; use reprocess to run it again")
    if client is not None and prompt is None:
        raise ProcessingError("a prompt is required when a model client is given")

    text = store.load_text(item.raw_sha256)
    if sha256_hex(text) != item.sanitised_sha256:
        raise ProcessingError(f"stored text of {intel_id} no longer matches its recorded hash")
    source = session.get(m.Source, item.source_id)
    assert source is not None
    retrieved = item.retrieved_at if item.retrieved_at.tzinfo else \
        item.retrieved_at.replace(tzinfo=UTC)
    published = item.published_at
    if published is not None and published.tzinfo is None:
        published = published.replace(tzinfo=UTC)

    factory = ClaimFactory(intel_id, item.sanitised_sha256)
    claims: list[Claim] = []
    publisher = [h for h in (_host(item.url), _host(source.url)) if h]
    benign = benign_domains if benign_domains is not None else load_benign_domains()
    for ind in extract_indicators(text, benign_domains=benign, publisher_domains=publisher,
                                  allow_test_tlds=allow_test_tlds):
        claims.append(factory.indicator_claim(ind, retrieved, cfg.scoring.indicator_expiry_days))
    for cve in extract_cves(text):
        claims.append(factory.cve_claim(cve))

    extraction: ExtractionStats | None = None
    extraction_errors: list[str] = []
    run_id = uuid.uuid4().hex[:12]
    calls = []
    if client is not None and prompt is not None:
        try:
            result = run_extraction(client, text, factory, attack, prompt, seed=seed,
                                    max_retries=2)
        except LLMError as exc:
            append_audit_event(session, actor=actor, action="process.model_unavailable",
                               entity_type="intelligence_item", entity_id=intel_id,
                               details={"error": str(exc)[:300]})
            item.processing = {**item.processing, "last_error": f"model: {exc}"[:300]}
            session.flush()
            return ProcessOutcome(intel_id, 0, 0, 0, 0, None, None, [], error=f"model: {exc}")
        claims += result.claims
        extraction, extraction_errors, calls = result.stats, result.errors, result.calls

    # ---- persist -------------------------------------------------------------------------
    if reprocess:
        old = list(session.scalars(select(m.Claim.claim_id).where(m.Claim.intel_id == intel_id)))
        session.execute(delete(m.Claim).where(m.Claim.intel_id == intel_id))
        session.execute(delete(m.EvidenceSegment).where(m.EvidenceSegment.intel_id == intel_id))
        if old:
            append_audit_event(session, actor=actor, action="process.reprocess",
                               entity_type="intelligence_item", entity_id=intel_id,
                               details={"removed_claims": len(old)})
    for c in claims:
        ev = c.evidence
        session.add(m.EvidenceSegment(
            evidence_id=ev.evidence_id, intel_id=intel_id, quote=ev.quote,
            char_start=ev.char_start, char_end=ev.char_end, source_sha256=ev.source_sha256,
            verified=ev.verified))
    session.flush()
    for c in claims:
        session.add(m.Claim(
            claim_id=c.claim_id, intel_id=intel_id, evidence_id=c.evidence.evidence_id,
            kind=c.kind.value, type=c.type.value if c.type else None, value=c.value,
            refanged_from=c.refanged_from, description=c.description, attack_id=c.attack_id,
            valid=c.valid, context=c.context.value, expires_at=c.expires_at,
            llm_stated_confidence=c.llm_stated_confidence))
    session.flush()
    if calls and prompt is not None:
        log_calls(session, run_id=run_id, agent="extraction", intel_id=intel_id, calls=calls,
                  prompt=prompt)

    # ---- correlate and score -------------------------------------------------------------
    keys = {(c.type.value, c.value) for c in claims
            if c.evidence.verified and c.value and c.kind is not ClaimKind.BEHAVIOR
            and c.context.value != "reference_only"}
    corroborating = _sightings(session, intel_id, item.source_id, item.cluster_id, keys)
    independent = 1 + len(corroborating)
    credibility = min(item.credibility_rating, 2) if independent >= 2 else item.credibility_rating

    usable = [c for c in claims if c.usable]
    technique_ids = list(dict.fromkeys(c.attack_id for c in usable if c.attack_id))
    indicator_types = list(dict.fromkeys(c.type.value for c in usable
                                         if c.kind is ClaimKind.INDICATOR))
    logsources = candidate_logsources(technique_ids, indicator_types)
    entities = [c for c in usable if c.kind is ClaimKind.ENTITY]
    products = [c.value for c in entities
                if c.type in (EntityType.PRODUCT, EntityType.TOOL, EntityType.MALWARE) and c.value]
    sectors = [c.value for c in entities if c.type is EntityType.SECTOR and c.value]
    platforms = sorted({s.split("_", 1)[0] for s in logsources if s.startswith(("windows_",
                                                                              "linux_"))})
    verified = sum(c.evidence.verified for c in claims)
    support = 100.0 * verified / len(claims) if claims else 0.0
    prim = primary_type(claims, cfg.scoring.recency_half_life_days)

    result = score_priority(
        ScoreInputs(reliability_rating=source.reliability_rating, credibility_rating=credibility,
                    evidence_support_pct=support, retrieved_at=retrieved, published_at=published,
                    primary_type=prim, independent_sources=independent,
                    technique_ids=technique_ids, products=products, platforms=platforms,
                    sectors=sectors, candidate_logsources=logsources),
        cfg.scoring, cfg.org_profile, cfg.telemetry_catalog, attack)

    ic = next(c for c in result.components if c.name == "intelligence_confidence")
    item.intelligence_confidence = int(round(ic.value))
    item.priority_score = result.score
    item.priority_band = result.priority.band.value
    item.priority_components = {"components": result.explanation(), "primary_type": prim,
                                "independent_sources": independent,
                                "corroborated_by": corroborating,
                                "effective_credibility": credibility}
    item.status = ProcessingStatus.PRIORITISED.value
    item.processing = {
        **{k: v for k, v in item.processing.items() if k != "last_error"},
        "run_id": run_id, "attack_version": attack.version,
        "extraction_agent": ("skipped" if client is None else
                             {"model": client.model, "prompt_version": prompt.version,
                              "prompt_sha256": prompt.sha256,
                              "errors": extraction_errors}),
        "candidate_logsources": logsources, "technique_ids": technique_ids}
    unsupported = len(claims) - verified
    append_audit_event(
        session, actor=actor, action="process.prioritised", entity_type="intelligence_item",
        entity_id=intel_id,
        details={"claims": len(claims), "unsupported": unsupported, "score": result.score,
                 "band": result.priority.band.value, "independent_sources": independent,
                 "run_id": run_id, "model": client.model if client else None})
    session.flush()
    return ProcessOutcome(intel_id, len(claims), verified, unsupported, independent, result,
                          extraction, extraction_errors)
