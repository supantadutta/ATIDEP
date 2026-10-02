"""Internal REST API (blueprint §40). Local use only: it binds to 127.0.0.1, every call except
``/health`` needs the API key, and every call that acts for a person needs that person's name in
``X-Analyst`` (an approval by a name such as "system" or "agent" is refused by the service).

``create_app`` takes its dependencies as an :class:`AppContext`, so the same code runs against a
real model and manager in the lab and against scripted ones in tests. Handlers are thin: they
open a transaction, call a service and shape the answer.
"""

from __future__ import annotations

import hmac
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi import Body, Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import Engine, func, select

from app.config import AppConfig
from app.db import models as m
from app.db.audit import verify_audit_chain
from app.db.session import session_scope
from app.services import costs, deployment, feedback, timers
from app.services.claims import load_claims
from app.services.detection import (
    DetectionError,
    assess_item,
    create_ioc_rule,
    create_sigma_rule,
)
from app.services.governance import (
    ApprovalError,
    GovernanceError,
    decide,
    evaluate_rule,
    load_report,
    loop_validator,
    submit_for_approval,
    validate_rule,
)
from app.services.ingest import get_or_create_source, ingest
from app.services.process import ProcessingError, process_item
from components.c1_ingest.collect import Fetcher, collect_bytes, collect_feed
from components.c1_ingest.evidence import EvidenceStore
from components.c1_ingest.parsers import ParseError
from components.c1_ingest.ssrf import FetchError
from components.c2_processing.attack import AttackRelease
from components.c4_validation.corpus import TestEvent, TestSet
from components.c4_validation.tier2 import LabManager
from components.c5_deployment.adapter import AdapterError, WazuhAdapter
from components.c5_deployment.verify import replay_verifier
from components.llm.client import LLMClient
from components.llm.prompts import PromptSet
from schemas.detection_opportunity import Decision
from schemas.validation_result import GateStatus


@dataclass
class AppContext:
    cfg: AppConfig
    engine: Engine
    store: EvidenceStore
    attack: AttackRelease
    prompts: PromptSet
    api_key: str
    benign_domains: list[str]
    llm: Callable[[], LLMClient]
    packages_dir: Path
    baseline: list[TestEvent] = field(default_factory=list)
    test_set_for: Callable[[str], TestSet | None] = lambda intel_id: None
    fetcher: Callable[[list[str]], Fetcher] | None = None
    adapter: Callable[[], WazuhAdapter] | None = None
    lab: LabManager | None = None
    allow_test_tlds: bool = False
    now: Callable[[], datetime] = lambda: datetime.now(UTC)


class ProcessBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    seed: int | None = None


class CommentBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    comment: str = Field(default="", max_length=2000)
    author: str = Field(default="ATIDEP", max_length=80)


class TestBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tier: int = Field(default=1, ge=1, le=2)


class DeployBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    dry_run: bool = True


class FeedbackBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    disposition: str
    notes: str = Field(default="", max_length=1000)


class TimerBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    condition: str = "B"
    activity: str = "review_approval"


def _iso(dt: datetime | None) -> str | None:
    return dt.isoformat() if dt else None


def create_app(ctx: AppContext) -> FastAPI:
    app = FastAPI(title="ATIDEP", version="0.1", docs_url=None, redoc_url=None)

    def auth(authorization: str = Header(default="")) -> None:
        token = authorization.removeprefix("Bearer ").strip()
        if not ctx.api_key or not hmac.compare_digest(token.encode(), ctx.api_key.encode()):
            raise HTTPException(status_code=401, detail="missing or wrong API key")

    def analyst(x_analyst: str = Header(default="")) -> str:
        if not x_analyst.strip():
            raise HTTPException(status_code=400, detail="X-Analyst (your name) is required")
        return x_analyst.strip()

    guarded = [Depends(auth)]

    @app.exception_handler(ApprovalError)
    async def _approval(_: Request, exc: ApprovalError) -> JSONResponse:
        return JSONResponse({"detail": str(exc)}, status_code=403)

    @app.exception_handler(GovernanceError)
    @app.exception_handler(DetectionError)
    @app.exception_handler(ProcessingError)
    @app.exception_handler(timers.TimerError)
    @app.exception_handler(deployment.DeploymentError)
    async def _conflict(_: Request, exc: Exception) -> JSONResponse:
        return JSONResponse({"detail": str(exc)}, status_code=409)

    @app.exception_handler(ParseError)
    @app.exception_handler(ValueError)
    async def _bad(_: Request, exc: Exception) -> JSONResponse:
        return JSONResponse({"detail": str(exc)}, status_code=422)

    @app.exception_handler(FetchError)
    @app.exception_handler(AdapterError)
    async def _upstream(_: Request, exc: Exception) -> JSONResponse:
        return JSONResponse({"detail": str(exc)}, status_code=502)

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    # ---- overview and intelligence ------------------------------------------------------------
    @app.get("/overview", dependencies=guarded)
    def overview() -> dict[str, Any]:
        with session_scope(ctx.engine) as s:
            def count(model, *where):
                return s.scalar(select(func.count()).select_from(model).where(*where)) or 0
            by_state = dict(s.execute(
                select(m.Rule.state, func.count()).group_by(m.Rule.state)).all())
            by_status = dict(s.execute(select(m.IntelligenceItem.status, func.count())
                                       .group_by(m.IntelligenceItem.status)).all())
            audit = [e.action for e in s.scalars(select(m.AuditEvent).where(
                m.AuditEvent.action == "ingest.duplicate"))]
            return {
                "items": count(m.IntelligenceItem), "duplicates_seen": len(audit),
                "high_priority": count(m.IntelligenceItem,
                                       m.IntelligenceItem.priority_band.in_(["high", "critical"])),
                "opportunities": count(m.DetectionOpportunity), "items_by_status": by_status,
                "rules_by_state": by_state,
                "alerts": count(m.DetectionResult)}

    @app.get("/intelligence", dependencies=guarded)
    def list_items(status: str | None = None, band: str | None = None,
                   limit: int = Query(default=50, ge=1, le=500)) -> list[dict[str, Any]]:
        with session_scope(ctx.engine) as s:
            q = select(m.IntelligenceItem).order_by(
                m.IntelligenceItem.priority_score.desc().nulls_last(), m.IntelligenceItem.intel_id)
            if status:
                q = q.where(m.IntelligenceItem.status == status)
            if band:
                q = q.where(m.IntelligenceItem.priority_band == band)
            return [{"intel_id": i.intel_id, "title": i.title, "status": i.status,
                     "priority_score": i.priority_score, "priority_band": i.priority_band,
                     "published_at": _iso(i.published_at), "cluster_id": i.cluster_id}
                    for i in s.scalars(q.limit(limit))]

    @app.get("/intelligence/{intel_id}", dependencies=guarded)
    def get_item(intel_id: str) -> dict[str, Any]:
        with session_scope(ctx.engine) as s:
            item = s.get(m.IntelligenceItem, intel_id)
            if item is None:
                raise HTTPException(status_code=404, detail="unknown item")
            claims = load_claims(s, intel_id)
            opps = s.scalars(select(m.DetectionOpportunity).where(
                m.DetectionOpportunity.intel_id == intel_id)).all()
            src = s.get(m.Source, item.source_id)
            return {
                "intel_id": intel_id, "title": item.title, "url": item.url, "status": item.status,
                "source": {"name": src.name, "reliability": src.reliability_rating},
                "credibility_rating": item.credibility_rating,
                "intelligence_confidence": item.intelligence_confidence,
                "priority": {"score": item.priority_score, "band": item.priority_band,
                             **(item.priority_components or {})},
                "sanitisation_stripped": item.sanitisation_stripped,
                "processing": item.processing,
                "claims": [{
                    "claim_id": c.claim_id, "kind": c.kind.value,
                    "type": c.type.value if c.type else None, "value": c.value,
                    "description": c.description, "attack_id": c.attack_id,
                    "context": c.context.value, "usable": c.usable,
                    "expires_at": _iso(c.expires_at),
                    "evidence": {"evidence_id": c.evidence.evidence_id, "quote": c.evidence.quote,
                                 "start": c.evidence.char_start, "end": c.evidence.char_end,
                                 "verified": c.evidence.verified}} for c in claims],
                "opportunities": [{
                    "opportunity_id": o.opportunity_id, "decision": o.decision,
                    "detectable": o.detectable, "concept": o.detection_concept,
                    "required_log_source": o.required_log_source,
                    "required_fields": o.required_fields, "techniques": o.attack_techniques,
                    "false_positives": o.false_positive_hypotheses, "evidence_ids": o.evidence_ids,
                    "reason": o.decision_reason, "override_applied": o.override_applied,
                    "override_reason": o.override_reason} for o in opps]}

    @app.get("/intelligence/{intel_id}/text", dependencies=guarded)
    def get_text(intel_id: str) -> dict[str, Any]:
        with session_scope(ctx.engine) as s:
            item = s.get(m.IntelligenceItem, intel_id)
            if item is None:
                raise HTTPException(status_code=404, detail="unknown item")
            return {"intel_id": intel_id, "sanitised_sha256": item.sanitised_sha256,
                    "text": ctx.store.load_text(item.raw_sha256)}

    @app.post("/intelligence/upload", dependencies=guarded)
    async def upload(request: Request, source: str = Query(min_length=1, max_length=120),
                     title: str | None = Query(default=None, max_length=300),
                     url: str | None = Query(default=None, max_length=1000),
                     reliability: str = Query(default="C", pattern="^[A-F]$"),
                     credibility: int = Query(default=3, ge=1, le=6),
                     who: str = Depends(analyst)) -> dict[str, Any]:
        data = await request.body()
        doc = collect_bytes(data, source_name=source, url=url, title=title,
                            content_type=request.headers.get("x-document-type"),
                            retrieved_at=ctx.now())
        with session_scope(ctx.engine) as s:
            src = get_or_create_source(s, name=source, reliability_rating=reliability,
                                       default_credibility=credibility)
            out = ingest(s, ctx.store, doc, src, actor=who)
        return {"intel_id": out.intel_id, "status": out.status.value,
                "duplicate_of": out.duplicate_of, "cluster_id": out.cluster_id}

    @app.post("/collection/run", dependencies=guarded)
    def collection_run(who: str = Depends(analyst)) -> dict[str, Any]:
        if ctx.fetcher is None:
            raise HTTPException(status_code=503, detail="no fetcher is configured")
        report: list[dict[str, Any]] = []
        for src_cfg in ctx.cfg.sources.get("sources", []):
            entry: dict[str, Any] = {"source": src_cfg["name"], "new": 0, "duplicates": 0,
                                     "errors": []}
            report.append(entry)
            try:
                fetcher = ctx.fetcher(list(src_cfg.get("allowed_domains", [])))
                feed = collect_feed(fetcher, src_cfg["url"], source_name=src_cfg["name"])
            except (FetchError, ParseError) as exc:
                entry["errors"].append(str(exc))
                continue
            entry["errors"] += feed.errors
            with session_scope(ctx.engine) as s:
                src = get_or_create_source(
                    s, name=src_cfg["name"], source_type=src_cfg.get("type", "feed"),
                    url=src_cfg["url"], reliability_rating=src_cfg.get("reliability", "C"),
                    default_credibility=src_cfg.get("default_credibility", 3))
                for doc in feed.documents:
                    out = ingest(s, ctx.store, doc, src, actor=who)
                    entry["duplicates" if out.status.value == "duplicate" else "new"] += 1
        return {"sources": report}

    @app.post("/intelligence/{intel_id}/process", dependencies=guarded)
    def process(intel_id: str, body: ProcessBody = Body(default_factory=ProcessBody),
                who: str = Depends(analyst)) -> dict[str, Any]:
        client = ctx.llm()
        with session_scope(ctx.engine) as s:
            out = process_item(s, ctx.store, intel_id, cfg=ctx.cfg, attack=ctx.attack,
                               client=client, prompt=ctx.prompts.extraction,
                               benign_domains=ctx.benign_domains,
                               allow_test_tlds=ctx.allow_test_tlds, seed=body.seed, actor=who)
            if not out.ok:
                return {"intel_id": intel_id, "processed": False, "error": out.error}
            ids = assess_item(s, intel_id, cfg=ctx.cfg, attack=ctx.attack, client=client,
                              prompt=ctx.prompts.opportunity, now=ctx.now(), seed=body.seed,
                              actor=who)
            item = s.get(m.IntelligenceItem, intel_id)
            return {"intel_id": intel_id, "processed": True, "claims": out.claims,
                    "unsupported_claims": out.unsupported_claims,
                    "priority": {"score": out.priority.score if out.priority else None,
                                 "band": item.priority_band},
                    "independent_sources": out.independent_sources,
                    "opportunity_ids": ids, "status": item.status}

    # ---- opportunities and rules --------------------------------------------------------------
    @app.get("/opportunities", dependencies=guarded)
    def list_opportunities(intel_id: str | None = None) -> list[dict[str, Any]]:
        with session_scope(ctx.engine) as s:
            q = select(m.DetectionOpportunity).order_by(m.DetectionOpportunity.opportunity_id)
            if intel_id:
                q = q.where(m.DetectionOpportunity.intel_id == intel_id)
            return [{"opportunity_id": o.opportunity_id, "intel_id": o.intel_id,
                     "decision": o.decision, "detectable": o.detectable,
                     "reason": o.decision_reason} for o in s.scalars(q)]

    @app.post("/opportunities/{opp_id}/generate-rule", dependencies=guarded)
    def generate_rule(opp_id: int, body: ProcessBody = Body(default_factory=ProcessBody),
                      who: str = Depends(analyst)) -> dict[str, Any]:
        with session_scope(ctx.engine) as s:
            opp = s.get(m.DetectionOpportunity, opp_id)
            if opp is None:
                raise HTTPException(status_code=404, detail="unknown opportunity")
            if opp.decision == Decision.IOC_BASED.value:
                rid = create_ioc_rule(s, opp_id, cfg=ctx.cfg, benign_domains=ctx.benign_domains,
                                      now=ctx.now(), actor=who)
                return {"rule_id": rid, "kind": "ioc_list"}
            if opp.decision != Decision.BEHAVIORAL.value:
                raise HTTPException(status_code=409, detail=f"a {opp.decision} opportunity does "
                                                            "not generate a rule")
            rid, res = create_sigma_rule(
                s, opp_id, cfg=ctx.cfg, client=ctx.llm(), prompt=ctx.prompts.rule,
                validate=loop_validator(s, ctx.cfg, ctx.attack), seed=body.seed, actor=who)
            return {"rule_id": rid, "kind": "sigma", "loop_status": res.status,
                    "first_pass_valid": res.first_pass_valid, "repairs_used": res.repairs_used,
                    "attempts": len(res.attempts)}

    def _rule_summary(s, r: m.Rule) -> dict[str, Any]:
        v = s.scalars(select(m.RuleVersion).where(
            m.RuleVersion.rule_id == r.rule_id, m.RuleVersion.version == r.current_version)).one()
        opp = s.get(m.DetectionOpportunity, r.opportunity_id)
        return {"rule_id": r.rule_id, "kind": r.kind, "state": r.state,
                "version": r.current_version, "quality_score": v.quality_score,
                "intel_id": opp.intel_id, "content_sha256": v.content_sha256}

    @app.get("/rules", dependencies=guarded)
    def list_rules(state: str | None = None) -> list[dict[str, Any]]:
        with session_scope(ctx.engine) as s:
            q = select(m.Rule).order_by(m.Rule.rule_id)
            if state:
                q = q.where(m.Rule.state == state)
            rules = list(s.scalars(q))
            out = [_rule_summary(s, r) for r in rules]
            return sorted(out, key=lambda r: (-(r["quality_score"] or -1), r["rule_id"]))

    @app.get("/rules/{rule_id}", dependencies=guarded)
    def get_rule(rule_id: str) -> dict[str, Any]:
        with session_scope(ctx.engine) as s:
            r = s.get(m.Rule, rule_id)
            if r is None:
                raise HTTPException(status_code=404, detail="unknown rule")
            versions = s.scalars(select(m.RuleVersion).where(
                m.RuleVersion.rule_id == rule_id).order_by(m.RuleVersion.version)).all()
            cur = next(v for v in versions if v.version == r.current_version)
            gates = [{"gate": g.gate.value, "status": g.status.value, "tier": g.tier,
                      "reason_codes": g.reason_codes, "message": g.message}
                     for g in load_report(s, cur.id)]
            approvals = s.scalars(select(m.Approval).where(
                m.Approval.rule_version_id.in_([v.id for v in versions]))).all()
            deps = s.scalars(select(m.Deployment).where(
                m.Deployment.rule_version_id.in_([v.id for v in versions]))).all()
            return {**_rule_summary(s, r), "content": cur.content,
                    "assumptions": cur.assumptions, "use_case": cur.use_case, "gates": gates,
                    "versions": [{"version": v.version, "origin": v.origin,
                                  "content_sha256": v.content_sha256,
                                  "quality_score": v.quality_score} for v in versions],
                    "approvals": [{"id": a.id, "reviewer": a.reviewer, "author": a.author,
                                   "decision": a.decision, "comment": a.comment,
                                   "content_sha256": a.content_sha256,
                                   "decided_at": _iso(a.decided_at)} for a in approvals],
                    "deployments": [{"id": d.id, "mode": d.mode, "status": d.status,
                                     "package_sha256": d.package_sha256,
                                     "rule_ids": d.wazuh_rule_ids} for d in deps]}

    def _outcome(out) -> dict[str, Any]:
        return {"rule_id": out.rule_id, "version": out.version, "outcome": out.outcome.value,
                "quality_score": out.quality_score, "report_sha256": out.report_sha256,
                "quality_breakdown": out.quality_breakdown,
                "gates": [{"gate": r.gate.value, "status": r.status.value, "tier": r.tier,
                           "reason_codes": r.reason_codes, "message": r.message}
                          for r in out.results],
                "defects": out.details.get("defects", [])}

    def _intel_of(s, rule_id: str) -> str:
        r = s.get(m.Rule, rule_id)
        if r is None:
            raise HTTPException(status_code=404, detail="unknown rule")
        return s.get(m.DetectionOpportunity, r.opportunity_id).intel_id

    @app.post("/rules/{rule_id}/validate", dependencies=guarded)
    def validate(rule_id: str, who: str = Depends(analyst)) -> dict[str, Any]:
        with session_scope(ctx.engine) as s:
            out = validate_rule(s, rule_id, cfg=ctx.cfg, attack=ctx.attack,
                                test_set=ctx.test_set_for(_intel_of(s, rule_id)),
                                baseline=ctx.baseline, lab=ctx.lab, actor=who)
            return _outcome(out)

    @app.post("/rules/{rule_id}/test", dependencies=guarded)
    def test_rule(rule_id: str, body: TestBody = Body(default_factory=TestBody),
                  who: str = Depends(analyst)) -> dict[str, Any]:
        if body.tier == 2 and ctx.lab is None:
            raise HTTPException(status_code=503, detail="no lab manager is configured for tier 2")
        with session_scope(ctx.engine) as s:
            rule = s.get(m.Rule, rule_id)
            if rule is None:
                raise HTTPException(status_code=404, detail="unknown rule")
            version = s.scalars(select(m.RuleVersion).where(
                m.RuleVersion.rule_id == rule_id,
                m.RuleVersion.version == rule.current_version)).one()
            ev = evaluate_rule(s, rule, version, cfg=ctx.cfg, attack=ctx.attack,
                               test_set=ctx.test_set_for(_intel_of(s, rule_id)),
                               baseline=ctx.baseline, lab=ctx.lab if body.tier == 2 else None)
            return {"rule_id": rule_id, "tier": body.tier, "stored": False,
                    "gates": [{"gate": r.gate.value, "status": r.status.value, "tier": r.tier,
                               "message": r.message} for r in ev.results],
                    "passed": all(r.status is GateStatus.PASSED for r in ev.results),
                    "events": ev.detail.get("events")}

    @app.post("/rules/{rule_id}/submit", dependencies=guarded)
    def submit(rule_id: str, who: str = Depends(analyst)) -> dict[str, str]:
        with session_scope(ctx.engine) as s:
            submit_for_approval(s, rule_id, actor=who)
        return {"rule_id": rule_id, "state": "pending_approval"}

    def _decide(rule_id: str, decision: str, body: CommentBody, who: str) -> dict[str, Any]:
        with session_scope(ctx.engine) as s:
            a = decide(s, rule_id, reviewer=who, decision=decision, comment=body.comment,
                       author=body.author)
            return {"rule_id": rule_id, "decision": decision, "approval_id": a.id,
                    "reviewer": a.reviewer, "content_sha256": a.content_sha256,
                    "validation_report_sha256": a.validation_report_sha256}

    @app.post("/rules/{rule_id}/approve", dependencies=guarded)
    def approve(rule_id: str, body: CommentBody = Body(default_factory=CommentBody),
                who: str = Depends(analyst)) -> dict[str, Any]:
        return _decide(rule_id, "approved", body, who)

    @app.post("/rules/{rule_id}/reject", dependencies=guarded)
    def reject(rule_id: str, body: CommentBody = Body(default_factory=CommentBody),
               who: str = Depends(analyst)) -> dict[str, Any]:
        return _decide(rule_id, "rejected", body, who)

    @app.post("/rules/{rule_id}/package", dependencies=guarded)
    def package(rule_id: str, who: str = Depends(analyst)) -> dict[str, Any]:
        with session_scope(ctx.engine) as s:
            dep = deployment.export_package(
                s, rule_id, ctx.cfg, out_dir=ctx.packages_dir, now=ctx.now(),
                test_set=ctx.test_set_for(_intel_of(s, rule_id)), actor=who)
            return {"deployment_id": dep.id, "package_sha256": dep.package_sha256,
                    "path": dep.package_path, "rule_ids": dep.wazuh_rule_ids}

    @app.post("/rules/{rule_id}/deploy-lab", dependencies=guarded)
    def deploy_lab(rule_id: str, body: DeployBody = Body(default_factory=DeployBody),
                   who: str = Depends(analyst)) -> dict[str, Any]:
        if ctx.adapter is None:
            raise HTTPException(status_code=503, detail="no Wazuh adapter is configured")
        adapter = ctx.adapter()
        with session_scope(ctx.engine) as s:
            ts = ctx.test_set_for(_intel_of(s, rule_id))
            if body.dry_run:
                dep = deployment.dry_run(s, rule_id, adapter, ctx.cfg, now=ctx.now(),
                                         test_set=ts, actor=who)
            else:
                art = deployment.compose_artifacts(s, rule_id, ctx.cfg, now=ctx.now())
                verify = replay_verifier(ctx.lab, ts, art.rule_ids) \
                    if ctx.lab is not None and ts is not None else None
                dep = deployment.deploy_lab(s, rule_id, adapter, ctx.cfg,
                                            out_dir=ctx.packages_dir, now=ctx.now(),
                                            test_set=ts, verify=verify, actor=who)
            return {"deployment_id": dep.id, "mode": dep.mode, "status": dep.status,
                    "details": dep.details, "package_sha256": dep.package_sha256}

    @app.post("/rules/{rule_id}/alerts", dependencies=guarded)
    def ingest_alerts(rule_id: str, alerts: list[dict[str, Any]] = Body(max_length=5000),
                      who: str = Depends(analyst)) -> dict[str, int]:
        with session_scope(ctx.engine) as s:
            return {"new": feedback.ingest_alerts(s, rule_id, alerts, actor=who)}

    @app.get("/rules/{rule_id}/stats", dependencies=guarded)
    def rule_stats(rule_id: str) -> dict[str, Any]:
        with session_scope(ctx.engine) as s:
            return feedback.rule_stats(s, rule_id).as_dict()

    @app.post("/rules/{rule_id}/improve", dependencies=guarded)
    def improve(rule_id: str, who: str = Depends(analyst)) -> dict[str, Any]:
        with session_scope(ctx.engine) as s:
            rep = feedback.improve_rule(s, rule_id, ctx.llm(), ctx.prompts.improvement, ctx.cfg,
                                        now=ctx.now(), actor=who)
            return {"skipped": rep.skipped, "error": rep.error, "new_version": rep.new_version,
                    "accepted": [r.model_dump(mode="json") for r in rep.accepted],
                    "rejected": [{"recommendation": r.model_dump(mode="json"), "why": why}
                                 for r, why in rep.rejected],
                    "applied": [r.model_dump(mode="json") for r in rep.applied]}

    @app.get("/detections", dependencies=guarded)
    def list_detections(rule_id: str | None = None, limit: int = Query(default=100, le=1000)
                        ) -> list[dict[str, Any]]:
        with session_scope(ctx.engine) as s:
            rows = s.scalars(select(m.DetectionResult).order_by(m.DetectionResult.id.desc())
                             .limit(limit)).all()
            return [{"id": r.id, "deployment_id": r.deployment_id, "wazuh_rule": r.rule_id_fired,
                     "event_time": _iso(r.event_time), "disposition": r.disposition,
                     "analyst": r.analyst, "features": r.features} for r in rows]

    @app.post("/detections/{result_id}/feedback", dependencies=guarded)
    def detection_feedback(result_id: int, body: FeedbackBody, who: str = Depends(analyst)
                           ) -> dict[str, Any]:
        with session_scope(ctx.engine) as s:
            feedback.set_disposition(s, result_id, body.disposition, who, body.notes)
        return {"id": result_id, "disposition": body.disposition}

    # ---- timers, costs, audit -------------------------------------------------------------------
    @app.post("/timers/{item_id}/start", dependencies=guarded)
    def timer_start(item_id: str, body: TimerBody = Body(default_factory=TimerBody),
                    who: str = Depends(analyst)) -> dict[str, Any]:
        with session_scope(ctx.engine) as s:
            sid = timers.start(s, analyst=who, intel_id=item_id, condition=body.condition,
                               activity=body.activity, now=ctx.now())
        return {"timer": sid}

    def _mine(s, item_id: str, who: str) -> str:
        sid = timers.running_session(s, who)
        first = s.scalars(select(m.TimerEvent).where(m.TimerEvent.session_id == sid)).first() \
            if sid else None
        if sid is None or first is None or first.intel_id != item_id:
            raise timers.TimerError("you have no open timer for this item")
        return sid

    @app.post("/timers/{item_id}/heartbeat", dependencies=guarded)
    def timer_heartbeat(item_id: str, who: str = Depends(analyst)) -> dict[str, Any]:
        with session_scope(ctx.engine) as s:
            t = timers.heartbeat(s, _mine(s, item_id, who), ctx.now())
            return {"active_seconds": t.active_seconds, "wall_seconds": t.wall_seconds,
                    "state": t.state}

    @app.post("/timers/{item_id}/pause", dependencies=guarded)
    def timer_pause(item_id: str, who: str = Depends(analyst)) -> dict[str, Any]:
        with session_scope(ctx.engine) as s:
            t = timers.pause(s, _mine(s, item_id, who), ctx.now())
            return {"active_seconds": t.active_seconds, "state": t.state}

    @app.post("/timers/{item_id}/resume", dependencies=guarded)
    def timer_resume(item_id: str, who: str = Depends(analyst)) -> dict[str, Any]:
        with session_scope(ctx.engine) as s:
            t = timers.resume(s, _mine(s, item_id, who), ctx.now())
            return {"active_seconds": t.active_seconds, "state": t.state}

    @app.post("/timers/{item_id}/stop", dependencies=guarded)
    def timer_stop(item_id: str, who: str = Depends(analyst)) -> dict[str, Any]:
        with session_scope(ctx.engine) as s:
            rec = timers.stop(s, _mine(s, item_id, who), ctx.now())
            return {"active_seconds": rec.analyst_active_seconds,
                    "wall_seconds": (rec.ended_at - rec.started_at).total_seconds(),
                    "activity": rec.activity, "condition": rec.condition}

    @app.get("/costs/summary", dependencies=guarded)
    def costs_summary() -> dict[str, Any]:
        with session_scope(ctx.engine) as s:
            return costs.summary(s, ctx.cfg)

    @app.get("/audit", dependencies=guarded)
    def audit(limit: int = Query(default=100, ge=1, le=1000), entity_id: str | None = None
              ) -> dict[str, Any]:
        with session_scope(ctx.engine) as s:
            chain = verify_audit_chain(s)
            q = select(m.AuditEvent).order_by(m.AuditEvent.id.desc())
            if entity_id:
                q = q.where(m.AuditEvent.entity_id == entity_id)
            events = s.scalars(q.limit(limit)).all()
            return {"chain_ok": chain.ok, "checked": chain.checked,
                    "first_bad_id": chain.first_bad_id,
                    "events": [{"id": e.id, "ts": _iso(e.ts), "actor": e.actor,
                                "action": e.action, "entity_type": e.entity_type,
                                "entity_id": e.entity_id, "details": e.details,
                                "event_hash": e.event_hash} for e in events]}

    return app
