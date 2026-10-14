"""Metrics for one run (blueprint §28). Pure functions over what a run produced and the item's
ground truth; nothing here reads a model or a manager."""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import models as m
from app.services.pipeline import PipelineRun
from research.dataset.model import GroundTruth
from schemas.claim import ClaimKind, IndicatorContext
from schemas.detection_opportunity import GENERATING_DECISIONS, Decision

STATIC_GATES = ("G1", "G2", "G3", "G4", "G5", "G6", "G7")
CASE_INSENSITIVE = {"domain", "md5", "sha1", "sha256", "ipv4", "ipv6"}


def prf(pred: set, gold: set) -> dict[str, float]:
    tp = len(pred & gold)
    p = tp / len(pred) if pred else (1.0 if not gold else 0.0)
    r = tp / len(gold) if gold else 1.0
    f1 = 2 * p * r / (p + r) if p + r else 0.0
    return {"precision": round(p, 4), "recall": round(r, 4), "f1": round(f1, 4), "tp": tp,
            "fp": len(pred - gold), "fn": len(gold - pred)}


def _parent(t: str) -> str:
    return t.split(".")[0]


def technique_scores(pred: set[str], gold: set[str]) -> dict[str, float]:
    """Set precision/recall/F1 with partial credit: 1 for the same ID, 0.5 when one is the
    parent of the other (T1059 against T1059.001). Each ID is matched at most once."""
    pred_left, gold_left = set(pred), set(gold)
    credit = 0.0
    for p in sorted(pred & gold):
        credit += 1.0
        pred_left.discard(p)
        gold_left.discard(p)
    for p in sorted(pred_left):
        match = next((g for g in sorted(gold_left) if _parent(g) == _parent(p)), None)
        if match:
            credit += 0.5
            gold_left.discard(match)
    pr = credit / len(pred) if pred else (1.0 if not gold else 0.0)
    rc = credit / len(gold) if gold else 1.0
    f1 = 2 * pr * rc / (pr + rc) if pr + rc else 0.0
    return {"precision": round(pr, 4), "recall": round(rc, 4), "f1": round(f1, 4)}


def canon(kind: str, value: str) -> tuple[str, str]:
    v = value.strip()
    return kind, v.lower() if kind in CASE_INSENSITIVE else v


# ---- extraction ------------------------------------------------------------------------------
def extraction_metrics(session: Session, gt: GroundTruth | None) -> dict[str, Any]:
    rows = session.execute(
        select(m.Claim, m.EvidenceSegment).join(
            m.EvidenceSegment, m.EvidenceSegment.evidence_id == m.Claim.evidence_id)).all()
    verified = [(c, e) for c, e in rows if e.verified]
    total = len(rows)
    out: dict[str, Any] = {
        "claims": total, "unsupported_claims": total - len(verified),
        "unsupported_rate": round((total - len(verified)) / total, 4) if total else 0.0}
    usable_ind = {canon(c.type, c.value or "") for c, e in verified
                  if c.kind == ClaimKind.INDICATOR.value and c.valid
                  and c.context != IndicatorContext.REFERENCE_ONLY.value}
    techniques = {c.attack_id for c, e in verified if c.attack_id}
    out["indicators_found"] = len(usable_ind)
    out["techniques_found"] = sorted(techniques)
    if gt is not None:
        out["indicators"] = prf(usable_ind, {canon(i.type, i.value) for i in gt.indicators})
        out["techniques"] = technique_scores(techniques, set(gt.techniques))
    return out


# ---- opportunity -----------------------------------------------------------------------------
def opportunity_metrics(session: Session, gt: GroundTruth | None) -> dict[str, Any]:
    opps = list(session.scalars(select(m.DetectionOpportunity)))
    decisions = sorted({o.decision for o in opps})
    detectable = any(Decision(d) in GENERATING_DECISIONS for d in decisions)
    out: dict[str, Any] = {
        "decisions": decisions, "detectable_predicted": detectable,
        "opportunities": len(opps), "overrides": sum(o.override_applied for o in opps),
        "override_rate": round(sum(o.override_applied for o in opps) / len(opps), 4)
        if opps else 0.0}
    if gt is not None:
        allowed = {d.value for d in gt.decisions}
        out["detectable_correct"] = detectable == gt.detectable
        out["decision_set_match"] = round(
            len(set(decisions) & allowed) / len(set(decisions) | allowed), 4)
        out["decisions_allowed"] = sorted(allowed)
    return out


# ---- rules -----------------------------------------------------------------------------------
def rule_metrics(run: PipelineRun) -> dict[str, Any]:
    sigma = [r for r in run.rules if r.kind == "sigma" and r.rule_id]
    bundles = [r for r in run.rules if r.kind == "ioc_list" and r.rule_id]

    def static_ok(r) -> bool:
        return r.outcome is not None and not set(r.failed_gates) & set(STATIC_GATES)

    first_bad = [r for r in sigma if r.first_pass_valid is False]
    repaired = [r for r in first_bad if static_ok(r)]
    matched = [r.events["matched"] for r in sigma if r.events]
    return {
        "rules": len(run.rules), "sigma_rules": len(sigma), "ioc_bundles": len(bundles),
        "first_pass_valid": sum(bool(r.first_pass_valid) for r in sigma),
        "post_repair_valid": sum(static_ok(r) for r in sigma),
        "repairs_used": sum(r.repairs_used or 0 for r in sigma),
        "repair_attempted": len(first_bad), "repair_succeeded": len(repaired),
        "validated": sum(r.outcome == "validated" for r in run.rules),
        "blocked": sum(r.outcome == "blocked" for r in run.rules),
        "invented_field": sum(any(c == "G5_UNKNOWN_FIELD" for c in r.first_attempt_codes)
                              for r in sigma),
        "failed_gates": sorted({g for r in run.rules for g in r.failed_gates}),
        "skipped": [r.skipped for r in run.rules if r.skipped],
        "positives_matched": sum(x["positive"] for x in matched),
        "negatives_matched": sum(x["negative"] + x["lookalike"] for x in matched),
        "attempts": sum(r.attempts for r in sigma)}


# ---- cost ------------------------------------------------------------------------------------
def cost_metrics(session: Session) -> dict[str, Any]:
    """Measured model usage for one run, kept as raw quantities (no prices). Money is computed
    offline from these and the price register (``research.economics``)."""
    by_agent: dict[str, dict[str, float]] = {}
    sources: dict[str, int] = {}
    providers: set[str] = set()
    models: set[str] = set()
    compute_ms = 0
    compute_reported = replayed = 0
    for r in session.scalars(select(m.ModelRun)):
        a = by_agent.setdefault(r.agent, {"calls": 0, "input_tokens": 0, "output_tokens": 0,
                                          "latency_ms": 0, "schema_invalid": 0, "cost": 0.0})
        a["calls"] += 1
        a["input_tokens"] += r.input_tokens
        a["output_tokens"] += r.output_tokens
        a["latency_ms"] += r.latency_ms or 0
        a["schema_invalid"] += 0 if r.schema_valid else 1
        a["cost"] += r.estimated_cost or 0.0
        sources[r.usage_source] = sources.get(r.usage_source, 0) + 1
        providers.add(r.provider)
        models.add(r.model)
        replayed += 1 if r.replayed else 0
        if r.compute_ms is not None:
            compute_ms += r.compute_ms
            compute_reported += 1
    calls = int(sum(a["calls"] for a in by_agent.values()))
    return {"agents": by_agent,
            "input_tokens": int(sum(a["input_tokens"] for a in by_agent.values())),
            "output_tokens": int(sum(a["output_tokens"] for a in by_agent.values())),
            "model_calls": calls,
            "model_latency_ms": int(sum(a["latency_ms"] for a in by_agent.values())),
            # None, not 0, when the provider reported no compute time for any call
            "model_compute_ms": compute_ms if compute_reported else None,
            "calls_with_compute_time": compute_reported, "replayed_calls": replayed,
            "usage_sources": dict(sorted(sources.items())),
            "providers": sorted(providers), "models": sorted(models),
            "estimated_cost": round(sum(a["cost"] for a in by_agent.values()), 6)}


def time_kinds(stage_seconds: dict[str, float], model_latency_ms: int, wall_seconds: float
               ) -> dict[str, float]:
    """The machine side of the four kinds of time (blueprint §22.2). Analyst active time comes
    from the timer, not from here. ``model_wait_seconds`` is what the pipeline spent waiting for
    the model; ``automated_seconds`` is the rest of the stage time (deterministic code, I/O,
    validation); ``wall_seconds`` is the whole run, including anything outside the stages."""
    stages = float(sum(stage_seconds.values()))
    wait = model_latency_ms / 1000.0
    return {"wall_seconds": round(wall_seconds, 3), "stage_seconds": round(stages, 3),
            "model_wait_seconds": round(wait, 3),
            "automated_seconds": round(max(0.0, stages - wait), 3)}
