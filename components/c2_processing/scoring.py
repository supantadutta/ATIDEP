"""Transparent priority scoring (blueprint §17.2.5).

A pure function of documented inputs. Every component is on a 0-100 scale and is returned with
its weight, weighted contribution and the reason for its value, so the interface can show the
whole calculation. Parameters come from ``config/scoring.yaml`` and ``config/org_profile.yaml``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from app.config import ScoringConfig
from components.c2_processing.attack import AttackRelease
from schemas.intelligence import Priority, band_for_score, round_score


@dataclass
class ScoreInputs:
    reliability_rating: str                 # Admiralty A-F
    credibility_rating: int                 # Admiralty 1-6
    evidence_support_pct: float             # share of claims whose quotes verified, 0-100
    retrieved_at: datetime
    published_at: datetime | None = None
    primary_type: str = "behavior"          # ip | domain | url | hash | behavior
    independent_sources: int = 1
    technique_ids: list[str] = field(default_factory=list)
    products: list[str] = field(default_factory=list)
    platforms: list[str] = field(default_factory=list)      # for example ["windows"]
    sectors: list[str] = field(default_factory=list)
    candidate_logsources: list[str] = field(default_factory=list)
    cvss: float | None = None


@dataclass(frozen=True)
class Component:
    name: str
    value: float
    weight: float
    reason: str

    @property
    def weighted(self) -> float:
        return self.weight * self.value


@dataclass(frozen=True)
class PriorityResult:
    score: float
    components: tuple[Component, ...]
    priority: Priority

    def explanation(self) -> list[dict[str, Any]]:
        return [{"component": c.name, "value": round(c.value, 1), "weight": c.weight,
                 "contribution": round(c.weighted, 2), "reason": c.reason}
                for c in self.components]


def _norm(s: str) -> str:
    return " ".join(s.lower().replace("_", " ").split())


def _matches(needle: str, haystack: list[str]) -> bool:
    n = _norm(needle)
    return bool(n) and any(n in _norm(h) or _norm(h) in n for h in haystack if _norm(h))


def score_priority(inputs: ScoreInputs, cfg: ScoringConfig, org: dict[str, Any],
                   telemetry: dict[str, Any], attack: AttackRelease) -> PriorityResult:
    w = cfg.priority_weights
    rel = cfg.admiralty["reliability"]
    cred = cfg.admiralty["credibility"]
    if inputs.reliability_rating not in rel:
        raise ValueError(f"unknown reliability rating {inputs.reliability_rating!r}")
    if inputs.credibility_rating not in cred:
        raise ValueError(f"unknown credibility rating {inputs.credibility_rating!r}")

    sr = float(rel[inputs.reliability_rating])
    sr_reason = f"source reliability {inputs.reliability_rating}" + \
        (" (cannot be judged; neutral value)" if inputs.reliability_rating == "F" else "")

    support = max(0.0, min(100.0, inputs.evidence_support_pct))
    ic = cred[inputs.credibility_rating] * support / 100.0
    ic_reason = (f"information credibility {inputs.credibility_rating} "
                 f"({cred[inputs.credibility_rating]}) x {support:.0f}% of claims verified")

    # environmental relevance
    org_tech = list(org.get("applications", [])) + list(org.get("operating_systems", []))
    if any(_matches(p, org_tech) for p in inputs.products):
        tech, tech_why = 100.0, "an affected product or tool matches the organisation profile"
    elif any(_matches(p, org_tech) for p in inputs.platforms):
        tech, tech_why = 50.0, "only the platform matches the organisation profile"
    else:
        tech, tech_why = 0.0, "no product or platform matches the organisation profile"
    sources = telemetry.get("logsources", {})
    avail = [s for s in inputs.candidate_logsources if sources.get(s, {}).get("available")]
    tele, tele_why = (100.0, f"telemetry available: {avail[0]}") if avail else \
        (0.0, "no required telemetry is available")
    if _matches(str(org.get("sector", "")), inputs.sectors):
        sect, sect_why = 100.0, "the organisation's sector is targeted"
    elif not inputs.sectors:
        sect, sect_why = 50.0, "the report states no sector"
    else:
        sect, sect_why = 0.0, "other sectors are targeted"
    ew = cfg.environmental_relevance["weights"]
    er = ew["tech_match"] * tech + ew["telemetry_match"] * tele + ew["sector_match"] * sect
    er_reason = f"{tech_why}; {tele_why}; {sect_why}"

    # recency
    half_life = cfg.recency_half_life_days.get(inputs.primary_type)
    if half_life is None:
        raise ValueError(f"no recency half-life for type {inputs.primary_type!r}")
    ref = inputs.published_at or inputs.retrieved_at
    age_days = max(0.0, (inputs.retrieved_at - ref).total_seconds() / 86400.0)
    re_ = 100.0 * 0.5 ** (age_days / half_life)
    re_reason = f"{age_days:.0f} days old, half-life {half_life:g} days for {inputs.primary_type}"

    # cross-source correlation
    n = inputs.independent_sources
    cs_map = cfg.cross_source
    cs = float(cs_map["one_source"] if n <= 1 else cs_map["two_sources"] if n == 2
               else cs_map["three_or_more"])
    cs_reason = f"{max(n, 1)} independent source(s)"

    # potential impact
    tactic_values = cfg.potential_impact["tactic_values"]
    impact_candidates: list[tuple[float, str]] = []
    for tid in inputs.technique_ids:
        for shortname in (attack.get(tid).tactics if attack.get(tid) else ()):
            if shortname in tactic_values:
                impact_candidates.append((float(tactic_values[shortname]), f"tactic {shortname}"))
    if inputs.cvss is not None:
        impact_candidates.append((min(100.0, max(0.0, inputs.cvss * 10)), f"CVSS {inputs.cvss}"))
    if impact_candidates:
        pi, pi_reason = max(impact_candidates)
        pi_reason = f"highest of the item's impact sources: {pi_reason}"
    else:
        pi, pi_reason = float(cfg.potential_impact["default"]), "no tactic or CVSS mapped; default"

    comps = (
        Component("source_reliability", sr, w["source_reliability"], sr_reason),
        Component("intelligence_confidence", ic, w["intelligence_confidence"], ic_reason),
        Component("environmental_relevance", er, w["environmental_relevance"], er_reason),
        Component("recency", re_, w["recency"], re_reason),
        Component("cross_source_correlation", cs, w["cross_source_correlation"], cs_reason),
        Component("potential_impact", pi, w["potential_impact"], pi_reason),
    )
    score = round_score(sum(c.weighted for c in comps))
    priority = Priority(score=score, band=band_for_score(score),
                        components={c.name: round(c.value, 1) for c in comps})
    return PriorityResult(score=score, components=comps, priority=priority)
