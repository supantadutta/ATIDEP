"""Quality score: orders the review queue, nothing else (blueprint §17.4.2).

It exists only for rules that already passed every hard gate, and it is never an experimental
outcome: a system must not be judged by the measure it optimises. Each component is 0-100 and
the weights come from ``config/scoring.yaml``.
"""

from __future__ import annotations

from decimal import ROUND_HALF_UP, Decimal
from typing import Any

from app.config import ScoringConfig
from components.c4_validation.event_gates import GENERIC_FIELDS
from components.c4_validation.sigma_ir import RuleIR
from schemas.intelligence import round_score

SPECIFICITY_BY_TERMS = {1: 40.0, 2: 70.0, 3: 90.0}


def _specificity(ir: RuleIR) -> float:
    weakest = min(sum(1 for m, neg in c if not neg and m.field not in GENERIC_FIELDS) or
                  sum(1 for _, neg in c if not neg) for c in ir.clauses)
    return SPECIFICITY_BY_TERMS.get(weakest, 100.0 if weakest > 3 else 0.0)


def _attack_precision(tags: list[str]) -> float:
    import re

    techniques = [t for t in tags if re.match(r"^attack\.t\d{4}(\.\d{3})?$", t, re.I)]
    if not techniques:
        return 0.0
    return sum(100.0 if "." in t[len("attack."):] else 70.0 for t in techniques) / len(techniques)


def quality_components(*, ir: RuleIR, evidence_stats: dict[str, int], falsepositives: list[str],
                       triage_present: bool, tags: list[str], counts: dict[str, int],
                       warnings: int) -> dict[str, float]:
    quoted, assumed = evidence_stats.get("quoted", 0), evidence_stats.get("assumed", 0)
    coverage = 100.0 if quoted + assumed == 0 else 100.0 * quoted / (quoted + assumed)
    fp = min(100.0, 40.0 * min(len(falsepositives), 2) + (20.0 if triage_present else 0.0))
    tests = 100.0 * (min(counts.get("positive", 0), 3) + min(counts.get("negative", 0), 3)
                     + min(counts.get("lookalike", 0), 3)) / 9.0
    return {"evidence_coverage": coverage, "specificity": _specificity(ir), "fp_analysis": fp,
            "attack_mapping_precision": _attack_precision(tags), "test_coverage": tests,
            "lint_cleanliness": max(0.0, 100.0 - 25.0 * warnings)}


def quality_score(components: dict[str, float], cfg: ScoringConfig) -> int:
    w = cfg.quality_ranking_weights
    if set(components) != set(w):
        raise ValueError(f"components must be exactly {sorted(w)}")
    total = round_score(sum(w[k] * components[k] for k in w))      # one decimal, half up
    return int(Decimal(str(total)).quantize(Decimal("1"), rounding=ROUND_HALF_UP))


def describe(components: dict[str, float], cfg: ScoringConfig) -> list[dict[str, Any]]:
    w = cfg.quality_ranking_weights
    return [{"component": k, "value": round(v, 1), "weight": w[k],
             "contribution": round(w[k] * v, 2)} for k, v in components.items()]
