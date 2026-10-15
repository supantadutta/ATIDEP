"""Inter-rater reliability for the blinded rubric (blueprint §27.8).

Two files may be present in the export folder:

* ``ratings_dimensions.csv`` (``rule_ref, rater, dimension, score``): the integer 1 to 5 score of
  each rater on each of the five rubric dimensions;
* ``ratings.csv`` (``item, condition, rule_ref, rater, score``): each rater's rule-level score
  (the mean of that rater's dimension scores), which feeds the H4 comparison.

Reported: quadratic-weighted kappa per dimension and rater pair, and the number of rule and
dimension cells on which two raters differ by more than one point (the cells the pre-declared
discussion procedure applies to); and ICC(2,1) on the rule-level scores over the rules every rater
scored. Nothing is computed from fewer than three rules, and a missing file is reported as missing.
"""

from __future__ import annotations

import csv
from collections import defaultdict
from itertools import combinations
from pathlib import Path
from statistics import fmean
from typing import Any

import numpy as np

from research.analysis.agreement import icc_2_1, weighted_kappa

MIN_RULES = 3
SCALE = [1, 2, 3, 4, 5]


def _rows(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def dimension_agreement(path: Path) -> dict[str, Any]:
    cell: dict[tuple[str, str], dict[str, int]] = defaultdict(dict)    # (rule, dim) -> rater: score
    for r in _rows(path):
        s = float(r["score"])
        if s != int(s) or int(s) not in SCALE:
            raise ValueError(f"rubric scores are integers 1 to 5, got {r['score']!r}")
        cell[(r["rule_ref"], r["dimension"])][r["rater"]] = int(s)
    raters = sorted({k for v in cell.values() for k in v})
    dims = sorted({d for _, d in cell})
    out: dict[str, Any] = {"raters": raters, "dimensions": {}}
    for d in dims:
        pairs: dict[str, Any] = {}
        for a, b in combinations(raters, 2):
            both = [(v[a], v[b]) for (_, dd), v in cell.items() if dd == d and a in v and b in v]
            if len(both) >= MIN_RULES:
                x, y = zip(*both, strict=True)
                pairs[f"{a}|{b}"] = {"rules": len(both),
                                     "weighted_kappa": weighted_kappa(list(x), list(y),
                                                                      categories=SCALE),
                                     "differ_by_more_than_one": sum(abs(p - q) > 1
                                                                    for p, q in both)}
        out["dimensions"][d] = {
            "pairs": pairs,
            "mean_weighted_kappa": fmean(p["weighted_kappa"] for p in pairs.values())
            if pairs else None}
    return out


def rule_icc(path: Path) -> dict[str, Any]:
    by_rule: dict[tuple[str, str, str], dict[str, float]] = defaultdict(dict)
    for r in _rows(path):
        by_rule[(r["item"], r["condition"], r["rule_ref"])][r["rater"]] = float(r["score"])
    raters = sorted({k for v in by_rule.values() for k in v})
    complete = [v for v in by_rule.values() if all(k in v for k in raters)]
    out: dict[str, Any] = {"raters": raters, "rules_rated": len(by_rule),
                           "rules_rated_by_all": len(complete)}
    if len(raters) < 2 or len(complete) < MIN_RULES:
        out["icc_2_1"] = None
        out["not_evaluable"] = (f"ICC(2,1) needs at least two raters and {MIN_RULES} rules scored "
                                "by all of them")
        return out
    matrix = np.array([[v[k] for k in raters] for v in complete])
    out["icc_2_1"] = icc_2_1(matrix)
    return out


def rater_agreement(export_dir: Path | str) -> dict[str, Any]:
    d = Path(export_dir)
    res: dict[str, Any] = {}
    dims, rules = d / "ratings_dimensions.csv", d / "ratings.csv"
    res["dimensions"] = (dimension_agreement(dims) if dims.exists()
                         else {"not_evaluable": "ratings_dimensions.csv is missing"})
    res["rules"] = (rule_icc(rules) if rules.exists()
                    else {"not_evaluable": "ratings.csv is missing"})
    return res
