"""One test per finding of the statistics audit of 23 October 2026: each pins the corrected
behaviour of the analysis that the pre-registered plan (blueprint section 29) requires."""

import csv
import json

import numpy as np
import pandas as pd
import pytest

from research.analysis import paired, proportions
from research.analysis.agreement import cohen_kappa, weighted_kappa
from research.analysis.crossover import first_exposure
from research.analysis.run import run_analysis
from research.analysis.sensitivity import rank_stability

RUN_COLS = ["item", "item_key", "condition", "run", "order_set", "budget_exceeded", "error",
            "cost.providers", "rules.sigma_rules", "rules.post_repair_valid",
            "rules.first_pass_valid"]
EFFORT_COLS = ["item_key", "condition", "activity", "analyst", "active_seconds", "disposition"]


def _write(path, cols, rows):
    with path.open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        w.writerows(rows)


def _export(tmp_path, minutes, *, stopped=(), order=None, runs_extra=(), ratings=None):
    """``minutes`` is [(manual, atidep)] per item; items in ``stopped`` had every B run hit the
    spend cap."""
    d = tmp_path / "export"
    d.mkdir()
    runs, effort = [], []
    for i, (a, b) in enumerate(minutes):
        name, key = f"I{i}", f"k{i}"
        o = (order[i] if order else ("X" if i % 2 else "Y"))
        for k in (1, 2, 3):
            runs.append({"item": name, "item_key": key, "condition": "B", "run": k,
                         "order_set": o, "budget_exceeded": "True" if i in stopped else "",
                         "error": "", "cost.providers": "ollama", "rules.sigma_rules": 1,
                         "rules.post_repair_valid": 1, "rules.first_pass_valid": 1})
        effort += [{"item_key": key, "condition": "A", "activity": "manual", "analyst": "a",
                    "active_seconds": a * 60, "disposition": "accepted"},
                   {"item_key": key, "condition": "B", "activity": "review_approval",
                    "analyst": "a", "active_seconds": b * 60, "disposition": "accepted"}]
    _write(d / "runs.csv", RUN_COLS, runs + list(runs_extra))
    _write(d / "analyst_effort.csv", EFFORT_COLS, effort)
    if ratings:
        _write(d / "ratings.csv", ["item", "condition", "rule_ref", "rater", "score"],
               [{"item": f"I{i}", "condition": c, "rule_ref": "r1", "rater": "R1", "score": s}
                for i, (sa, sb) in enumerate(ratings) for c, s in (("A", sa), ("B", sb))])
    return d


# ---- intention to treat ------------------------------------------------------------------------
def test_h1_keeps_items_whose_pipeline_runs_all_hit_the_spend_cap(tmp_path):
    minutes = [(60, 30)] * 7 + [(60, 90)] * 3
    res = run_analysis(_export(tmp_path, minutes, stopped={7, 8, 9}), tmp_path / "out")
    assert res["H1"]["analysis"] == "intention to treat" and res["H1"]["items"] == 10
    assert res["H1"]["supported_as_preregistered"] is False         # the 3 slow items count
    pp = res["H1_per_protocol"]
    assert pp["items"] == 7 and pp["excluded_items"] == ["I7", "I8", "I9"]


# ---- Holm decides the confirmatory verdicts ----------------------------------------------------
def test_a_verdict_needs_holm_even_when_the_unadjusted_criteria_are_met(tmp_path):
    rng = np.random.default_rng(1)
    a = rng.uniform(40, 80, 30)
    f = np.concatenate([rng.uniform(0.40, 0.68, 21), rng.uniform(1.2, 2.6, 9)])
    d = rng.normal(size=30)
    d = (d - d.mean()) / d.std(ddof=1) * 0.865 - 0.20                 # mean -0.20, SD 0.865
    ratings = [(3.6, 3.6 + x) for x in d]
    res = run_analysis(_export(tmp_path, list(zip(a, a * f, strict=True)), ratings=ratings),
                       tmp_path / "out")
    assert res["H4"]["non_inferior"] is True                             # unadjusted, 95%
    assert not any(v["reject"] for v in res["holm"].values())
    assert res["confirmatory_verdicts"] == {"H1": "not supported",
                                            "H4": "non-inferiority not shown"}
    assert res["H4"]["at_holm_level"]["non_inferior"] is False           # at 97.5%
    assert res["H4"]["at_holm_level"]["alpha"] == pytest.approx(0.025)


# ---- H2 on the primary model, with an item-clustered interval ----------------------------------
def test_h2_leaves_out_hosted_runs_and_clusters_by_item(tmp_path):
    hosted = [{"item": f"I{i}", "item_key": f"k{i}", "condition": "B", "run": 9,
               "order_set": "X", "budget_exceeded": "", "error": "",
               "cost.providers": "cloud-openai", "rules.sigma_rules": 5,
               "rules.post_repair_valid": 0, "rules.first_pass_valid": 0} for i in range(6)]
    res = run_analysis(_export(tmp_path, [(60, 30)] * 6, runs_extra=hosted), tmp_path / "out")
    h2 = res["H2"]
    assert h2["rules"] == 18 and h2["post_repair_rate"] == 1.0
    assert h2["hosted_model_runs_excluded"] == 6
    assert h2["post_repair_ci95_item_clustered"] is not None


def test_the_item_clustered_interval_is_wider_when_validity_is_a_property_of_the_item():
    k = [3] * 24 + [0] * 6                                  # 30 items x 3 runs
    n = [3] * 30
    clustered = proportions.clustered_interval(k, n, n_resamples=5000, seed=1)
    naive = proportions.clopper_pearson(72, 90)
    assert clustered[0] < naive[0] and clustered[1] > naive[1]
    with pytest.raises(ValueError):
        proportions.clopper_pearson(5, 4)


# ---- the crossover never takes the rest of the analysis down -----------------------------------
def test_a_single_sequence_is_reported_not_evaluable_and_the_analysis_is_still_written(tmp_path):
    res = run_analysis(_export(tmp_path, [(60, 30)] * 8, order=["X"] * 8), tmp_path / "out")
    assert "not_evaluable" in res["crossover"]
    assert (tmp_path / "out" / "analysis.json").exists() and "items" in res["H1"]


# ---- the registered stratified first-exposure comparison ---------------------------------------
def test_the_first_exposure_comparison_is_stratified_by_category():
    rng = np.random.default_rng(7)
    base = {"ioc": 30.0, "beh": 90.0, "mixed": 60.0, "unsuit": 8.0}
    rows = []
    for c, count in (("ioc", 10), ("beh", 10), ("mixed", 5), ("unsuit", 5)):
        for j in range(count):
            m = base[c] * rng.lognormal(0, 0.12)
            x = j % 2 == 0
            rows += [{"item": f"{c}{j}", "category": c, "condition": "A",
                      "order": "first" if x else "second", "minutes": m},
                     {"item": f"{c}{j}", "category": c, "condition": "B",
                      "order": "second" if x else "first",
                      "minutes": m * 0.75 * rng.lognormal(0, 0.05)}]
    r = first_exposure(pd.DataFrame(rows), seed=1, strata="category", n_resamples=500)
    assert r["unstratified"]["p"] > 0.05                       # swamped by category effort
    assert r["stratified"]["z"] < 0 and r["stratified"]["p"] < 0.001
    assert set(r["stratified"]["strata"]) == {"ioc", "beh", "mixed", "unsuit"}


# ---- BCa with ties, resamples and effect sizes --------------------------------------------------
def test_bca_counts_ties_with_the_estimate_as_half_below_it():
    rel = np.array([0.40] * 21 + [1 - x for x in np.linspace(1.3, 2.9, 9)])
    out = paired.bca(rel.reshape(-1, 1), lambda x: float(np.median(x)), n_resamples=5000,
                     seed=1, side="lower")
    assert out["lower"] == pytest.approx(0.40)


def test_h1_uses_the_registered_resamples_and_reports_an_effect_size():
    a = [60.0] * 10
    b = [30.0, 35, 40, 28, 33, 45, 50, 31, 29, 38]
    r = paired.h1(a, b, delta_t_pct=30, n_resamples=3000, seed=1)
    assert r["bootstrap_resamples"] == {"median_bound": 3000, "hodges_lehmann_ci": 3000}
    assert r["effect_size_rank_biserial"] == pytest.approx(1.0)
    assert paired.h4([3.0] * 5, [3.1, 2.9, 3.2, 3.0, 3.3], delta_q=0.5)["effect_size_dz"] > 0


# ---- undefined agreement is not perfect agreement ---------------------------------------------
def test_kappa_is_undefined_when_both_raters_use_one_category():
    assert cohen_kappa([True] * 10, [True] * 10) is None
    assert weighted_kappa([4] * 5, [4] * 5, categories=[1, 2, 3, 4, 5]) is None
    assert cohen_kappa([True, False, True], [True, False, False]) == pytest.approx(0.4)


def test_top_k_retention_is_one_when_nothing_changes_even_with_fewer_items_than_k():
    comps = np.array([[10, 20, 30, 40], [40, 30, 20, 10], [25, 25, 25, 25]], float)
    r = rank_stability(comps, np.array([0.4, 0.3, 0.2, 0.1]), spread=0.0, top_k=5, n_draws=20)
    assert r["top_k_retained_mean"] == pytest.approx(1.0)


def test_analysis_json_is_valid_json_without_nan(tmp_path):
    run_analysis(_export(tmp_path, [(60, 30)] * 8), tmp_path / "out")
    def refuse(token):
        raise AssertionError(f"analysis.json holds {token}, which is not JSON")
    json.loads((tmp_path / "out" / "analysis.json").read_text(), parse_constant=refuse)
