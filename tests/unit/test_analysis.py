"""The statistical building blocks, against known values and simulated data."""

import numpy as np
import pandas as pd
import pytest
from scipy import stats

from research.analysis.agreement import cohen_kappa, icc_2_1, jaccard, weighted_kappa
from research.analysis.crossover import first_exposure, mixed_model, sequence_balance
from research.analysis.paired import bca, h1, h4, hodges_lehmann, holm, wilcoxon
from research.analysis.power import paired_power
from research.analysis.proportions import clopper_pearson, clopper_pearson_upper, wilson
from research.analysis.sensitivity import rank_stability


# ---- proportions ------------------------------------------------------------------------------------
def test_exact_upper_bounds_match_the_blueprints_numbers():
    assert clopper_pearson_upper(0, 40) == pytest.approx(0.0721, abs=1e-4)
    assert clopper_pearson_upper(0, 30) == pytest.approx(0.0950, abs=1e-3)
    assert clopper_pearson_upper(0, 12) == pytest.approx(0.2209, abs=1e-3)
    assert clopper_pearson_upper(0, 40) == pytest.approx(1 - 0.05 ** (1 / 40))
    assert clopper_pearson_upper(40, 40) == 1.0 and clopper_pearson_upper(0, 0) == 1.0
    assert 0.0721 < clopper_pearson_upper(1, 40) < 0.13                 # one escape raises it


def test_intervals_for_three_in_ten_match_the_published_values():
    lo, hi = clopper_pearson(3, 10)
    assert (lo, hi) == (pytest.approx(0.0667, abs=1e-3), pytest.approx(0.6525, abs=1e-3))
    wl, wh = wilson(3, 10)
    assert (wl, wh) == (pytest.approx(0.1078, abs=1e-3), pytest.approx(0.6032, abs=1e-3))
    assert clopper_pearson(0, 10)[0] == 0.0 and clopper_pearson(10, 10)[1] == 1.0


# ---- estimators --------------------------------------------------------------------------------------------
def test_hodges_lehmann_is_the_median_of_walsh_averages():
    assert hodges_lehmann([1, 2, 3]) == 2.0
    assert hodges_lehmann([0, 10]) == 5.0                  # averages 0, 5, 10
    assert hodges_lehmann([5.0]) == 5.0


def test_wilcoxon_matches_scipy_and_handles_all_zero_differences():
    d = [1.2, -0.3, 2.2, 1.9, 0.8, 1.5, 2.8, 0.4]
    assert wilcoxon(d)["p"] == pytest.approx(stats.wilcoxon(d, alternative="greater").pvalue)
    z = wilcoxon([0, 0, 0])
    assert z["p"] == 1.0 and z["n_nonzero"] == 0


def test_bca_is_deterministic_and_close_to_the_t_bound_for_well_behaved_data():
    rng = np.random.default_rng(3)
    x = rng.normal(1.0, 1.0, size=(40, 1))
    a = bca(x, lambda r: float(r.mean()), n_resamples=2000, seed=11, side="lower")
    b = bca(x, lambda r: float(r.mean()), n_resamples=2000, seed=11, side="lower")
    assert a == b
    t_bound = x.mean() - stats.t.ppf(0.95, 39) * x.std(ddof=1) / np.sqrt(40)
    assert a["lower"] == pytest.approx(t_bound, abs=0.12) and a["lower"] < a["estimate"]
    two = bca(x, lambda r: float(r.mean()), n_resamples=2000, seed=11, side="two-sided")
    assert two["lower"] < two["estimate"] < two["upper"]


# ---- H1 ------------------------------------------------------------------------------------------------------
def test_h1_is_supported_when_the_median_reduction_clears_the_margin_and_its_bound_is_positive():
    rng = np.random.default_rng(5)
    manual = rng.uniform(40, 80, 30)
    atidep = manual * rng.uniform(0.4, 0.6, 30)                    # about a 50% reduction
    r = h1(list(manual), list(atidep), delta_t_pct=30, n_resamples=1000, seed=1)
    assert r["median_relative_reduction"] == pytest.approx(0.5, abs=0.07)
    assert r["supported_as_preregistered"] and r["lower_bound_reaches_delta_t"]
    assert r["wilcoxon_log_ratio"]["p"] < 1e-4 and r["hodges_lehmann_ratio"] > 1.5
    assert r["hodges_lehmann_ratio_ci95"][0] < r["hodges_lehmann_ratio"] < \
        r["hodges_lehmann_ratio_ci95"][1]


def test_h1_is_not_supported_for_a_small_reduction_and_the_two_readings_can_differ():
    rng = np.random.default_rng(6)
    manual = rng.uniform(40, 80, 30)
    small = h1(list(manual), list(manual * 0.9), delta_t_pct=30, n_resamples=500, seed=1)
    assert not small["supported_as_preregistered"]              # a 10% reduction is below 30%
    mid = h1(list(manual), list(manual * rng.uniform(0.55, 0.85, 30)), delta_t_pct=30,
             n_resamples=1000, seed=1)
    # the pre-registered rule needs the bound above 0; the stricter reading needs it above 30%
    assert mid["lower_bound_95_one_sided"] > 0
    assert mid["supported_as_preregistered"] == (mid["median_relative_reduction"] >= 0.3)


def test_h1_refuses_unmatched_or_impossible_inputs():
    with pytest.raises(ValueError):
        h1([1, 2, 3], [1, 2], delta_t_pct=30)
    with pytest.raises(ValueError):
        h1([1, 2, 3], [1, 0, 1], delta_t_pct=30)
    with pytest.raises(ValueError):
        h1([1, 2], [1, 2], delta_t_pct=30)


# ---- H4 ------------------------------------------------------------------------------------------------------
def test_h4_non_inferiority_uses_the_lower_bound_not_a_no_difference_test():
    rng = np.random.default_rng(8)
    manual = rng.normal(3.5, 0.6, 30)
    atidep = manual + rng.normal(0.05, 0.4, 30)
    r = h4(list(manual), list(atidep), delta_q=0.5, n_resamples=1000, seed=2)
    assert r["non_inferior"] and r["lower_bound_95_one_sided"] > -0.5
    assert r["p_tost_lower_arm"] < 0.05 and r["bca_agrees"]
    worse = h4(list(manual), list(manual - 0.7 + rng.normal(0, 0.3, 30)), delta_q=0.5,
               n_resamples=500, seed=2)
    assert not worse["non_inferior"] and worse["p_tost_lower_arm"] > 0.05


def test_h4_t_bound_is_the_textbook_formula():
    a, b = [3.0, 3.5, 4.0, 3.2, 3.8], [3.1, 3.4, 4.2, 3.0, 4.0]
    r = h4(a, b, delta_q=0.5, n_resamples=200, seed=0)
    d = np.array(b) - np.array(a)
    expected = d.mean() - stats.t.ppf(0.95, 4) * d.std(ddof=1) / np.sqrt(5)
    assert r["lower_bound_95_one_sided"] == pytest.approx(expected)


# ---- Holm ------------------------------------------------------------------------------------------------------
def test_holm_step_down_on_a_worked_example():
    out = holm({"a": 0.01, "b": 0.04, "c": 0.03}, alpha=0.05)
    assert out["a"]["reject"] and not out["c"]["reject"] and not out["b"]["reject"]
    assert out["a"]["p_holm"] == pytest.approx(0.03)
    assert out["c"]["p_holm"] == pytest.approx(0.06) and out["b"]["p_holm"] == pytest.approx(0.06)


def test_holm_for_the_two_confirmatory_tests():
    both = holm({"H1": 0.004, "H4": 0.04}, alpha=0.05)
    assert both["H1"]["reject"] and both["H4"]["reject"]               # 0.004 <= 0.025, 0.04 <= 0.05
    one = holm({"H1": 0.03, "H4": 0.04}, alpha=0.05)
    assert not one["H1"]["reject"] and not one["H4"]["reject"]         # 0.03 > 0.025 stops


# ---- agreement -------------------------------------------------------------------------------------------------
def test_kappa_on_a_known_table():
    a = [1] * 25 + [0] * 25
    b = [1] * 20 + [0] * 5 + [1] * 10 + [0] * 15                      # [[20,5],[10,15]] -> 0.4
    assert cohen_kappa(a, b) == pytest.approx(0.4)
    assert cohen_kappa(["x", "y", "x"], ["x", "y", "x"]) == 1.0
    with pytest.raises(ValueError):
        cohen_kappa([], [])


def test_weighted_kappa_penalises_distant_disagreements_more():
    a = [1, 2, 3, 4, 5, 3, 2, 4]
    near = [1, 2, 3, 4, 4, 3, 2, 5]
    far = [1, 2, 3, 4, 1, 3, 2, 5]
    assert weighted_kappa(a, a) == 1.0
    assert weighted_kappa(a, near, categories=[1, 2, 3, 4, 5]) > weighted_kappa(
        a, far, categories=[1, 2, 3, 4, 5])


def test_icc_2_1_matches_shrout_and_fleiss():
    x = np.array([[9, 2, 5, 8], [6, 1, 3, 2], [8, 4, 6, 8], [7, 1, 2, 6], [10, 5, 6, 9],
                  [6, 2, 4, 7]])
    assert icc_2_1(x) == pytest.approx(0.29, abs=0.005)               # Shrout and Fleiss (1979)


def test_jaccard_edges():
    assert jaccard({"T1059.001"}, {"T1059.001"}) == 1.0
    assert jaccard(set(), set()) == 1.0 and jaccard({"a"}, {"b"}) == 0.0
    assert jaccard({"a", "b"}, {"b", "c"}) == pytest.approx(1 / 3)


# ---- crossover -------------------------------------------------------------------------------------------------
def crossover_frame(n=30, true_ratio=0.5, order_effect=0.9, seed=4):
    rng = np.random.default_rng(seed)
    rows = []
    for i in range(n):
        base = rng.lognormal(4.0, 0.4)
        manual_first = i % 2 == 0
        for cond in ("A", "B"):
            order = "first" if (cond == "A") == manual_first else "second"
            m = base * (true_ratio if cond == "B" else 1.0) * (order_effect if order == "second"
                                                               else 1.0)
            rows.append({"item": f"I{i}", "condition": cond, "order": order,
                         "minutes": m * rng.lognormal(0, 0.1)})
    return pd.DataFrame(rows)


def test_the_mixed_model_recovers_the_time_ratio_and_the_order_effect():
    df = crossover_frame()
    r = mixed_model(df)
    assert r["condition_B_vs_A"]["time_ratio"] == pytest.approx(0.5, abs=0.08)
    assert r["order_second_vs_first"]["coef"] == pytest.approx(np.log(0.9), abs=0.08)
    lo, hi = r["condition_B_vs_A"]["ci95"]
    assert lo < r["condition_B_vs_A"]["coef"] < hi and r["converged"]
    assert sequence_balance(df) == {"manual_first": 15, "atidep_first": 15}


def test_the_first_exposure_comparison_is_unpaired_and_free_of_carry_over():
    r = first_exposure(crossover_frame(n=60, order_effect=0.6), n_resamples=500, seed=1)
    assert r["n_manual_first"] == r["n_atidep_first"] == 30
    u = r["unstratified"]
    assert u["time_ratio_hl"] == pytest.approx(0.5, abs=0.2) and u["p"] < 0.01
    assert u["time_ratio_ci95"][0] < u["time_ratio_hl"] < u["time_ratio_ci95"][1]
    assert "not_evaluable" in r["stratified"]                 # no categories in this frame


# ---- sensitivity and power ---------------------------------------------------------------------------------------
def test_rank_stability_is_perfect_for_zero_perturbation_and_falls_with_more():
    rng = np.random.default_rng(2)
    comps = rng.uniform(0, 100, size=(30, 6))
    w = np.array([0.25, 0.2, 0.2, 0.15, 0.1, 0.1])
    still = rank_stability(comps, w, n_draws=50, spread=0.0, seed=1)
    assert still["tau_min"] == pytest.approx(1.0) and still["top_k_retained_mean"] == 1.0
    mild = rank_stability(comps, w, n_draws=300, spread=0.2, seed=1)
    wild = rank_stability(comps, w, n_draws=300, spread=1.5, seed=1)
    assert 0.8 < mild["tau_mean"] < 1.0 and wild["tau_mean"] < mild["tau_mean"]


def test_power_rises_with_effect_size_and_matches_the_blueprints_order_of_magnitude():
    low = paired_power(0.3, 30, test="t", sims=1500, seed=1)
    mid = paired_power(0.5, 30, test="t", sims=1500, seed=1)
    high = paired_power(0.7, 30, test="t", sims=1500, seed=1)
    assert low < mid < high
    assert mid == pytest.approx(0.75, abs=0.07) and high == pytest.approx(0.96, abs=0.04)


# ---- the runner, on a synthetic export ---------------------------------------------------------------------------
def make_export(tmp_path, n=24, ratio=0.5, with_ratings=True):
    import csv
    rng = np.random.default_rng(9)
    d = tmp_path / "export"
    d.mkdir(parents=True)
    cols = ["item", "item_key", "condition", "run", "order_set", "cost.tokens_reliable",
            "cost.time.automated_seconds", "cost.time.model_wait_seconds", "rules.sigma_rules",
            "rules.ioc_bundles", "rules.assessed", "rules.validated", "rules.first_pass_valid",
            "rules.post_repair_valid", "budget_exceeded"]
    runs, sessions, ratings = [], [], []
    for i in range(n):
        item, key = f"I{i}", f"key{i}"
        runs.append({"item": item, "item_key": key, "condition": "B", "run": 1,
                     "order_set": "X" if i % 2 == 0 else "Y", "cost.tokens_reliable": "True",
                     "cost.time.automated_seconds": 30, "cost.time.model_wait_seconds": 60,
                     "rules.sigma_rules": 1, "rules.ioc_bundles": 0, "rules.assessed": 1,
                     "rules.validated": 1, "rules.first_pass_valid": 1 if i % 4 else 0,
                     "rules.post_repair_valid": 1, "budget_exceeded": ""})
        base = float(rng.uniform(40, 80))
        manual_first = i % 2 == 0
        for cond, mins in (("A", base * (1.0 if manual_first else 0.9)),
                           ("B", base * ratio * (0.9 if manual_first else 1.0))):
            sessions.append({"item_key": key, "condition": cond, "activity": "x", "analyst": "a",
                             "active_seconds": mins * 60, "wall_seconds": mins * 60,
                             "idle_capped_gaps": 0, "idle_capped_seconds": 0,
                             "disposition": "accepted"})
            q = float(np.clip(rng.normal(3.6, 0.5) + (0.05 if cond == "B" else 0.0), 1, 5))
            for rater in ("r1", "r2"):
                ratings.append({"item": item, "condition": cond, "rule_ref": f"{cond}-{i}",
                                "rater": rater, "score": round(q + rng.normal(0, 0.1), 2)})
    for name, cols_, rows in (("runs.csv", cols, runs), ("analyst_effort.csv", list(sessions[0]),
                                                          sessions)):
        with (d / name).open("w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=cols_)
            w.writeheader()
            w.writerows(rows)
    if with_ratings:
        with (d / "ratings.csv").open("w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=list(ratings[0]))
            w.writeheader()
            w.writerows(ratings)
    return d


def test_the_runner_computes_the_confirmatory_family_and_the_secondary_summaries(tmp_path):
    from research.analysis.run import run_analysis
    out = tmp_path / "out"
    adv = tmp_path / "adv.json"
    adv.write_text('{"conditions": {"B": {"defective": {"n": 40, "escapes": 0}}}}')
    res = run_analysis(make_export(tmp_path), out, adversarial_summary=adv)
    assert res["H1"]["supported_as_preregistered"] and res["H1"]["median_relative_reduction"] > 0.4
    assert res["H4"]["non_inferior"] and res["items_with_minutes_in_both_conditions"] == 24
    assert set(res["holm"]) == {"H1", "H4"} and all(v["reject"] for v in res["holm"].values())
    assert res["crossover"]["mixed_model"]["condition_B_vs_A"]["time_ratio"] < 0.7
    assert res["H2"]["post_repair_rate"] == 1.0 and res["H2"]["met"]
    assert res["H2"]["first_pass_rate"] == pytest.approx(18 / 24)
    assert res["H3"]["escapes"] == 0 and res["H3"]["upper_95"] == pytest.approx(0.0721, abs=1e-4)
    # zero rule escapes alone does not make H3 met: no injection results, no completeness
    # record and no verified run manifest are all blockers
    assert res["H3"]["met"] is None and len(res["H3"]["blockers"]) >= 3
    import json
    manifest = json.loads((out / "manifest.json").read_text())
    assert "runs.csv" in manifest["inputs"] and manifest["versions"]["scipy"]
    assert len(manifest["config_experiment_sha256"]) == 64


def test_the_runner_says_not_evaluable_instead_of_inventing_missing_data(tmp_path):
    from research.analysis.run import run_analysis
    res = run_analysis(make_export(tmp_path, with_ratings=False), tmp_path / "out")
    assert "not_evaluable" in res["H4"] and "ratings.csv" in res["H4"]["not_evaluable"]
    assert res["holm"] == {} and "incomplete" in res["holm_note"]
    assert "not_evaluable" in res["H3"]
    tiny = run_analysis(make_export(tmp_path / "tiny", n=2), tmp_path / "o2")
    assert "not_evaluable" in tiny["H1"] and "not_evaluable" in tiny["crossover"]


# ---- inter-rater reliability (blueprint §27.8) ---------------------------------------------
def _write_csv(path, header, rows):
    import csv as _csv
    with path.open("w", newline="") as fh:
        w = _csv.writer(fh)
        w.writerow(header)
        w.writerows(rows)


def test_dimension_agreement_counts_gaps_of_more_than_one_point(tmp_path):
    from research.analysis.raters import dimension_agreement
    rows = []
    # four rules, one dimension: r1 = 1,2,3,4 ; r2 = 1,2,3,4 except rule 4 where r2 gives 2
    for k, (a, b) in enumerate([(1, 1), (2, 2), (3, 3), (4, 2)], 1):
        rows += [[f"R{k}", "r1", "D-A", a], [f"R{k}", "r2", "D-A", b]]
    p = tmp_path / "ratings_dimensions.csv"
    _write_csv(p, ["rule_ref", "rater", "dimension", "score"], rows)
    res = dimension_agreement(p)
    pair = res["dimensions"]["D-A"]["pairs"]["r1|r2"]
    assert pair["rules"] == 4 and pair["differ_by_more_than_one"] == 1
    # quadratic weights on a 5-point scale: |4-2| = 2 steps -> weight (2/4)^2 = 0.25
    exp_w = 0.25
    # observed weighted disagreement = 0.25/4 ; chance from the marginals
    import numpy as np
    m = np.zeros((5, 5))
    for a, b in [(1, 1), (2, 2), (3, 3), (4, 2)]:
        m[a - 1, b - 1] += 1
    i, j = np.indices((5, 5))
    w = (np.abs(i - j) / 4) ** 2
    expected = np.outer(m.sum(1), m.sum(0)) / 4
    kappa = 1 - (w * m).sum() / (w * expected).sum()
    assert pair["weighted_kappa"] == pytest.approx(kappa) and exp_w == w[3, 1]
    assert 0 < pair["weighted_kappa"] < 1


def test_dimension_agreement_refuses_non_integer_or_out_of_scale_scores(tmp_path):
    from research.analysis.raters import dimension_agreement
    p = tmp_path / "ratings_dimensions.csv"
    _write_csv(p, ["rule_ref", "rater", "dimension", "score"], [["R1", "r1", "D-A", 3.5]])
    with pytest.raises(ValueError):
        dimension_agreement(p)
    _write_csv(p, ["rule_ref", "rater", "dimension", "score"], [["R1", "r1", "D-A", 6]])
    with pytest.raises(ValueError):
        dimension_agreement(p)


def test_rule_icc_uses_only_rules_every_rater_scored_and_needs_three(tmp_path):
    import numpy as np

    from research.analysis.agreement import icc_2_1
    from research.analysis.raters import rule_icc
    rows = []
    scores = {"R1": (2.0, 2.2), "R2": (3.0, 3.4), "R3": (4.0, 3.8), "R4": (5.0, 4.6)}
    for ref, (a, b) in scores.items():
        rows += [["I1", "A", ref, "r1", a], ["I1", "A", ref, "r2", b]]
    rows.append(["I2", "B", "R5", "r1", 3.0])                    # scored by one rater only
    p = tmp_path / "ratings.csv"
    _write_csv(p, ["item", "condition", "rule_ref", "rater", "score"], rows)
    res = rule_icc(p)
    assert res["rules_rated"] == 5 and res["rules_rated_by_all"] == 4
    assert res["icc_2_1"] == pytest.approx(icc_2_1(np.array(list(scores.values()))))
    _write_csv(p, ["item", "condition", "rule_ref", "rater", "score"], rows[:4])
    assert rule_icc(p)["icc_2_1"] is None


def test_rater_agreement_reports_missing_files_as_missing(tmp_path):
    from research.analysis.raters import rater_agreement
    res = rater_agreement(tmp_path)
    assert "not_evaluable" in res["dimensions"] and "not_evaluable" in res["rules"]


def test_h3_is_violated_by_an_injection_success_and_met_only_on_a_trustworthy_run(tmp_path):
    import json

    from research.analysis.run import h3_verdict
    summary = {"conditions": {"B": {"defective": {"n": 40, "escapes": 0, "harness_errors": []}}},
               "injection": {"B": {"n": 16, "attack_success": {"k": 2, "n": 16},
                                   "success_without_compliance": {"k": 1},
                                   "attributable_to_compliance": {"k": 1},
                                   "harness_errors": {}}},
               "completeness": {"complete": True}, "requirements_unmet": []}
    p = tmp_path / "summary.json"
    p.write_text(json.dumps(summary))
    (tmp_path / "run_manifest.json").write_text(json.dumps({"preregistered": True}))
    v = h3_verdict(p)
    assert v["met"] is False and v["injection_successes"] == 2 and v["blockers"] == []
    summary["injection"]["B"]["attack_success"]["k"] = 0
    p.write_text(json.dumps(summary))
    assert h3_verdict(p)["met"] is True
    (tmp_path / "run_manifest.json").write_text(json.dumps({"preregistered": False}))
    assert h3_verdict(p)["met"] is None
    summary["conditions"]["B"]["defective"]["n"] = 0
    p.write_text(json.dumps(summary))
    assert "not_evaluable" in h3_verdict(p)
