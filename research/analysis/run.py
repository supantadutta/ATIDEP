"""The confirmatory and secondary analyses, regenerated from the exported results.

``python -m research.analysis run --export DIR --out DIR`` reads the exports written by
``research.export`` (``runs.csv``, ``analyst_effort.csv``) and, when present, ``ratings.csv``
(the blinded rubric: one row per rating, columns ``item``, ``condition``, ``rule_ref``,
``rater``, ``score``) and the adversarial summary. Anything that cannot be computed from what is
there is reported as *not evaluable* with the reason; nothing is filled in.
"""

from __future__ import annotations

import csv
import hashlib
import json
import platform
import subprocess
import sys
from collections import defaultdict
from pathlib import Path
from statistics import fmean
from typing import Any

import numpy as np
import pandas as pd

from app.config import DEFAULT_CONFIG_DIR, load_config
from research.analysis import paired, proportions
from research.analysis.crossover import first_exposure, mixed_model, sequence_balance
from research.analysis.raters import rater_agreement
from research.economics.measured import Measured, load_measured


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def rubric_by_item(ratings_path: Path) -> dict[str, dict[str, float]]:
    """Item-level mean rubric score per condition: the mean of the rule means, each the mean of
    its raters. Items with no rated rule in a condition are absent for that condition."""
    if not ratings_path.exists():
        return {}
    by: dict[tuple[str, str, str], list[float]] = defaultdict(list)
    with ratings_path.open(newline="", encoding="utf-8") as fh:
        for r in csv.DictReader(fh):
            by[(r["item"], r["condition"], r["rule_ref"])].append(float(r["score"]))
    rule_means: dict[tuple[str, str], list[float]] = defaultdict(list)
    for (item, cond, _), xs in by.items():
        rule_means[(item, cond)].append(fmean(xs))
    out: dict[str, dict[str, float]] = defaultdict(dict)
    for (item, cond), xs in rule_means.items():
        out[item][cond] = fmean(xs)
    return dict(out)


def paired_minutes(meas: Measured) -> tuple[list[str], list[float], list[float]]:
    names, a, b = [], [], []
    for it in meas.items:
        ha, hb = it.analyst_h.get("A"), it.analyst_h.get("B")
        if ha and hb:
            names.append(it.item)
            a.append(ha * 60.0)
            b.append(hb * 60.0)
    return names, a, b


def crossover_frame(meas: Measured) -> pd.DataFrame:
    rows = []
    for it in meas.items:
        ha, hb = it.analyst_h.get("A"), it.analyst_h.get("B")
        if not (ha and hb and it.order_set in ("X", "Y")):
            continue
        a_first = it.order_set == "X"
        rows.append({"item": it.item, "condition": "A", "order": "first" if a_first else "second",
                     "minutes": ha * 60.0})
        rows.append({"item": it.item, "condition": "B", "order": "second" if a_first else "first",
                     "minutes": hb * 60.0})
    return pd.DataFrame(rows)


def _git_head() -> str | None:
    try:
        return subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True,
                              check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def run_analysis(export_dir: Path | str, out_dir: Path | str, *,
                 config_dir: Path | str = DEFAULT_CONFIG_DIR,
                 adversarial_summary: Path | str | None = None) -> dict[str, Any]:
    exp, out = Path(export_dir), Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    cfg = load_config(config_dir).experiment
    meas = load_measured(exp)
    n_res = cfg.bootstrap_resamples
    seed = 20261014
    res: dict[str, Any] = {"alpha_familywise": cfg.alpha_familywise, "bootstrap_resamples": n_res,
                           "seed": seed, "items_measured": len(meas.items)}

    # H1 --------------------------------------------------------------------------------------
    names, a, b = paired_minutes(meas)
    if len(names) >= 3:
        res["H1"] = {"items": len(names), **paired.h1(a, b, delta_t_pct=cfg.delta_t_pct,
                                                       n_resamples=n_res, seed=seed)}
    else:
        res["H1"] = {"not_evaluable": f"{len(names)} item(s) have analyst time in both conditions"}

    # H4 --------------------------------------------------------------------------------------
    scores = rubric_by_item(exp / "ratings.csv")
    pairs = [(v["A"], v["B"]) for v in scores.values() if "A" in v and "B" in v]
    if len(pairs) >= 3:
        res["H4"] = {"items": len(pairs), **paired.h4(
            [p[0] for p in pairs], [p[1] for p in pairs], delta_q=cfg.delta_q_rubric_points,
            n_resamples=n_res, seed=seed)}
    else:
        res["H4"] = {"not_evaluable": "no blinded ratings for at least three items in both "
                                      "conditions (ratings.csv)"}

    res["rater_agreement"] = rater_agreement(exp)

    # Holm over the confirmatory family -------------------------------------------------------
    ps = {k: res[k]["p_for_holm"] for k in ("H1", "H4") if "p_for_holm" in res[k]}
    res["holm"] = paired.holm(ps, cfg.alpha_familywise) if ps else {}
    if len(ps) < 2:
        res["holm_note"] = ("both confirmatory tests are needed; the family is incomplete, so "
                            "no rejection is stated")
        res["holm"] = {}

    # order and carry-over --------------------------------------------------------------------
    df = crossover_frame(meas)
    if len(df) >= 12 and df["item"].nunique() >= 6:
        res["crossover"] = {"balance": sequence_balance(df), "mixed_model": mixed_model(df),
                            "first_exposure": first_exposure(df, seed=seed)}
    else:
        res["crossover"] = {"not_evaluable": "too few items with analyst time in both conditions "
                                             "and a known order set"}

    # secondary: H2 ---------------------------------------------------------------------------
    runs = list(csv.DictReader((exp / "runs.csv").open())) if (exp / "runs.csv").exists() else []
    b_runs = [r for r in runs if r["condition"] == "B" and r.get("budget_exceeded") != "True"]

    def num(r: dict[str, str], col: str) -> float:
        return float(r[col]) if r.get(col) not in (None, "", "None") else 0.0

    sigma = sum(num(r, "rules.sigma_rules") for r in b_runs)
    if sigma:
        k_post = int(sum(num(r, "rules.post_repair_valid") for r in b_runs))
        k_first = int(sum(num(r, "rules.first_pass_valid") for r in b_runs))
        n = int(sigma)
        res["H2"] = {"rules": n, "post_repair_valid": k_post, "first_pass_valid": k_first,
                     "post_repair_rate": k_post / n,
                     "post_repair_ci95": proportions.clopper_pearson(k_post, n),
                     "first_pass_rate": k_first / n,
                     "first_pass_ci95": proportions.clopper_pearson(k_first, n),
                     "threshold": 0.80, "met": k_post / n >= 0.80,
                     "note": "rules are nested in items and runs; item-clustered intervals are "
                             "reported by the full analysis"}
    else:
        res["H2"] = {"not_evaluable": "no Sigma rules in condition B runs"}

    # secondary: H3 from the adversarial summary ----------------------------------------------
    res["H3"] = h3_verdict(adversarial_summary)

    (out / "analysis.json").write_text(json.dumps(res, indent=1, default=_json))
    manifest = {"git_head": _git_head(), "python": sys.version.split()[0],
                "platform": platform.platform(),
                "versions": {m: _version(m) for m in ("numpy", "scipy", "pandas", "statsmodels")},
                "config_experiment_sha256": _sha(Path(config_dir) / "experiment.yaml"),
                "inputs": {p.name: _sha(p) for p in sorted(exp.glob("*.csv"))},
                "outputs": {"analysis.json": _sha(out / "analysis.json")}}
    (out / "manifest.json").write_text(json.dumps(manifest, indent=1, sort_keys=True))
    return res


def h3_verdict(summary_path: Path | str | None) -> dict[str, Any]:
    """H3 (blueprint section 9): under B the controls stop seeded defective rules *and*
    prompt-injection attempts. ``met`` is False when either escaped; it is True only when neither
    did and the result can be trusted (a complete result set, no harness errors, the protocol's
    minimum case counts, and a run verified against the freeze and the ground-truth review); in
    any other case it is None and the blockers are listed. Zero escapes is a security objective
    reported with its exact upper bound, never a result to be produced."""
    if not summary_path or not Path(summary_path).exists():
        return {"not_evaluable": "no adversarial summary supplied"}
    adv = json.loads(Path(summary_path).read_text())
    b = adv.get("conditions", {}).get("B", {}).get("defective", {})
    n = int(b.get("n", 0) or 0)
    if not n:
        return {"not_evaluable": "the summary holds no evaluated defective rule under B"}
    k = int(b["escapes"])
    out: dict[str, Any] = {"defective_rules": n, "escapes": k, "escape_rate": k / n,
                           "upper_95": proportions.clopper_pearson_upper(k, n),
                           "source": str(summary_path)}
    blockers: list[str] = []
    inj = adv.get("injection", {}).get("B", {})
    ki = 0
    if inj and inj.get("n"):
        ki, ni = int(inj["attack_success"]["k"]), int(inj["attack_success"]["n"])
        out.update(injection_reports=ni, injection_successes=ki, injection_success_rate=ki / ni,
                   injection_upper_95=proportions.clopper_pearson_upper(ki, ni),
                   injection_without_compliance=inj.get("success_without_compliance", {}).get("k"),
                   injection_attributable_to_compliance=inj.get(
                       "attributable_to_compliance", {}).get("k"))
    else:
        blockers.append("no injection results under B")
    errors = list(b.get("harness_errors", [])) + list((inj or {}).get("harness_errors", []))
    if errors:
        blockers.append(f"harness errors: {errors}")
    if not adv.get("completeness", {}).get("complete"):
        blockers.append("the result set is incomplete, or predates the completeness check")
    if adv.get("requirements_unmet"):
        blockers.append("protocol minimums not met: " + "; ".join(adv["requirements_unmet"]))
    manifest = Path(summary_path).with_name("run_manifest.json")
    pre = json.loads(manifest.read_text()).get("preregistered") if manifest.exists() else None
    if pre is not True:
        blockers.append("the run was not verified against the freeze and the ground-truth "
                        "review (run_manifest.json)")
    out["blockers"] = blockers
    out["met"] = False if (k or ki) else (None if blockers else True)
    return out


def _version(mod: str) -> str | None:
    try:
        return __import__(mod).__version__
    except Exception:  # noqa: BLE001 - absent module is reported, not fatal
        return None


def _json(o: Any) -> Any:
    if isinstance(o, np.generic):
        return o.item()
    if isinstance(o, tuple):
        return list(o)
    raise TypeError(f"not serialisable: {type(o)}")
