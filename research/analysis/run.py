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
from research.economics.measured import _b, _hosted, review_time


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


def _read(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open(newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def item_minutes(exp: Path, categories: dict[str, str] | None = None) -> list[dict[str, Any]]:
    """One row per item with analyst active minutes in both conditions, read from the analyst
    records (``analyst_effort.csv``) and not from the pipeline's runs, so an item whose ATIDEP
    runs all failed or hit the spend cap keeps its measured minutes (intention to treat, blueprint
    §29 item 12). ``per_protocol`` is True when at least one condition-B run on the local model
    neither failed nor hit the cap."""
    runs = _read(exp / "runs.csv")
    hours, _, _ = review_time(_read(exp / "analyst_effort.csv"))
    info: dict[str, dict[str, Any]] = {}
    for r in runs:
        key = r.get("item_key")
        if not key:
            continue
        e = info.setdefault(key, {"item": r["item"], "order_set": r.get("order_set") or None,
                                  "pipeline_ok": False})
        if r["condition"] == "B" and not _hosted(r) and not _b(r.get("budget_exceeded")) \
                and not (r.get("error") or "").strip():
            e["pipeline_ok"] = True
    rows = []
    for key, h in sorted(hours.items()):
        if (h.get("A") or 0) > 0 and (h.get("B") or 0) > 0:
            e = info.get(key, {"item": key, "order_set": None, "pipeline_ok": False})
            rows.append({"item": e["item"], "key": key, "order_set": e["order_set"],
                         "category": (categories or {}).get(e["item"]), "A": h["A"] * 60.0,
                         "B": h["B"] * 60.0, "per_protocol": e["pipeline_ok"]})
    return rows


def crossover_frame(rows: list[dict[str, Any]]) -> pd.DataFrame:
    out = []
    for r in rows:
        if r["order_set"] not in ("X", "Y"):
            continue
        a_first = r["order_set"] == "X"
        out.append({"item": r["item"], "category": r["category"], "condition": "A",
                    "order": "first" if a_first else "second", "minutes": r["A"]})
        out.append({"item": r["item"], "category": r["category"], "condition": "B",
                    "order": "second" if a_first else "first", "minutes": r["B"]})
    return pd.DataFrame(out)


def holm_levels(pvalues: dict[str, float], alpha: float) -> dict[str, float]:
    """The level at which Holm's step-down tests each hypothesis: alpha / (m - rank)."""
    names = sorted(pvalues, key=lambda k: pvalues[k])
    return {n: alpha / (len(names) - i) for i, n in enumerate(names)}


def _git_head() -> str | None:
    try:
        return subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True,
                              check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def run_analysis(export_dir: Path | str, out_dir: Path | str, *,
                 config_dir: Path | str = DEFAULT_CONFIG_DIR,
                 adversarial_summary: Path | str | None = None,
                 categories: dict[str, str] | None = None) -> dict[str, Any]:
    exp, out = Path(export_dir), Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    cfg = load_config(config_dir).experiment
    rows = item_minutes(exp, categories)
    n_res = cfg.bootstrap_resamples
    seed = 20261014
    res: dict[str, Any] = {"alpha_familywise": cfg.alpha_familywise, "bootstrap_resamples": n_res,
                           "seed": seed, "items_with_minutes_in_both_conditions": len(rows)}

    # H1: intention to treat (confirmatory) and per protocol (beside it) ----------------------
    pp = [r for r in rows if r["per_protocol"]]
    if len(rows) >= 3:
        res["H1"] = {"analysis": "intention to treat", "items": len(rows),
                     **paired.h1([r["A"] for r in rows], [r["B"] for r in rows],
                                 delta_t_pct=cfg.delta_t_pct, n_resamples=n_res, seed=seed)}
        res["H1_per_protocol"] = {
            "analysis": "per protocol (items with at least one working condition-B run)",
            "items": len(pp), "excluded_items": sorted(r["item"] for r in rows
                                                       if not r["per_protocol"]),
            **(paired.h1([r["A"] for r in pp], [r["B"] for r in pp], delta_t_pct=cfg.delta_t_pct,
                         n_resamples=n_res, seed=seed) if len(pp) >= 3 else
               {"not_evaluable": f"{len(pp)} item(s) per protocol"})}
    else:
        res["H1"] = {"not_evaluable": f"{len(rows)} item(s) have analyst time in both conditions"}

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

    # Holm over the confirmatory family, and the verdicts it allows ---------------------------
    # The per-hypothesis flags above are unadjusted. A confirmatory verdict needs both Holm's
    # rejection and the registered criterion re-evaluated at the level Holm tests it at.
    ps = {k: res[k]["p_for_holm"] for k in ("H1", "H4") if "p_for_holm" in res[k]}
    res["holm"] = paired.holm(ps, cfg.alpha_familywise) if len(ps) == 2 else {}
    verdicts: dict[str, Any] = {}
    if len(ps) < 2:
        res["holm_note"] = ("both confirmatory tests are needed; the family is incomplete, so "
                            "no rejection is stated")
        for k in ("H1", "H4"):
            verdicts[k] = "not evaluable (the confirmatory family is incomplete)"
    else:
        levels = holm_levels(ps, cfg.alpha_familywise)
        at1 = paired.h1([r["A"] for r in rows], [r["B"] for r in rows],
                        delta_t_pct=cfg.delta_t_pct, n_resamples=n_res, seed=seed,
                        alpha=levels["H1"])
        at4 = paired.h4([p[0] for p in pairs], [p[1] for p in pairs],
                        delta_q=cfg.delta_q_rubric_points, n_resamples=n_res, seed=seed,
                        alpha=levels["H4"])
        res["H1"]["at_holm_level"] = {k: at1[k] for k in (
            "alpha", "lower_bound_one_sided", "supported_as_preregistered",
            "lower_bound_reaches_delta_t")}
        res["H4"]["at_holm_level"] = {k: at4[k] for k in (
            "alpha", "lower_bound_one_sided", "non_inferior")}
        verdicts["H1"] = ("supported" if res["holm"]["H1"]["reject"]
                          and at1["supported_as_preregistered"] else "not supported")
        verdicts["H4"] = ("non-inferior" if res["holm"]["H4"]["reject"]
                          and at4["non_inferior"] else "non-inferiority not shown")
    res["confirmatory_verdicts"] = verdicts

    # order and carry-over --------------------------------------------------------------------
    df = crossover_frame(rows)
    res["crossover"] = _crossover(df, seed)

    # secondary: H2, on the primary (local) model's condition-B runs only ---------------------
    runs = _read(exp / "runs.csv")
    b_runs = [r for r in runs if r["condition"] == "B" and not _b(r.get("budget_exceeded"))
              and not _hosted(r)]

    def num(r: dict[str, str], col: str) -> float:
        return float(r[col]) if r.get(col) not in (None, "", "None") else 0.0

    sigma = sum(num(r, "rules.sigma_rules") for r in b_runs)
    if sigma:
        k_post = int(sum(num(r, "rules.post_repair_valid") for r in b_runs))
        k_first = int(sum(num(r, "rules.first_pass_valid") for r in b_runs))
        n = int(sigma)
        by_item: dict[str, list[float]] = defaultdict(lambda: [0.0, 0.0, 0.0])
        for r in b_runs:
            c = by_item[r["item"]]
            c[0] += num(r, "rules.post_repair_valid")
            c[1] += num(r, "rules.first_pass_valid")
            c[2] += num(r, "rules.sigma_rules")
        cl = list(by_item.values())
        res["H2"] = {"rules": n, "items": len(by_item), "post_repair_valid": k_post,
                     "first_pass_valid": k_first, "post_repair_rate": k_post / n,
                     "post_repair_ci95_item_clustered": proportions.clustered_interval(
                         [c[0] for c in cl], [c[2] for c in cl], n_resamples=n_res, seed=seed),
                     "post_repair_ci95_ignoring_clustering": proportions.clopper_pearson(k_post,
                                                                                         n),
                     "first_pass_rate": k_first / n,
                     "first_pass_ci95_item_clustered": proportions.clustered_interval(
                         [c[1] for c in cl], [c[2] for c in cl], n_resamples=n_res, seed=seed),
                     "first_pass_ci95_ignoring_clustering": proportions.clopper_pearson(k_first,
                                                                                        n),
                     "threshold": 0.80, "met": k_post / n >= 0.80,
                     "hosted_model_runs_excluded": sum(1 for r in runs if r["condition"] == "B"
                                                       and _hosted(r)),
                     "note": "rules are nested in items and runs; the item-clustered interval "
                             "(bootstrap over items) is the one to quote"}
    else:
        res["H2"] = {"not_evaluable": "no Sigma rules in condition B runs on the local model"}

    # secondary: H3 from the adversarial summary ----------------------------------------------
    res["H3"] = h3_verdict(adversarial_summary)

    (out / "analysis.json").write_text(json.dumps(_finite(res), indent=1, default=_json,
                                                  allow_nan=False))
    manifest = {"git_head": _git_head(), "python": sys.version.split()[0],
                "platform": platform.platform(),
                "versions": {m: _version(m) for m in ("numpy", "scipy", "pandas", "statsmodels")},
                "config_experiment_sha256": _sha(Path(config_dir) / "experiment.yaml"),
                "inputs": {p.name: _sha(p) for p in sorted(exp.glob("*.csv"))},
                "outputs": {"analysis.json": _sha(out / "analysis.json")}}
    (out / "manifest.json").write_text(json.dumps(manifest, indent=1, sort_keys=True))
    return res


def _crossover(df: pd.DataFrame, seed: int) -> dict[str, Any]:
    """The mixed model and the first-exposure comparison, or why they cannot be computed. With
    one sequence only, condition and order are confounded; each sequence needs two items."""
    if df.empty or df["item"].nunique() < 6:
        return {"not_evaluable": "too few items with analyst time in both conditions and a known "
                                 "order set"}
    bal = sequence_balance(df)
    if min(bal.values()) < 2:
        return {"balance": bal, "not_evaluable": "each sequence (manual first, ATIDEP first) needs "
                                                 "at least two items; otherwise condition and "
                                                 "order are confounded"}
    out: dict[str, Any] = {"balance": bal}
    for name, fn in (("mixed_model", lambda: mixed_model(df)),
                     ("first_exposure", lambda: first_exposure(df, seed=seed,
                                                               strata="category"))):
        try:
            out[name] = fn()
        except (np.linalg.LinAlgError, ValueError) as exc:
            out[name] = {"not_evaluable": f"{type(exc).__name__}: {exc}"[:200]}
    return out


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


def _finite(o: Any) -> Any:
    """NaN and infinity are not JSON; a statistic that is not finite is written as null."""
    if isinstance(o, dict):
        return {k: _finite(v) for k, v in o.items()}
    if isinstance(o, (list, tuple)):
        return [_finite(v) for v in o]
    if isinstance(o, (float, np.floating)):
        return float(o) if np.isfinite(o) else None
    return o


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
