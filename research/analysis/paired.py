"""Paired comparisons: Hodges-Lehmann estimate, Wilcoxon, BCa bootstrap, the two confirmatory
rules H1 and H4, and Holm's correction (blueprint §9, §29)."""

from __future__ import annotations

import math
from collections.abc import Callable
from typing import Any

import numpy as np
from scipy import stats


def hodges_lehmann(x: np.ndarray | list[float]) -> float:
    """Median of the Walsh averages (x_i + x_j) / 2 over i <= j: the median shift."""
    a = np.asarray(x, dtype=float)
    i, j = np.triu_indices(len(a))
    return float(np.median((a[i] + a[j]) / 2.0))


def wilcoxon(diffs: np.ndarray | list[float], alternative: str = "greater") -> dict[str, Any]:
    d = np.asarray(diffs, dtype=float)
    nonzero = int(np.sum(d != 0))
    if nonzero == 0:
        return {"p": 1.0, "statistic": 0.0, "n": len(d), "n_nonzero": 0}
    res = stats.wilcoxon(d, alternative=alternative, zero_method="wilcox")
    return {"p": float(res.pvalue), "statistic": float(res.statistic), "n": len(d),
            "n_nonzero": nonzero}


def bca(data: np.ndarray, stat: Callable[[np.ndarray], float], *, n_resamples: int = 10000,
        seed: int = 0, alpha: float = 0.05, side: str = "lower") -> dict[str, Any]:
    """BCa bootstrap over the rows of ``data`` (items). ``side='lower'`` gives the one-sided
    lower bound at level 1 - alpha, ``'upper'`` the upper, ``'two-sided'`` the interval."""
    data = np.asarray(data, dtype=float)
    n = len(data)
    theta = float(stat(data))
    rng = np.random.default_rng(seed)
    idx = rng.integers(0, n, size=(n_resamples, n))
    boots = np.array([stat(data[i]) for i in idx], dtype=float)
    boots = boots[np.isfinite(boots)]
    # replicates equal to the estimate count as half below it (as scipy does); with a median
    # many replicates tie, and counting them as "not below" pushes the bound into the tail
    prop = float(np.mean(boots < theta) + 0.5 * np.mean(boots == theta)) if len(boots) else 0.5
    z0 = float(stats.norm.ppf(min(max(prop, 1.0 / (len(boots) + 1)), 1 - 1.0 / (len(boots) + 1))))
    jack = np.array([stat(np.delete(data, k, axis=0)) for k in range(n)], dtype=float)
    jm = jack.mean()
    den = 6.0 * (np.sum((jm - jack) ** 2) ** 1.5)
    acc = float(np.sum((jm - jack) ** 3) / den) if den > 0 else 0.0

    def q(level: float) -> float:
        za = stats.norm.ppf(level)
        adj = float(stats.norm.cdf(z0 + (z0 + za) / (1 - acc * (z0 + za))))
        return float(np.quantile(boots, min(max(adj, 0.0), 1.0)))

    out: dict[str, Any] = {"estimate": theta, "n": n, "resamples": int(len(boots)),
                           "bias_z0": z0, "acceleration": acc}
    if side == "lower":
        out["lower"] = q(alpha)
    elif side == "upper":
        out["upper"] = q(1 - alpha)
    else:
        out["lower"], out["upper"] = q(alpha / 2), q(1 - alpha / 2)
    return out


# ---- H1: efficiency --------------------------------------------------------------------------
def rank_biserial(diffs: np.ndarray) -> float | None:
    """Matched-pairs rank-biserial correlation (W+ - W-) / (W+ + W-) over the non-zero
    differences: the effect size that goes with the Wilcoxon signed-rank test."""
    d = np.asarray(diffs, float)
    d = d[d != 0]
    if not len(d):
        return None
    ranks = stats.rankdata(np.abs(d))
    plus, minus = float(ranks[d > 0].sum()), float(ranks[d < 0].sum())
    return (plus - minus) / (plus + minus)


def h1(minutes_manual: list[float], minutes_atidep: list[float], *, delta_t_pct: float,
       n_resamples: int = 10000, seed: int = 0, alpha: float = 0.05) -> dict[str, Any]:
    """H1. Per item, the relative reduction r = (A - B) / A in analyst active minutes (A manual,
    B ATIDEP). As pre-registered, supported if the median r is at least delta_t and the
    one-sided (1 - alpha) BCa lower bound of the median is above 0; ``alpha`` is 0.05 on its
    own and the Holm level inside the confirmatory family. The stricter reading (the lower
    bound itself at least delta_t) is reported beside it. The Wilcoxon test is on log(A/B), and
    the Hodges-Lehmann estimate of the log ratio is turned back into a ratio. The criterion
    here is unadjusted; the confirmatory verdict also needs Holm's rejection (``run``)."""
    a, b = np.asarray(minutes_manual, float), np.asarray(minutes_atidep, float)
    if len(a) != len(b) or len(a) < 3:
        raise ValueError("H1 needs matched minutes for at least three items")
    if np.any(a <= 0) or np.any(b <= 0):
        raise ValueError("active minutes must be positive")
    rel = (a - b) / a
    lb = bca(rel.reshape(-1, 1), lambda x: float(np.median(x)), n_resamples=n_resamples,
             seed=seed, side="lower", alpha=alpha)
    logratio = np.log(a / b)
    w = wilcoxon(logratio, "greater")
    hl_ci = bca(logratio.reshape(-1, 1), lambda x: hodges_lehmann(x[:, 0]),
                n_resamples=n_resamples, seed=seed, side="two-sided")
    med = float(np.median(rel))
    delta = delta_t_pct / 100.0
    return {"n": len(a), "alpha": alpha, "median_relative_reduction": med,
            "lower_bound_one_sided": lb["lower"], "lower_bound_95_one_sided": lb["lower"]
            if alpha == 0.05 else None, "delta_t": delta,
            "supported_as_preregistered": bool(med >= delta and lb["lower"] > 0),
            "lower_bound_reaches_delta_t": bool(lb["lower"] >= delta),
            "wilcoxon_log_ratio": w, "effect_size_rank_biserial": rank_biserial(logratio),
            "hodges_lehmann_ratio": math.exp(hodges_lehmann(logratio)),
            "hodges_lehmann_ratio_ci95": [math.exp(hl_ci["lower"]), math.exp(hl_ci["upper"])],
            "bootstrap_resamples": {"median_bound": lb["resamples"],
                                    "hodges_lehmann_ci": hl_ci["resamples"]},
            "median_minutes": {"manual": float(np.median(a)), "atidep": float(np.median(b))},
            "p_for_holm": w["p"]}


# ---- H4: non-inferiority ---------------------------------------------------------------------
def h4(rubric_manual: list[float], rubric_atidep: list[float], *, delta_q: float,
       n_resamples: int = 10000, seed: int = 0, alpha: float = 0.05) -> dict[str, Any]:
    """H4. Paired differences d = B - A in item-level mean blinded rubric score. Non-inferiority:
    the one-sided (1 - alpha) lower bound of the mean difference exceeds -delta_q (equivalently
    the lower arm of TOST at alpha); ``alpha`` is 0.05 on its own and the Holm level inside the
    confirmatory family. The t-based bound is primary; the BCa bound is a check. The criterion
    here is unadjusted; the confirmatory verdict also needs Holm's rejection (``run``)."""
    a, b = np.asarray(rubric_manual, float), np.asarray(rubric_atidep, float)
    if len(a) != len(b) or len(a) < 3:
        raise ValueError("H4 needs matched scores for at least three items")
    d = b - a
    n = len(d)
    mean, se = float(d.mean()), float(d.std(ddof=1) / math.sqrt(n))
    t_crit = float(stats.t.ppf(1 - alpha, n - 1))
    lower = mean - t_crit * se
    t_stat = (mean + delta_q) / se if se > 0 else math.inf
    p = float(stats.t.sf(t_stat, n - 1)) if se > 0 else (0.0 if mean > -delta_q else 1.0)
    boot = bca(d.reshape(-1, 1), lambda x: float(np.mean(x)), n_resamples=n_resamples, seed=seed,
               side="lower", alpha=alpha)
    sd = float(d.std(ddof=1))
    return {"n": n, "alpha": alpha, "mean_difference": mean, "se": se,
            "lower_bound_one_sided": lower,
            "lower_bound_95_one_sided": lower if alpha == 0.05 else None,
            "effect_size_dz": mean / sd if sd > 0 else None,
            "delta_q": delta_q, "non_inferior": bool(lower > -delta_q), "p_tost_lower_arm": p,
            "bca_lower_bound": boot["lower"], "bca_agrees": bool(boot["lower"] > -delta_q) ==
            bool(lower > -delta_q), "p_for_holm": p}


# ---- Holm ------------------------------------------------------------------------------------
def holm(pvalues: dict[str, float], alpha: float = 0.05) -> dict[str, dict[str, float | bool]]:
    """Holm's step-down procedure. For two one-sided tests the smaller p is compared with
    alpha / 2 and, if it passes, the larger with alpha."""
    names = sorted(pvalues, key=lambda k: pvalues[k])
    m = len(names)
    out: dict[str, dict[str, float | bool]] = {}
    running, still = 0.0, True
    for rank, name in enumerate(names):
        adj = min(1.0, (m - rank) * pvalues[name])
        running = max(running, adj)
        reject = still and pvalues[name] <= alpha / (m - rank)
        still = reject
        out[name] = {"p": pvalues[name], "p_holm": running, "reject": reject}
    return out
