"""Order and carry-over in the counterbalanced crossover (blueprint §27.5, §29 item 7).

Every item is done twice, once manually (A) and once with ATIDEP (B), in the order its set fixes.
The mixed model puts item as a random effect and condition and exposure order as fixed effects;
the first-exposure comparison uses only each item's first exposure, which is free of carry-over
but unpaired and so less powerful.
"""

from __future__ import annotations

import warnings
from typing import Any

import numpy as np
import pandas as pd
from scipy import stats


def mixed_model(df: pd.DataFrame) -> dict[str, Any]:
    """``log(minutes) ~ condition + order + (1 | item)``. ``df`` has columns item, condition
    ('A' or 'B'), order ('first' or 'second' exposure) and minutes (> 0). The condition
    coefficient is the log ratio of ATIDEP to manual time, so exp(coefficient) is the time ratio."""
    import statsmodels.formula.api as smf

    d = df.copy()
    if (d["minutes"] <= 0).any():
        raise ValueError("minutes must be positive")
    d["log_minutes"] = np.log(d["minutes"])
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        formula = ("log_minutes ~ C(condition, Treatment('A')) "
                   "+ C(order, Treatment('first'))")
        fit = smf.mixedlm(formula, d, groups=d["item"]).fit(reml=True)
    ci = fit.conf_int()
    cond, order = (k for k in fit.params.index if k.startswith("C("))

    def row(k: str) -> dict[str, float]:
        return {"coef": float(fit.params[k]), "ci95": [float(ci.loc[k, 0]), float(ci.loc[k, 1])],
                "p": float(fit.pvalues[k])}

    return {"condition_B_vs_A": {**row(cond), "time_ratio": float(np.exp(fit.params[cond]))},
            "order_second_vs_first": row(order), "items": int(d["item"].nunique()),
            "converged": bool(fit.converged), "warnings": sorted({str(w.message)[:120]
                                                                   for w in caught})}


def first_exposure(df: pd.DataFrame, *, n_resamples: int = 5000, seed: int = 0) -> dict[str, Any]:
    """Compare the first exposures only: items whose set puts manual work first contribute their
    manual time, the others their ATIDEP time. Mann-Whitney U (two-sided) on log minutes, the
    Hodges-Lehmann shift as a time ratio, and a percentile bootstrap interval for it."""
    first = df[df["order"] == "first"]
    a = np.log(first[first["condition"] == "A"]["minutes"].to_numpy(float))
    b = np.log(first[first["condition"] == "B"]["minutes"].to_numpy(float))
    if len(a) < 2 or len(b) < 2:
        raise ValueError("each group needs at least two items")
    u = stats.mannwhitneyu(b, a, alternative="two-sided")
    walsh = (b[:, None] - a[None, :]).ravel()
    shift = float(np.median(walsh))
    rng = np.random.default_rng(seed)
    boots = [float(np.median((rng.choice(b, len(b))[:, None] - rng.choice(a, len(a))[None, :])
                             .ravel())) for _ in range(n_resamples)]
    lo, hi = np.quantile(boots, [0.025, 0.975])
    return {"n_manual_first": len(a), "n_atidep_first": len(b), "u": float(u.statistic),
            "p": float(u.pvalue), "time_ratio_hl": float(np.exp(shift)),
            "time_ratio_ci95": [float(np.exp(lo)), float(np.exp(hi))],
            "note": "unpaired; free of carry-over; compare with the paired estimate"}


def sequence_balance(df: pd.DataFrame) -> dict[str, int]:
    """How many items were done manually first and how many agentically first."""
    first = df[df["order"] == "first"]
    return {"manual_first": int((first["condition"] == "A").sum()),
            "atidep_first": int((first["condition"] == "B").sum())}


__all__ = ["first_exposure", "mixed_model", "sequence_balance"]
