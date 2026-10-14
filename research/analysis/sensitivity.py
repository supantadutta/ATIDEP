"""Sensitivity of the priority ranking to its weights (blueprint §29 items 13): are the ranks
stable when the weights are perturbed?"""

from __future__ import annotations

import numpy as np
from scipy.stats import kendalltau


def rank_stability(components: np.ndarray, weights: np.ndarray, *, n_draws: int = 1000,
                   spread: float = 0.25, top_k: int = 5, seed: int = 0) -> dict[str, float]:
    """``components`` is items x components (each 0-100); the score is components @ weights.
    Each draw multiplies every weight by exp(N(0, spread)) and renormalises to the original sum.
    Returns Kendall's tau between the baseline and perturbed rankings (mean, 5th percentile,
    minimum) and how often the baseline top-k items stay in the top k."""
    c, w = np.asarray(components, float), np.asarray(weights, float)
    base = c @ w
    rng = np.random.default_rng(seed)
    taus, kept = [], []
    top = set(np.argsort(-base)[:top_k])
    for _ in range(n_draws):
        wp = w * np.exp(rng.normal(0.0, spread, size=len(w)))
        wp *= w.sum() / wp.sum()
        score = c @ wp
        tau = kendalltau(base, score).statistic
        taus.append(1.0 if np.isnan(tau) else float(tau))
        kept.append(len(top & set(np.argsort(-score)[:top_k])) / top_k)
    t = np.array(taus)
    return {"tau_mean": float(t.mean()), "tau_p05": float(np.quantile(t, 0.05)),
            "tau_min": float(t.min()), "top_k": top_k, "top_k_retained_mean": float(np.mean(kept)),
            "draws": n_draws, "spread": spread}
