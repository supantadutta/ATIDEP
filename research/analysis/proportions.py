"""Proportions and exact bounds (blueprint §29 item 8)."""

from __future__ import annotations

import numpy as np
from scipy.stats import beta, norm

from research.adversarial.stats import clopper_pearson_upper

__all__ = ["clopper_pearson", "clopper_pearson_upper", "clustered_interval", "wilson"]


def clopper_pearson(k: int, n: int, confidence: float = 0.95) -> tuple[float, float]:
    """Exact two-sided interval for k events in n trials."""
    if n <= 0:
        return 0.0, 1.0
    if not 0 <= k <= n:
        raise ValueError(f"{k} events in {n} trials is not a proportion")
    a = (1.0 - confidence) / 2.0
    lo = 0.0 if k == 0 else float(beta.ppf(a, k, n - k + 1))
    hi = 1.0 if k == n else float(beta.ppf(1.0 - a, k + 1, n - k))
    return lo, hi


def wilson(k: int, n: int, confidence: float = 0.95) -> tuple[float, float]:
    if n <= 0:
        return 0.0, 1.0
    z = float(norm.ppf(1.0 - (1.0 - confidence) / 2.0))
    p = k / n
    centre = (p + z * z / (2 * n)) / (1 + z * z / n)
    half = z * ((p * (1 - p) / n + z * z / (4 * n * n)) ** 0.5) / (1 + z * z / n)
    return max(0.0, centre - half), min(1.0, centre + half)


def clustered_interval(k_by_cluster: list[float], n_by_cluster: list[float], *,
                       n_resamples: int = 10000, seed: int = 0, confidence: float = 0.95
                       ) -> tuple[float, float] | None:
    """Percentile bootstrap interval for a ratio of sums, resampling clusters (items): the
    interval for a proportion whose trials are repeated within items (blueprint §29 item 8).
    None when there are fewer than two clusters with trials."""
    k, n = np.asarray(k_by_cluster, float), np.asarray(n_by_cluster, float)
    if len(k) != len(n) or int(np.sum(n > 0)) < 2:
        return None
    rng = np.random.default_rng(seed)
    idx = rng.integers(0, len(k), size=(n_resamples, len(k)))
    tot = n[idx].sum(axis=1)
    ratios = k[idx].sum(axis=1)[tot > 0] / tot[tot > 0]
    a = (1.0 - confidence) / 2.0
    lo, hi = np.quantile(ratios, [a, 1.0 - a])
    return float(lo), float(hi)
