"""Power by simulation (blueprint §29 item 11): the design only detects moderate-to-large effects;
this lets the pilot's variance check that before the freeze."""

from __future__ import annotations

import numpy as np
from scipy import stats


def paired_power(effect_size: float, n: int, *, alpha: float = 0.025, test: str = "wilcoxon",
                 sims: int = 4000, seed: int = 0) -> float:
    """Probability that a one-sided paired test rejects when the standardised mean difference of
    normally distributed differences is ``effect_size``."""
    rng = np.random.default_rng(seed)
    hits = 0
    for _ in range(sims):
        d = rng.normal(effect_size, 1.0, size=n)
        if test == "t":
            p = stats.ttest_1samp(d, 0.0, alternative="greater").pvalue
        else:
            p = stats.wilcoxon(d, alternative="greater").pvalue
        hits += p < alpha
    return hits / sims
