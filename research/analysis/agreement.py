"""Agreement measures (blueprint §29 item 9)."""

from __future__ import annotations

from collections.abc import Hashable, Sequence

import numpy as np


def cohen_kappa(a: Sequence[Hashable], b: Sequence[Hashable]) -> float | None:
    """Cohen's kappa, or None when it is undefined: both raters used one single category, so
    chance agreement is 1 and (po - pe) / (1 - pe) is 0/0. That is not perfect agreement."""
    if len(a) != len(b) or not a:
        raise ValueError("two equal-length, non-empty label lists are needed")
    cats = sorted(set(a) | set(b), key=str)
    ix = {c: i for i, c in enumerate(cats)}
    m = np.zeros((len(cats), len(cats)))
    for x, y in zip(a, b, strict=True):
        m[ix[x], ix[y]] += 1
    n = m.sum()
    po = np.trace(m) / n
    pe = float(np.sum(m.sum(axis=1) * m.sum(axis=0)) / (n * n))
    return None if pe == 1 else float((po - pe) / (1 - pe))


def weighted_kappa(a: Sequence[int], b: Sequence[int], *, categories: Sequence[int] | None = None,
                   weights: str = "quadratic") -> float | None:
    """Weighted kappa for ordinal ratings (the rubric); quadratic weights by default. None when
    it is undefined (no disagreement is possible by chance, for example one score throughout)."""
    cats = list(categories) if categories is not None else sorted(set(a) | set(b))
    k = len(cats)
    ix = {c: i for i, c in enumerate(cats)}
    m = np.zeros((k, k))
    for x, y in zip(a, b, strict=True):
        m[ix[x], ix[y]] += 1
    n = m.sum()
    i, j = np.indices((k, k))
    dist = np.abs(i - j) / max(k - 1, 1)
    w = dist**2 if weights == "quadratic" else dist
    expected = np.outer(m.sum(axis=1), m.sum(axis=0)) / n
    denom = np.sum(w * expected)
    return None if denom == 0 else float(1.0 - np.sum(w * m) / denom)


def icc_2_1(ratings: np.ndarray) -> float:
    """Intraclass correlation ICC(2,1): two-way random effects, absolute agreement, single
    rater (Shrout and Fleiss). ``ratings`` is subjects x raters."""
    x = np.asarray(ratings, float)
    n, k = x.shape
    grand = x.mean()
    ss_rows = k * np.sum((x.mean(axis=1) - grand) ** 2)
    ss_cols = n * np.sum((x.mean(axis=0) - grand) ** 2)
    ss_err = np.sum((x - grand) ** 2) - ss_rows - ss_cols
    msr, msc, mse = ss_rows / (n - 1), ss_cols / (k - 1), ss_err / ((n - 1) * (k - 1))
    return float((msr - mse) / (msr + (k - 1) * mse + k * (msc - mse) / n))


def jaccard(a: set, b: set) -> float:
    """Set agreement for technique IDs; two empty sets agree completely."""
    return 1.0 if not a and not b else len(a & b) / len(a | b)
