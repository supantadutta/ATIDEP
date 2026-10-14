"""Exact binomial bounds for the escape and success rates."""

from __future__ import annotations

from scipy.stats import beta


def clopper_pearson_upper(events: int, n: int, confidence: float = 0.95) -> float:
    """Exact one-sided upper confidence bound for a proportion. With no events in ``n`` trials it
    is 1 - (1 - confidence) ** (1 / n), e.g. about 7.2% for 40 and 22.1% for 12."""
    if n <= 0:
        return 1.0
    if events >= n:
        return 1.0
    if events == 0:
        return 1.0 - (1.0 - confidence) ** (1.0 / n)
    return float(beta.ppf(confidence, events + 1, n - events))


def rate(events: int, n: int) -> float | None:
    return events / n if n else None
