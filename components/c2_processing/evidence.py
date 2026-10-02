"""Verbatim-quote verification and claim construction (blueprint §17.2.2, §16.2).

A claim is *verified* only if its quotation occurs in the sanitised source text after the
shared normalisation of ``components.c1_ingest.text``. The match is case-sensitive and finds
the exact character span, so evidence offsets always point into the stored sanitised text.
A model therefore cannot introduce a claim that the document does not contain.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta

from components.c1_ingest.text import clean_text
from components.c2_processing.indicators import CveMention, Indicator
from schemas.claim import Claim, ClaimKind, EntityType, Evidence, IndicatorContext

MIN_QUOTE_CHARS = 8
MAX_QUOTE_CHARS = 600


@dataclass(frozen=True)
class QuoteCheck:
    ok: bool
    start: int = 0
    end: int = 0
    reason: str = ""


def check_quote(quote: str, text: str) -> QuoteCheck:
    normalised, _ = clean_text(quote or "")
    tokens = normalised.split()
    if not tokens:
        return QuoteCheck(False, reason="empty")
    flat = " ".join(tokens)
    if len(flat) < MIN_QUOTE_CHARS:
        return QuoteCheck(False, reason="too_short")
    if len(flat) > MAX_QUOTE_CHARS:
        return QuoteCheck(False, reason="too_long")
    match = re.search(r"\s+".join(re.escape(t) for t in tokens), text)
    if not match:
        return QuoteCheck(False, reason="not_found")
    return QuoteCheck(True, match.start(), match.end())


class ClaimFactory:
    """Allocates claim and evidence IDs for one intelligence item."""

    def __init__(self, intel_id: str, sanitised_sha256: str) -> None:
        self.intel_id = intel_id
        self.sha = sanitised_sha256
        self._n = 0
        suffix = intel_id.removeprefix("TI-")
        self._cl, self._ev = f"CL-{suffix}-", f"EV-{suffix}-"

    def _ids(self) -> tuple[str, str]:
        self._n += 1
        return f"{self._cl}{self._n:03d}", f"{self._ev}{self._n:03d}"

    def evidence(self, quote: str, start: int, end: int, verified: bool, eid: str) -> Evidence:
        return Evidence(evidence_id=eid, quote=quote, char_start=start,
                        char_end=max(end, start + 1), source_sha256=self.sha, verified=verified)

    def indicator_claim(self, ind: Indicator, retrieved_at: datetime,
                        expiry_days: dict[str, int]) -> Claim:
        cid, eid = self._ids()
        t = ind.type.value
        key = "hash" if t in ("md5", "sha1", "sha256") else "ip" if t.startswith("ipv") else t
        expires = retrieved_at + timedelta(days=expiry_days[key]) \
            if ind.context is not IndicatorContext.REFERENCE_ONLY else None
        return Claim(claim_id=cid, kind=ClaimKind.INDICATOR, type=ind.type, value=ind.value,
                     refanged_from=ind.quote if ind.defanged else None, valid=True,
                     context=ind.context, expires_at=expires,
                     evidence=self.evidence(ind.quote, ind.start, ind.end, True, eid))

    def cve_claim(self, cve: CveMention) -> Claim:
        cid, eid = self._ids()
        return Claim(claim_id=cid, kind=ClaimKind.ENTITY, type=EntityType.VULNERABILITY,
                     value=cve.value,
                     evidence=self.evidence(cve.quote, cve.start, cve.end, True, eid))

    def checked_claim(self, check: QuoteCheck, quote: str, **fields) -> Claim:
        """A claim from model output. Unverified claims are kept (so they can be counted as
        unsupported) but their evidence is marked unverified."""
        cid, eid = self._ids()
        start, end = (check.start, check.end) if check.ok else (0, max(1, len(quote or "x")))
        ev = self.evidence(quote if quote else "(empty)", start, end, check.ok, eid)
        return Claim(claim_id=cid, evidence=ev, **fields)
