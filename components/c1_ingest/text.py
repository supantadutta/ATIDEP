"""Text normalisation shared by ingest and by quote verification (blueprint §17.1, §17.2.2).

One function defines what "the same text" means, so a quotation is compared with its source
under exactly the normalisation that produced the sanitised text.
"""

from __future__ import annotations

import re
import unicodedata

# Zero-width and bidirectional control characters that can hide or reorder text.
ZERO_WIDTH = "​‌‍‎‏⁠⁡⁢⁣⁤﻿­᠎"
BIDI_CONTROLS = "‪‫‬‭‮⁦⁧⁨⁩"
_ZERO_WIDTH_RE = re.compile(f"[{ZERO_WIDTH}]")
_BIDI_RE = re.compile(f"[{BIDI_CONTROLS}]")
# C0/C1 control characters except tab and newline.
_CONTROL_RE = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")
_SPACES_RE = re.compile(r"[^\S\n]+")
_BLANK_LINES_RE = re.compile(r"\n{3,}")


def clean_text(text: str) -> tuple[str, list[str]]:
    """Unicode-normalise (NFKC), drop invisible/control characters, and tidy whitespace.

    Returns the cleaned text and the kinds of thing that were removed.
    """
    removed: list[str] = []
    text = unicodedata.normalize("NFKC", text)
    for kind, pattern in (("zero_width_chars", _ZERO_WIDTH_RE), ("bidi_controls", _BIDI_RE),
                          ("control_chars", _CONTROL_RE)):
        text, n = pattern.subn("", text)
        if n:
            removed.append(kind)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = _SPACES_RE.sub(" ", text)
    text = "\n".join(line.strip() for line in text.split("\n"))
    text = _BLANK_LINES_RE.sub("\n\n", text).strip()
    return text, removed


def normalise_for_match(text: str) -> str:
    """Canonical form for comparing a quotation with its source: cleaned, whitespace
    collapsed to single spaces, case preserved."""
    cleaned, _ = clean_text(text)
    return " ".join(cleaned.split())


def quote_in_source(quote: str, source: str) -> bool:
    """Verbatim-quote check: the quotation must occur in the source after normalisation."""
    q = normalise_for_match(quote)
    return bool(q) and q in normalise_for_match(source)
