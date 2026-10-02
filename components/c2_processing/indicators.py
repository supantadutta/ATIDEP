"""Deterministic indicator extraction (blueprint §17.2.1).

Finds IPs, domains, URLs, hashes and CVE IDs in sanitised text, including defanged forms
(``hxxp``, ``[.]``). Every indicator carries the exact character span in the text it was found
in, so its quotation is verbatim by construction. Indicators are classified, not judged:

* ``reserved``: private, loopback, link-local, documentation and other non-public addresses;
* ``benign``: first-party or reference domains from the allowlist (and the report publisher's
  own domain), kept as ``reference_only`` and never placed in a detection list;
* ``context``: ``malicious`` only when the surrounding text uses clear threat-actor wording,
  otherwise ``unknown``. This is a heuristic that the extraction experiment measures; it is
  not enrichment and not a verdict.
"""

from __future__ import annotations

import bisect
import ipaddress
import json
import re
from dataclasses import dataclass
from pathlib import Path

import tldextract

from components.c1_ingest.ssrf import host_allowed, is_public_address
from schemas.claim import IndicatorContext, IndicatorType

BENIGN_DOMAINS_PATH = Path(__file__).resolve().parents[2] / "knowledge" / "benign_domains.json"
INERT_TLDS = frozenset({"invalid", "test", "example"})
# Real TLDs that are far more often file names in reports (install.sh, config.py, README.md).
FILE_LIKE_TLDS = frozenset({"sh", "py", "pl", "rb", "rs", "md", "js", "so", "ps", "pm", "cs",
                            "vb", "jar"})

_DOT = r"(?:\.|\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\))"
_URL = re.compile(r"\b(?:https?|hxxps?|h\*\*ps?)(?:://|\[:\]//|\[://\]|:\[//\]|\[:\]\[//\])"
                  r"[^\s<>\"'`]+", re.I)
_IPV4 = re.compile(rf"(?<![\w.])((?:\d{{1,3}}{_DOT}){{3}}\d{{1,3}})(?![\w])(?!{_DOT}\d)", re.I)
_IPV6 = re.compile(r"(?<![\w:])((?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4})(?![\w:])", re.I)
_HASH = re.compile(r"(?<![0-9a-fA-F])([0-9a-fA-F]{64}|[0-9a-fA-F]{40}|[0-9a-fA-F]{32})"
                   r"(?![0-9a-fA-F])")
_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_DOMAIN = re.compile(rf"(?<![\w@.\-/])((?:{_LABEL}{_DOT})+[a-z]{{2,24}})(?![\w\-])", re.I)
_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
_MALICIOUS_CUES = re.compile(
    r"\b(c2|c&c|command[- ]and[- ]control|beacon\w*|exfiltrat\w*|malicious|payload"
    r"|stag(?:e|es|ed|ing)"
    r"|download(?:s|ed|ing)?|call(?:s|ed)? back|callback|dropper|loader|phishing|"
    r"(?:contact|connect|communicat)(?:s|ed|ing)? (?:to|with)|resolv(?:es|ed|ing)? to|"
    r"hosted on|served from|indicators? of compromise|iocs?)\b", re.I)

# Sites where anyone can publish content: a bare domain is a reference, but a deep URL on them
# can be attacker content (a release asset, a post) and is kept as a URL indicator.
USER_CONTENT_DOMAINS = frozenset({"twitter.com", "x.com", "youtube.com", "facebook.com",
                                  "reddit.com", "linkedin.com", "medium.com", "github.com"})
_SENT_BREAK = re.compile(r"(?<=[.!?])\s+(?=[A-Z0-9\"'(\[])|\n{2,}")

_tld = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)


@dataclass(frozen=True)
class Indicator:
    type: IndicatorType
    value: str          # canonical: refanged, lower-cased where the type is case-insensitive
    quote: str          # exactly text[start:end]
    start: int
    end: int
    defanged: bool
    reserved: bool = False
    benign: bool = False
    context: IndicatorContext = IndicatorContext.UNKNOWN


def refang(value: str) -> str:
    v = re.sub(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)", ".", value, flags=re.I)
    v = re.sub(r"^(?:hxxp|h\*\*p)", "http", v, flags=re.I)
    v = v.replace("[://]", "://").replace("[:]//", "://").replace(":[//]", "://")
    v = v.replace("[:]", ":").replace("[@]", "@").replace("[at]", "@")
    return v


def load_benign_domains(path: Path | str = BENIGN_DOMAINS_PATH) -> list[str]:
    return list(json.loads(Path(path).read_text(encoding="utf-8"))["domains"])


def _boundaries(text: str) -> list[tuple[int, int]]:
    """(start, end) of each sentence or block, split on sentence punctuation and blank lines."""
    spans, last = [], 0
    for m in _SENT_BREAK.finditer(text):
        spans.append((last, m.start()))
        last = m.end()
    spans.append((last, len(text)))
    return spans


def _context(text: str, start: int, end: int, spans: list[tuple[int, int]]) -> IndicatorContext:
    """Threat wording must be in the indicator's own sentence or list block."""
    i = max(0, bisect.bisect_right([s for s, _ in spans], start) - 1)
    s, e = spans[i]
    return IndicatorContext.MALICIOUS if _MALICIOUS_CUES.search(text[s:e]) \
        else IndicatorContext.UNKNOWN


def _trim_url(raw: str) -> str:
    while raw and (raw[-1] in ".,;:!?)}>'\"" or
                   (raw[-1] == "]" and raw.count("]") > raw.count("["))):
        raw = raw[:-1]
    return raw


def _host_of(url: str) -> str:
    m = re.match(r"https?://(?:[^@/]*@)?([^/:?#]+)", url, re.I)
    return m.group(1).lower() if m else ""


def _valid_domain(host: str, allow_test_tlds: bool) -> bool:
    if len(host) > 253 or ".." in host or host.startswith(("-", ".")):
        return False
    labels = host.split(".")
    if any(not lab or len(lab) > 63 for lab in labels) or len(labels) < 2:
        return False
    tld = labels[-1]
    if tld.isdigit():
        return False
    if allow_test_tlds and tld in INERT_TLDS:
        return True
    if tld in FILE_LIKE_TLDS and len(labels) == 2:
        return False
    parts = _tld(host)
    return bool(parts.suffix and parts.domain)


def extract_indicators(text: str, *, benign_domains: tuple[str, ...] | list[str] = (),
                       publisher_domains: tuple[str, ...] | list[str] = (),
                       allow_test_tlds: bool = False) -> list[Indicator]:
    benign = tuple(benign_domains) + tuple(publisher_domains)
    spans = _boundaries(text)
    found: list[Indicator] = []
    occupied: list[tuple[int, int]] = []   # IP and URL spans, so a domain inside them is skipped

    def add(kind, raw, start, end, value, *, reserved=False, is_benign=False):
        ctx = IndicatorContext.REFERENCE_ONLY if (reserved or is_benign) \
            else _context(text, start, end, spans)
        found.append(Indicator(kind, value, text[start:end], start, end, defanged=raw != value,
                               reserved=reserved, benign=is_benign, context=ctx))

    for m in _URL.finditer(text):
        raw = _trim_url(m.group(0))
        start, end = m.start(), m.start() + len(raw)
        value = refang(raw)
        host = _host_of(value)
        if not host or (not _valid_domain(host, allow_test_tlds) and not _is_ip(host)):
            continue
        path_empty = re.sub(r"^https?://[^/]+/?$", "", value, flags=re.I) == ""
        reference_host = host_allowed(host, benign)
        user_content = host_allowed(host, USER_CONTENT_DOMAINS)
        add(IndicatorType.URL, raw, start, end, value,
            is_benign=bool(reference_host and (path_empty or not user_content)))
        occupied.append((start, end))

    for m in _IPV4.finditer(text):
        raw = m.group(1)
        value = refang(raw)
        try:
            ip = ipaddress.IPv4Address(value)
        except ValueError:
            continue
        add(IndicatorType.IPV4, raw, m.start(1), m.end(1), str(ip),
            reserved=not is_public_address(str(ip)))
        occupied.append((m.start(1), m.end(1)))

    for m in _IPV6.finditer(text):
        raw = m.group(1)
        if "::" not in raw and raw.count(":") != 7:
            continue
        try:
            ip = ipaddress.IPv6Address(raw)
        except ValueError:
            continue
        add(IndicatorType.IPV6, raw, m.start(1), m.end(1), str(ip),
            reserved=not is_public_address(str(ip)))
        occupied.append((m.start(1), m.end(1)))

    for m in _HASH.finditer(text):
        raw = m.group(1)
        kind = {32: IndicatorType.MD5, 40: IndicatorType.SHA1, 64: IndicatorType.SHA256}[len(raw)]
        add(kind, raw, m.start(1), m.end(1), raw.lower())
        occupied.append((m.start(1), m.end(1)))

    for m in _DOMAIN.finditer(text):
        start, end = m.start(1), m.end(1)
        if any(a <= start and end <= b for a, b in occupied):
            continue
        raw = m.group(1)
        value = refang(raw).lower().rstrip(".")
        if _is_ip(value) or not _valid_domain(value, allow_test_tlds):
            continue
        add(IndicatorType.DOMAIN, raw, start, end, value, is_benign=host_allowed(value, benign))

    unique: dict[tuple[IndicatorType, str], Indicator] = {}
    for ind in sorted(found, key=lambda i: i.start):
        unique.setdefault((ind.type, ind.value), ind)
    return list(unique.values())


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


@dataclass(frozen=True)
class CveMention:
    value: str
    quote: str
    start: int
    end: int


def extract_cves(text: str) -> list[CveMention]:
    seen: dict[str, CveMention] = {}
    for m in _CVE.finditer(text):
        value = m.group(0).upper()
        seen.setdefault(value, CveMention(value, text[m.start():m.end()], m.start(), m.end()))
    return list(seen.values())
