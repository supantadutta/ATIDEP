"""Parsers for the supported input types: HTML, plain text, PDF, RSS/Atom and JSON feeds
(blueprint §17.1, §19.3).

Type detection uses content (magic bytes and structure), never the file name or the declared
content type alone. XML is parsed with defusedxml (no entity expansion, no DTDs). PDFs are
parsed in a child process with CPU, memory and size limits.
"""

from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from enum import StrEnum
from pathlib import Path

from defusedxml import ElementTree as SafeET
from defusedxml.common import DefusedXmlException

PDF_MAGIC = b"%PDF-"
_REPO_ROOT = Path(__file__).resolve().parents[2]


class Kind(StrEnum):
    PDF = "pdf"
    HTML = "html"
    TEXT = "text"
    RSS = "rss"
    ATOM = "atom"
    JSON_FEED = "json_feed"


class ParseError(Exception):
    pass


def decode_text(data: bytes, charset: str | None = None) -> str:
    for enc in ([charset] if charset else []) + ["utf-8-sig"]:
        try:
            return data.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return data.decode("latin-1")


def detect_kind(data: bytes) -> Kind:
    if not data.strip():
        raise ParseError("empty document")
    head = data[:2048].lstrip()
    if head.startswith(PDF_MAGIC):
        return Kind.PDF
    lowered = head.lower()
    if lowered.startswith(b"{") or lowered.startswith(b"["):
        try:
            doc = json.loads(decode_text(data))
        except ValueError:
            return Kind.TEXT
        if isinstance(doc, dict) and "items" in doc:
            return Kind.JSON_FEED
        if isinstance(doc, list) and doc and all(isinstance(x, dict) for x in doc):
            return Kind.JSON_FEED
        return Kind.TEXT
    if lowered.startswith(b"<?xml") or lowered.startswith(b"<rss") or lowered.startswith(b"<feed"):
        if b"<rss" in data[:4096].lower():
            return Kind.RSS
        if b"<feed" in data[:4096].lower():
            return Kind.ATOM
        raise ParseError("XML that is neither RSS nor Atom")
    if b"\x00" in data[:4096]:
        raise ParseError("binary content is not supported")
    if any(tag in lowered for tag in (b"<!doctype html", b"<html", b"<body", b"<head", b"<p>",
                                      b"<div", b"<article", b"<h1")):
        return Kind.HTML
    return Kind.TEXT


# ---- PDF in a sandboxed child process -----------------------------------------------------
def pdf_to_text(data: bytes, *, timeout: float = 30.0, memory_mb: int = 1024,
                cpu_seconds: int = 20) -> str:
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "components.c1_ingest._pdf_worker", str(memory_mb),
             str(cpu_seconds)],
            input=data, capture_output=True, timeout=timeout, cwd=_REPO_ROOT, check=False)
    except subprocess.TimeoutExpired as exc:
        raise ParseError("PDF parsing timed out") from exc
    if proc.returncode != 0:
        try:
            reason = json.loads(proc.stdout or b"{}").get("error")
        except ValueError:
            reason = None
        raise ParseError(f"PDF could not be parsed ({reason or 'worker failed'})")
    try:
        return json.loads(proc.stdout)["text"]
    except (ValueError, KeyError) as exc:
        raise ParseError("PDF worker returned invalid output") from exc


# ---- feeds ---------------------------------------------------------------------------------
@dataclass
class FeedItem:
    title: str
    link: str | None
    published_at: datetime | None
    content: str  # HTML or text; may be empty if the feed only carries a link


def _utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt.astimezone(UTC)


def _parse_date(value: str | None) -> datetime | None:
    if not value:
        return None
    value = value.strip()
    try:
        return _utc(parsedate_to_datetime(value))
    except (TypeError, ValueError):
        pass
    try:
        return _utc(datetime.fromisoformat(value.replace("Z", "+00:00")))
    except ValueError:
        return None


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _child_text(el, name: str) -> str:
    for c in el:
        if _local(c.tag) == name:
            return "".join(c.itertext()).strip()
    return ""


def parse_xml_feed(data: bytes) -> list[FeedItem]:
    try:
        root = SafeET.fromstring(data, forbid_dtd=True)
    except (SafeET.ParseError, DefusedXmlException) as exc:
        raise ParseError(f"feed XML rejected: {exc}") from exc
    items: list[FeedItem] = []
    if _local(root.tag) == "rss":
        for el in root.iter():
            if _local(el.tag) != "item":
                continue
            content = _child_text(el, "encoded") or _child_text(el, "description")
            items.append(FeedItem(_child_text(el, "title"), _child_text(el, "link") or None,
                                  _parse_date(_child_text(el, "pubDate")), content))
    elif _local(root.tag) == "feed":
        for el in root:
            if _local(el.tag) != "entry":
                continue
            link = None
            for c in el:
                if _local(c.tag) == "link" and c.attrib.get("rel", "alternate") == "alternate":
                    link = c.attrib.get("href")
                    break
            content = _child_text(el, "content") or _child_text(el, "summary")
            date = _child_text(el, "published") or _child_text(el, "updated")
            items.append(FeedItem(_child_text(el, "title"), link, _parse_date(date), content))
    else:
        raise ParseError("not an RSS or Atom document")
    return items


def parse_json_feed(data: bytes) -> list[FeedItem]:
    try:
        doc = json.loads(decode_text(data))
    except ValueError as exc:
        raise ParseError("invalid JSON") from exc
    raw_items = doc.get("items", []) if isinstance(doc, dict) else doc
    items: list[FeedItem] = []
    for it in raw_items:
        if not isinstance(it, dict):
            continue
        content = it.get("content_html") or it.get("content_text") or it.get("content") or \
            it.get("summary") or ""
        link = it.get("url") or it.get("link")
        date = it.get("date_published") or it.get("published") or it.get("date")
        items.append(FeedItem(
            str(it.get("title", "")).strip(), link if isinstance(link, str) else None,
            _parse_date(str(date)) if date else None, str(content)))
    return items
