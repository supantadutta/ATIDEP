"""Collectors: uploads, allowlisted URLs and feeds -> sanitised documents (blueprint §17.1).

Each collector returns :class:`Collected` records holding the raw evidence bytes untouched and
the sanitised text that later stages may use. No collector writes to the database or the
evidence store; that is the job of ``app.services.ingest``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Protocol

from components.c1_ingest.parsers import (
    FeedItem,
    Kind,
    ParseError,
    decode_text,
    detect_kind,
    parse_json_feed,
    parse_xml_feed,
    pdf_to_text,
)
from components.c1_ingest.sanitise import SanitisedText, sanitise_html, sanitise_plain
from components.c1_ingest.ssrf import FetchError, FetchResult

MIN_TEXT_CHARS = 40
INLINE_CONTENT_MIN_CHARS = 400
MAX_UPLOAD_BYTES = 10 * 1024 * 1024


class Fetcher(Protocol):
    def fetch(self, url: str) -> FetchResult: ...


@dataclass
class Collected:
    source_name: str
    title: str
    url: str | None
    published_at: datetime | None
    retrieved_at: datetime
    raw: bytes
    kind: Kind
    sanitised: SanitisedText

    @property
    def text(self) -> str:
        return self.sanitised.text


@dataclass
class FeedResult:
    documents: list[Collected] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def _now() -> datetime:
    return datetime.now(UTC)


def collect_bytes(data: bytes, *, source_name: str, url: str | None = None,
                  title: str | None = None, published_at: datetime | None = None,
                  content_type: str | None = None, max_bytes: int = MAX_UPLOAD_BYTES,
                  retrieved_at: datetime | None = None) -> Collected:
    """One document from raw bytes. Feed documents are rejected here; use ``collect_feed_bytes``."""
    if len(data) > max_bytes:
        raise ParseError(f"document is larger than {max_bytes} bytes")
    kind = detect_kind(data)
    if kind in (Kind.RSS, Kind.ATOM, Kind.JSON_FEED):
        raise ParseError("this is a feed; ingest it with the feed collector")
    charset = None
    if content_type and "charset=" in content_type:
        charset = content_type.split("charset=", 1)[1].split(";")[0].strip() or None
    if kind is Kind.PDF:
        sanitised = sanitise_plain(pdf_to_text(data))
    elif kind is Kind.HTML:
        sanitised = sanitise_html(decode_text(data, charset))
    else:
        sanitised = sanitise_plain(decode_text(data, charset))
    if len(sanitised.text) < MIN_TEXT_CHARS:
        raise ParseError("no readable text in the document")
    return Collected(source_name=source_name, title=(title or sanitised.title or "").strip()
                     or "(untitled)", url=url, published_at=published_at,
                     retrieved_at=retrieved_at or _now(), raw=data, kind=kind,
                     sanitised=sanitised)


def collect_url(fetcher: Fetcher, url: str, *, source_name: str,
                title: str | None = None, published_at: datetime | None = None) -> Collected:
    result = fetcher.fetch(url)
    return collect_bytes(result.body, source_name=source_name, url=result.url, title=title,
                         published_at=published_at, content_type=result.content_type)


def _items_from(data: bytes) -> list[FeedItem]:
    kind = detect_kind(data)
    if kind in (Kind.RSS, Kind.ATOM):
        return parse_xml_feed(data)
    if kind is Kind.JSON_FEED:
        return parse_json_feed(data)
    raise ParseError("not a feed document")


def collect_feed_bytes(data: bytes, *, source_name: str, fetcher: Fetcher | None = None,
                       max_items: int = 50, fetch_articles: bool = True) -> FeedResult:
    """Items of a feed. Inline content is used when it is substantial; otherwise the linked
    article is fetched (through the SSRF-safe fetcher) if a fetcher is available."""
    result = FeedResult()
    for item in _items_from(data)[:max_items]:
        try:
            inline = sanitise_html(item.content) if item.content else None
            if inline and len(inline.text) >= INLINE_CONTENT_MIN_CHARS:
                result.documents.append(Collected(
                    source_name=source_name, title=item.title or inline.title or "(untitled)",
                    url=item.link, published_at=item.published_at, retrieved_at=_now(),
                    raw=item.content.encode("utf-8"), kind=Kind.HTML, sanitised=inline))
            elif item.link and fetcher is not None and fetch_articles:
                result.documents.append(collect_url(
                    fetcher, item.link, source_name=source_name, title=item.title,
                    published_at=item.published_at))
            else:
                result.errors.append(f"{item.link or item.title!r}: no usable content")
        except (ParseError, FetchError) as exc:
            result.errors.append(f"{item.link or item.title!r}: {exc}")
    return result


def collect_feed(fetcher: Fetcher, feed_url: str, *, source_name: str, max_items: int = 50,
                 fetch_articles: bool = True) -> FeedResult:
    fetched = fetcher.fetch(feed_url)
    return collect_feed_bytes(fetched.body, source_name=source_name, fetcher=fetcher,
                              max_items=max_items, fetch_articles=fetch_articles)
