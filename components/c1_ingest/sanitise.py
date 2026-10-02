"""Turn untrusted content into the text a language model is allowed to see (blueprint §17.1).

The raw bytes are always kept as evidence; only the sanitised text reaches an LLM. HTML is
reduced to visible text: scripts, styles, comments and elements hidden by attributes or inline
CSS are dropped, then invisible Unicode is removed. What was removed is recorded.

Limits: text hidden only by a stylesheet class, or coloured like its background, cannot be
detected without rendering the page, so it stays in the sanitised text. The verbatim-quote
check and human review remain the later defences.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from html.parser import HTMLParser

from components.c1_ingest.text import clean_text

VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param",
        "source", "track", "wbr"}
DROP_CONTENT = {"script", "style", "noscript", "template", "iframe", "object", "embed", "svg",
                "canvas", "head", "select", "option", "textarea", "button"}
BLOCK = {"p", "div", "br", "li", "ul", "ol", "tr", "table", "h1", "h2", "h3", "h4", "h5", "h6",
         "section", "article", "header", "footer", "pre", "blockquote", "hr", "dt", "dd", "td",
         "th"}

_HIDDEN_STYLE = re.compile(
    r"display\s*:\s*none|visibility\s*:\s*(hidden|collapse)|opacity\s*:\s*0(\.0*)?\s*(;|$)"
    r"|font-size\s*:\s*0(px|pt|em|rem|%)?\s*(;|$)|(left|top|margin-left|text-indent)\s*:\s*-\d{3,}"
    r"|color\s*:\s*transparent|(max-)?(height|width)\s*:\s*0(px)?\s*;[^\"']*overflow\s*:\s*hidden",
    re.I)


@dataclass
class SanitisedText:
    text: str
    stripped: list[str] = field(default_factory=list)
    title: str | None = None


class _Extractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.stripped: set[str] = set()
        self.title: str | None = None
        self._stack: list[tuple[str, bool, str | None]] = []  # (tag, hidden, drop-kind)
        self._in_title = False

    @property
    def _suppressed(self) -> bool:
        return any(hidden or drop for _tag, hidden, drop in self._stack)

    @staticmethod
    def _is_hidden(attrs: list[tuple[str, str | None]]) -> bool:
        a = {k.lower(): (v or "") for k, v in attrs}
        if "hidden" in a:
            return True
        if a.get("aria-hidden", "").strip().lower() == "true":
            return True
        return bool(_HIDDEN_STYLE.search(a.get("style", "")))

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        if tag == "title":
            self._in_title = True
        if tag in BLOCK and not self._suppressed:
            self.parts.append("\n")
        if tag in VOID:
            return
        hidden = self._is_hidden(attrs)
        drop = tag in DROP_CONTENT
        if hidden and tag not in DROP_CONTENT:
            self.stripped.add("hidden_html")
        if drop and tag in {"script", "style"}:
            self.stripped.add(tag)
        self._stack.append((tag, hidden, tag if drop else None))

    def handle_startendtag(self, tag, attrs):
        if tag.lower() in BLOCK and not self._suppressed:
            self.parts.append("\n")

    def handle_endtag(self, tag):
        tag = tag.lower()
        if tag == "title":
            self._in_title = False
        for i in range(len(self._stack) - 1, -1, -1):
            if self._stack[i][0] == tag:
                del self._stack[i:]
                break
        if tag in BLOCK and not self._suppressed:
            self.parts.append("\n")

    def handle_data(self, data):
        if self._in_title:
            self.title = (self.title or "") + data
        if self._suppressed:
            # Report only text hidden by attributes or CSS; structural drops (head, script,
            # style) are expected on every page and are not signs of hidden content.
            if data.strip() and any(hidden for _tag, hidden, _drop in self._stack):
                self.stripped.add("hidden_html")
            return
        self.parts.append(data)

    def handle_comment(self, data):
        if data.strip():
            self.stripped.add("html_comment")


def sanitise_html(html: str) -> SanitisedText:
    parser = _Extractor()
    parser.feed(html)
    parser.close()
    text, removed = clean_text("".join(parser.parts))
    title, _ = clean_text(parser.title) if parser.title else (None, [])
    return SanitisedText(text=text, stripped=sorted(parser.stripped | set(removed)), title=title)


def sanitise_plain(text: str) -> SanitisedText:
    cleaned, removed = clean_text(text)
    return SanitisedText(text=cleaned, stripped=sorted(removed))
