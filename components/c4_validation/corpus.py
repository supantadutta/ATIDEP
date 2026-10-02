"""Event corpora for gates G8-G11 (blueprint §27.7).

A *test set* belongs to one detection opportunity: positive events the rule must match, negative
events and benign look-alikes it must not. The *benign baseline* is shared and measures breadth.
Events are structured Sysmon events (``{"win": {"system": ..., "eventdata": ...}}``) and are
identified by ``eventRecordID``, which must be unique across everything replayed together.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

LABELS = {"positive": "positive", "negative": "negative", "lookalike": "benign_lookalike"}


class CorpusError(Exception):
    pass


@dataclass(frozen=True)
class TestEvent:
    __test__ = False                       # not a pytest class

    name: str
    event: dict[str, Any]

    @property
    def record_id(self) -> str:
        return str(self.event["win"]["system"]["eventRecordID"])


@dataclass
class TestSet:
    __test__ = False

    set_id: str
    positive: list[TestEvent] = field(default_factory=list)
    negative: list[TestEvent] = field(default_factory=list)
    lookalike: list[TestEvent] = field(default_factory=list)

    def all_events(self) -> list[TestEvent]:
        return self.positive + self.negative + self.lookalike


def _read(path: Path) -> TestEvent:
    try:
        ev = json.loads(path.read_text(encoding="utf-8"))
        _ = TestEvent(path.name, ev).record_id                # shape check
    except (ValueError, KeyError, TypeError) as exc:
        raise CorpusError(f"{path} is not a structured Sysmon event: {exc}") from exc
    return TestEvent(path.name, ev)


def check_unique(*groups: list[TestEvent]) -> None:
    seen: dict[str, str] = {}
    for g in groups:
        for e in g:
            if e.record_id in seen:
                raise CorpusError(f"eventRecordID {e.record_id} is used by both {seen[e.record_id]}"
                                  f" and {e.name}")
            seen[e.record_id] = e.name


def load_test_set(root: Path | str, set_id: str | None = None) -> TestSet:
    root = Path(root)
    ts = TestSet(set_id or root.name)
    for attr, sub in LABELS.items():
        d = root / sub
        if d.is_dir():
            setattr(ts, attr, [_read(p) for p in sorted(d.glob("*.json"))])
    check_unique(ts.positive, ts.negative, ts.lookalike)
    return ts


def load_baseline(path: Path | str) -> list[TestEvent]:
    p = Path(path)
    if p.is_dir():
        events = [_read(f) for f in sorted(p.glob("*.json"))]
    else:
        events = []
        for i, line in enumerate(p.read_text(encoding="utf-8").splitlines()):
            if line.strip():
                ev = TestEvent(f"{p.name}:{i + 1}", json.loads(line))
                _ = ev.record_id                               # shape check
                events.append(ev)
    check_unique(events)
    return events


def corpus_sha256(events: list[TestEvent]) -> str:
    h = hashlib.sha256()
    for e in sorted(events, key=lambda x: x.record_id):
        h.update(json.dumps(e.event, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    return h.hexdigest()
