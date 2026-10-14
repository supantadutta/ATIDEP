"""Measured quantities from the exported results (``research.export``), per item.

Three rules keep the numbers honest:

* **One plane per ratio.** Model usage, machine time and generated/valid rule counts come from
  the experiment's runs (``runs.csv``, condition B). Analyst time, dispositions and approved or
  deployed rules come from the live application's database (``analyst_effort.csv``,
  ``live_rules.csv``). They are joined by the item's content hash and never added together.
* **Missing is missing.** An item whose runs did not report provider token counts has *no*
  token figure (not zero); an item with no analyst session has no analyst time.
* **Production cost is one reviewed run per item.** The mean over the item's runs is the expected
  usage; runs beyond that, the ablations and the single-prompt baseline are research overhead and
  are reported apart. A run stopped by the spend cap is missing data and is left out; any other
  failure stays in (intention to treat), with what it spent.
"""

from __future__ import annotations

import csv
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from statistics import fmean

from research.economics.ledger import Quantities


def _f(v: str | None) -> float | None:
    try:
        return float(v) if v not in (None, "", "None") else None
    except ValueError:
        return None


def _b(v: str | None) -> bool | None:
    return None if v in (None, "", "None") else v == "True"


def _mean(xs: list[float | None]) -> float | None:
    ys = [x for x in xs if x is not None]
    return fmean(ys) if ys and len(ys) == len(xs) else None


@dataclass
class ItemMeasure:
    item: str
    item_key: str | None
    category: str | None = None
    runs: int = 0
    tokens_in: float | None = None
    tokens_out: float | None = None
    automated_h: float | None = None
    inference_h: float | None = None
    generated: float | None = None
    assessed: float | None = None
    valid: float | None = None
    analyst_h: dict[str, float | None] = field(default_factory=dict)       # by condition
    accepted: dict[str, bool | None] = field(default_factory=dict)         # by condition
    approved_rules: int | None = None
    deployed_rules: int | None = None


@dataclass
class Overhead:
    """What the runs other than the one reviewed run per item used, by condition, in the
    physical units they were measured in (fresh calls only)."""

    runs: int = 0
    input_tokens: float = 0.0
    output_tokens: float = 0.0
    automated_s: float = 0.0
    model_wait_s: float = 0.0
    tokens_reliable: bool = True


@dataclass
class Measured:
    items: list[ItemMeasure]
    overhead: dict[str, Overhead]
    budget_stopped: int = 0
    runs_by_condition: dict[str, int] = field(default_factory=dict)

    def quantities(self, items_per_month: float, *, condition: str = "B",
                   storage_gb: float | None = None, siem_ingest_gb: float | None = None,
                   endpoints: float | None = None) -> Quantities:
        """Per-item means (ratio of sums over items, so the item mix is the test set's) turned
        into the quantities the ledger needs. Anything missing for any item is missing here."""
        it = self.items

        def mean(attr: str) -> float | None:
            return _mean([getattr(i, attr) for i in it]) if it else None

        review = {c: _mean([i.analyst_h.get(c) for i in it]) if it else None for c in ("A", "B")}
        t_in, t_out = mean("tokens_in"), mean("tokens_out")
        return Quantities(
            items_per_month=items_per_month, review_hours_per_item=review,
            automated_hours_per_item=mean("automated_h"),
            inference_hours_per_item=mean("inference_h"),
            local_tokens=(t_in, t_out) if t_in is not None and t_out is not None else None,
            storage_gb=storage_gb, siem_ingest_gb=siem_ingest_gb, endpoints=endpoints)

    def rate(self, attr: str) -> float | None:
        """Mean per item of a count (generated, assessed, valid), or None if any is missing."""
        return _mean([getattr(i, attr) for i in self.items]) if self.items else None

    def accepted_rate(self, condition: str) -> float | None:
        xs = [i.accepted.get(condition) for i in self.items]
        if not xs or any(x is None for x in xs):
            return None
        return sum(bool(x) for x in xs) / len(xs)

    def approved_rate(self) -> float | None:
        xs = [i.approved_rules for i in self.items]
        return None if not xs or any(x is None for x in xs) else sum(xs) / len(xs)  # type: ignore

    def deployed_rate(self) -> float | None:
        xs = [i.deployed_rules for i in self.items]
        return None if not xs or any(x is None for x in xs) else sum(xs) / len(xs)  # type: ignore

    def resample(self, indices: list[int]) -> Measured:
        return Measured([self.items[i] for i in indices], self.overhead, self.budget_stopped,
                        self.runs_by_condition)


def _read(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open(newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def load_measured(export_dir: Path | str, categories: dict[str, str] | None = None) -> Measured:
    d = Path(export_dir)
    runs, analyst, live = _read(d / "runs.csv"), _read(d / "analyst_effort.csv"), _read(
        d / "live_rules.csv")
    by_item: dict[str, list[dict[str, str]]] = defaultdict(list)
    overhead: dict[str, Overhead] = defaultdict(Overhead)
    budget = 0
    counts: dict[str, int] = defaultdict(int)
    for r in runs:
        counts[r["condition"]] += 1
        if _b(r.get("budget_exceeded")):
            budget += 1
            continue
        h = overhead[r["condition"]]
        h.runs += 1
        h.input_tokens += _f(r.get("cost.input_tokens")) or 0.0
        h.output_tokens += _f(r.get("cost.output_tokens")) or 0.0
        h.automated_s += _f(r.get("cost.time.automated_seconds")) or 0.0
        h.model_wait_s += _f(r.get("cost.time.model_wait_seconds")) or 0.0
        h.tokens_reliable = h.tokens_reliable and bool(_b(r.get("cost.tokens_reliable")))
        if r["condition"] == "B":
            by_item[r["item"]].append(r)

    items: list[ItemMeasure] = []
    for name, rs in sorted(by_item.items()):
        key = rs[0].get("item_key") or None
        im = ItemMeasure(name, key, (categories or {}).get(name), runs=len(rs))
        reliable = all(_b(r.get("cost.tokens_reliable")) for r in rs)
        if reliable:
            im.tokens_in = _mean([_f(r.get("cost.input_tokens")) for r in rs])
            im.tokens_out = _mean([_f(r.get("cost.output_tokens")) for r in rs])
        im.automated_h = _scaled(_mean([_f(r.get("cost.time.automated_seconds")) for r in rs]))
        im.inference_h = _scaled(_mean([_f(r.get("cost.time.model_wait_seconds")) for r in rs]))
        im.generated = _mean([(_f(r.get("rules.sigma_rules")) or 0) + (
            _f(r.get("rules.ioc_bundles")) or 0) for r in rs])
        im.assessed = _mean([_f(r.get("rules.assessed")) for r in rs])
        im.valid = _mean([_f(r.get("rules.validated")) for r in rs])
        sessions = [a for a in analyst if key and a.get("item_key") == key
                    and a.get("activity") != "operations"]
        for cond in ("A", "B"):
            mine = [a for a in sessions if a["condition"] == cond]
            if mine:
                im.analyst_h[cond] = sum(_f(a["active_seconds"]) or 0.0 for a in mine) / 3600.0
                last = mine[-1].get("disposition")
                im.accepted[cond] = None if last in (None, "", "in_progress") else (
                    last == "accepted")
        if live and key:
            rules = [x for x in live if x["item_key"] == key]
            im.approved_rules = sum(_b(x["approved"]) is True for x in rules)
            im.deployed_rules = sum(_b(x["deployed_lab"]) is True for x in rules)
        items.append(im)
    return Measured(items, dict(overhead), budget, dict(counts))


def _scaled(seconds: float | None) -> float | None:
    return None if seconds is None else seconds / 3600.0
