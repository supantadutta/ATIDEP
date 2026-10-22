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
  are reported apart. A run stopped by the spend cap is missing data and is left out, and an item
  whose every run was stopped is listed (``dropped_items``), never silently lost; any other
  failure stays in (intention to treat), with what it spent and with zero detections.
* **Each arm is measured on its own runs.** Condition B on the local model and condition B on a
  hosted model (the S-OSS-API arm, a run whose provider is ``cloud-*``) are kept apart; detection
  counts are kept per condition, so the manual scenario is divided by the manual arm's rules.
  Model waiting time is taken only from runs without replayed calls (a replayed call waited for
  nothing). Analyst time is summed per analyst and then averaged over analysts, so an independent
  analyst who repeats an item is not added to the primary analyst's time.
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
    order_set: str | None = None          # X: manual first; Y: ATIDEP first
    runs: int = 0
    tokens_in: float | None = None
    tokens_out: float | None = None
    automated_h: float | None = None
    inference_h: float | None = None
    generated: float | None = None            # condition B (local model)
    assessed: float | None = None
    valid: float | None = None
    counts_by_condition: dict[str, dict[str, float | None]] = field(default_factory=dict)
    cloud_tokens_in: float | None = None      # condition B on a hosted model, if that arm ran
    cloud_tokens_out: float | None = None
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
    dropped_items: list[str] = field(default_factory=list)   # every run stopped by the cap
    hosted_runs: int = 0
    replayed_runs_without_wait: int = 0    # left out of the model-waiting time
    operations_hours: float | None = None  # the 'operations' timer, a floor for maintenance
    analysts: list[str] = field(default_factory=list)

    def report(self) -> dict[str, object]:
        """What the measurement covers, for the report: nothing here is used silently."""
        return {"items": len(self.items), "dropped_items": self.dropped_items,
                "budget_stopped_runs": self.budget_stopped,
                "runs_by_condition": self.runs_by_condition, "hosted_runs": self.hosted_runs,
                "replayed_runs_left_out_of_model_wait": self.replayed_runs_without_wait,
                "operations_hours_measured": self.operations_hours, "analysts": self.analysts,
                "research_overhead": {c: vars(o) for c, o in sorted(self.overhead.items())}}

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
        c_in, c_out = mean("cloud_tokens_in"), mean("cloud_tokens_out")
        return Quantities(
            items_per_month=items_per_month, review_hours_per_item=review,
            automated_hours_per_item=mean("automated_h"),
            inference_hours_per_item=mean("inference_h"),
            local_tokens=(t_in, t_out) if t_in is not None and t_out is not None else None,
            cloud_tokens=(c_in, c_out) if c_in is not None and c_out is not None else None,
            storage_gb=storage_gb, siem_ingest_gb=siem_ingest_gb, endpoints=endpoints)

    def rate(self, attr: str, condition: str = "B") -> float | None:
        """Mean per item of a count (generated, assessed, valid) in one condition's runs, or None
        if any item lacks it."""
        if not self.items:
            return None
        if condition == "B":
            return _mean([getattr(i, attr) for i in self.items])
        return _mean([i.counts_by_condition.get(condition, {}).get(attr) for i in self.items])

    def accepted_rate(self, condition: str) -> float | None:
        xs = [i.accepted.get(condition) for i in self.items]
        if not xs or any(x is None for x in xs):
            return None
        return sum(bool(x) for x in xs) / len(xs)

    def approved_rate(self, condition: str = "B") -> float | None:
        """Approved rules per item in the live application, which is condition B's workflow;
        the export does not attribute live rules to another condition, so that is None."""
        xs = [i.approved_rules for i in self.items]
        if condition != "B" or not xs or any(x is None for x in xs):
            return None
        return sum(xs) / len(xs)  # type: ignore[arg-type]

    def deployed_rate(self, condition: str = "B") -> float | None:
        xs = [i.deployed_rules for i in self.items]
        if condition != "B" or not xs or any(x is None for x in xs):
            return None
        return sum(xs) / len(xs)  # type: ignore[arg-type]

    def resample(self, indices: list[int]) -> Measured:
        return Measured([self.items[i] for i in indices], self.overhead, self.budget_stopped,
                        self.runs_by_condition, self.dropped_items, self.hosted_runs,
                        self.replayed_runs_without_wait, self.operations_hours, self.analysts)


def _read(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open(newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def _hosted(r: dict[str, str]) -> bool:
    return any(p.startswith("cloud-") for p in (r.get("cost.providers") or "").split(";"))


def _counts(r: dict[str, str]) -> tuple[float | None, float | None, float | None]:
    """(generated, assessed, valid) of one run. A failed run that reported no rule metrics
    produced nothing (intention to treat); otherwise a missing count is missing."""
    sigma, ioc = _f(r.get("rules.sigma_rules")), _f(r.get("rules.ioc_bundles"))
    assessed, valid = _f(r.get("rules.assessed")), _f(r.get("rules.validated"))
    if sigma is None and ioc is None and valid is None and (r.get("error") or "").strip():
        return 0.0, 0.0, 0.0
    generated = None if sigma is None and ioc is None else (sigma or 0.0) + (ioc or 0.0)
    return generated, assessed, valid


def _fresh(r: dict[str, str]) -> bool:
    replayed = _f(r.get("cost.replayed_calls"))
    return replayed is None or replayed == 0


def load_measured(export_dir: Path | str, categories: dict[str, str] | None = None) -> Measured:
    d = Path(export_dir)
    runs, analyst, live = _read(d / "runs.csv"), _read(d / "analyst_effort.csv"), _read(
        d / "live_rules.csv")
    by_item: dict[str, list[dict[str, str]]] = defaultdict(list)
    by_item_cloud: dict[str, list[dict[str, str]]] = defaultdict(list)
    by_item_other: dict[tuple[str, str], list[dict[str, str]]] = defaultdict(list)
    seen_b: set[str] = set()
    overhead: dict[str, Overhead] = defaultdict(Overhead)
    budget = hosted = 0
    counts: dict[str, int] = defaultdict(int)
    for r in runs:
        counts[r["condition"]] += 1
        if r["condition"] == "B" and not _hosted(r):
            seen_b.add(r["item"])
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
        if r["condition"] == "B" and _hosted(r):
            hosted += 1
            by_item_cloud[r["item"]].append(r)
        elif r["condition"] == "B":
            by_item[r["item"]].append(r)
        else:
            by_item_other[(r["item"], r["condition"])].append(r)

    sessions_all = [a for a in analyst if a.get("activity") != "operations"]
    names = sorted({a.get("analyst") or "" for a in sessions_all})
    reach = {n: len({a.get("item_key") for a in sessions_all if (a.get("analyst") or "") == n})
             for n in names}
    primary = max(names, key=lambda n: (reach[n], -names.index(n))) if names else None
    ops = [a for a in analyst if a.get("activity") == "operations"]
    replayed_out = 0
    items: list[ItemMeasure] = []
    for name, rs in sorted(by_item.items()):
        key = rs[0].get("item_key") or None
        im = ItemMeasure(name, key, (categories or {}).get(name), rs[0].get("order_set") or None,
                         runs=len(rs))
        if all(_b(r.get("cost.tokens_reliable")) for r in rs):
            im.tokens_in = _mean([_f(r.get("cost.input_tokens")) for r in rs])
            im.tokens_out = _mean([_f(r.get("cost.output_tokens")) for r in rs])
        im.automated_h = _scaled(_mean([_f(r.get("cost.time.automated_seconds")) for r in rs]))
        fresh = [r for r in rs if _fresh(r)]
        replayed_out += len(rs) - len(fresh)
        im.inference_h = _scaled(_mean([_f(r.get("cost.time.model_wait_seconds"))
                                        for r in fresh])) if fresh else None
        trip = [_counts(r) for r in rs]
        im.generated = _mean([g for g, _, _ in trip])
        im.assessed = _mean([a for _, a, _ in trip])
        im.valid = _mean([v for _, _, v in trip])
        for cond in sorted({c for (n, c) in by_item_other if n == name}):
            trip = [_counts(r) for r in by_item_other[(name, cond)]]
            im.counts_by_condition[cond] = {"generated": _mean([g for g, _, _ in trip]),
                                            "assessed": _mean([a for _, a, _ in trip]),
                                            "valid": _mean([v for _, _, v in trip])}
        cloud = by_item_cloud.get(name, [])
        if cloud and all(_b(r.get("cost.tokens_reliable")) for r in cloud):
            im.cloud_tokens_in = _mean([_f(r.get("cost.input_tokens")) for r in cloud])
            im.cloud_tokens_out = _mean([_f(r.get("cost.output_tokens")) for r in cloud])
        mine_all = [a for a in sessions_all if key and a.get("item_key") == key]
        for cond in ("A", "B"):
            mine = [a for a in mine_all if a["condition"] == cond]
            if not mine:
                continue
            per_analyst = defaultdict(float)
            for a in mine:
                per_analyst[a.get("analyst") or ""] += _f(a["active_seconds"]) or 0.0
            im.analyst_h[cond] = fmean(per_analyst.values()) / 3600.0
            own = [a for a in mine if (a.get("analyst") or "") == primary] or mine
            last = own[-1].get("disposition")
            im.accepted[cond] = None if last in (None, "", "in_progress") else (
                last == "accepted")
        if live and key:
            rules = [x for x in live if x["item_key"] == key]
            im.approved_rules = sum(_b(x["approved"]) is True for x in rules)
            im.deployed_rules = sum(_b(x["deployed_lab"]) is True for x in rules)
        items.append(im)
    # research overhead for B is what the runs beyond one per item used
    if "B" in overhead and items:
        b = overhead["B"]
        b.runs -= len(items)
        for im in items:
            b.input_tokens -= im.tokens_in or 0.0
            b.output_tokens -= im.tokens_out or 0.0
            b.automated_s -= 3600.0 * (im.automated_h or 0.0)
    return Measured(items, dict(overhead), budget, dict(counts),
                    dropped_items=sorted(seen_b - set(by_item)), hosted_runs=hosted,
                    replayed_runs_without_wait=replayed_out,
                    operations_hours=(sum(_f(a["active_seconds"]) or 0.0 for a in ops) / 3600.0
                                      if ops else None),
                    analysts=[n for n in names if n])


def _scaled(seconds: float | None) -> float | None:
    return None if seconds is None else seconds / 3600.0
