"""Readiness check for the real dataset (blueprint §27.2, §27.3, §27.9).

    python -m research.dataset check DIR [--cutoff YYYY-MM-DD] [--pilot DIR] [--second-labels FILE]

It reads a dataset folder (a ``manifest.yaml`` plus the files it names) and reports what still
stands between it and the main run. It invents nothing and repairs nothing: every problem is a
*blocker* the coordinator must resolve, a *warning*, or a plain note. Exit status 1 means at
least one blocker. The synthetic demonstration dataset therefore always fails this check, which
is correct: it is not evidence for the research questions.

The second labeller's file is YAML, ``{item_id: {detectable: bool, techniques: [T1059.001]}}``.
Agreement (Cohen's kappa on the detectable label, mean Jaccard on technique sets) is computed
here from the two files; adjudication stays a human act and is logged outside this tool.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from research.analysis.agreement import cohen_kappa, jaccard
from research.dataset.model import LoadedDataset, assign_order_sets, load_dataset
from schemas.detection_opportunity import Decision

EXPECTED = {"ioc": 10, "behaviour": 10, "mixed": 5, "unsuitable": 5}      # §27.2
SECOND_LABEL_MIN_ITEMS = 10                                                 # §27.3
SECOND_LABEL_MIN_SHARE = 1 / 3


@dataclass
class Finding:
    level: str                    # blocker | warning | note
    code: str
    message: str


@dataclass
class Report:
    findings: list[Finding] = field(default_factory=list)
    facts: dict[str, Any] = field(default_factory=dict)

    def add(self, level: str, code: str, message: str) -> None:
        self.findings.append(Finding(level, code, message))

    @property
    def blockers(self) -> list[Finding]:
        return [f for f in self.findings if f.level == "blocker"]

    @property
    def ready(self) -> bool:
        return not self.blockers

    def to_dict(self) -> dict[str, Any]:
        return {"ready_for_main_run": self.ready, "facts": self.facts,
                "findings": [vars(f) for f in self.findings]}


def _content_hashes(ds: LoadedDataset) -> dict[str, str]:
    return {i.id: hashlib.sha256(ds.read(i)).hexdigest() for i in ds.items}


def _second_labels(path: Path, ds: LoadedDataset, rep: Report) -> None:
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    items = [i for i in ds.items if not i.adversarial and i.ground_truth]
    labelled = [i for i in items if i.id in raw]
    unknown = sorted(set(raw) - {i.id for i in ds.items})
    if unknown:
        rep.add("blocker", "second_labels_unknown_items",
                f"second-labeller file names items not in the dataset: {unknown}")
    need = max(SECOND_LABEL_MIN_ITEMS, math.ceil(SECOND_LABEL_MIN_SHARE * len(items)))
    rep.facts["second_labeller_items"] = len(labelled)
    rep.facts["second_labeller_required"] = need
    if len(labelled) < need:
        rep.add("blocker", "second_labels_too_few",
                f"{len(labelled)} items labelled by the second labeller; at least {need} needed "
                f"(a third of the items, minimum {SECOND_LABEL_MIN_ITEMS})")
    missing = sorted({i.category for i in items} - {i.category for i in labelled})
    if labelled and missing:
        rep.add("blocker", "second_labels_not_stratified",
                f"the second labeller's items do not cover the categories {missing}")
    if not labelled:
        return
    bad = [i.id for i in labelled if not isinstance(raw[i.id], dict)
           or not isinstance(raw[i.id].get("detectable"), bool)]
    if bad:
        rep.add("blocker", "second_labels_malformed",
                f"items without a boolean 'detectable': {bad}")
        return
    first = [i.ground_truth.detectable for i in labelled]            # type: ignore[union-attr]
    second = [raw[i.id]["detectable"] for i in labelled]
    jac = [jaccard(set(i.ground_truth.techniques),                  # type: ignore[union-attr]
                   set(raw[i.id].get("techniques") or [])) for i in labelled]
    rep.facts["agreement"] = {
        "detectable_kappa": cohen_kappa(first, second),
        "detectable_raw_agreement": sum(a == b for a, b in zip(first, second, strict=True))
        / len(first),
        "technique_jaccard_mean": sum(jac) / len(jac),
        "disagreements": sorted(i.id for i, a, b in zip(labelled, first, second, strict=True)
                                if a != b),
        "note": "disagreements are adjudicated by the second labeller or the supervisor and "
                "logged; this tool does not adjudicate"}


def check_dataset(root: Path | str, *, manifest: str = "manifest.yaml",
                  model_cutoff: date | None = None, pilot_root: Path | str | None = None,
                  second_labels: Path | str | None = None,
                  expected: dict[str, int] | None = None) -> Report:
    expected = EXPECTED if expected is None else expected
    rep = Report()
    try:
        ds = load_dataset(root, manifest)
    except (ValidationError, FileNotFoundError, ValueError, yaml.YAMLError) as exc:
        rep.add("blocker", "manifest_invalid", f"the manifest cannot be loaded: {exc}")
        return rep
    d = ds.data
    rep.facts.update({"dataset_id": d.dataset_id, "synthetic": d.synthetic, "seed": d.seed,
                      "items": len(d.items), "dataset_sha256": ds.sha256()})
    if d.synthetic:
        rep.add("blocker", "synthetic", "the dataset is marked synthetic; it is not evidence for "
                "the research questions")

    test = [i for i in d.items if not i.adversarial]
    counts = Counter(i.category for i in test)
    rep.facts["composition"] = dict(counts)
    for category, n in expected.items():
        if counts.get(category, 0) != n:
            rep.add("blocker", "composition",
                    f"category {category!r}: {counts.get(category, 0)} items, {n} required")
    extra = sorted(set(counts) - set(expected))
    if extra:
        rep.add("blocker", "composition", f"categories outside the design: {extra}")

    for i in test:
        gt = i.ground_truth
        if gt is None:
            rep.add("blocker", "no_ground_truth", f"{i.id}: no ground truth")
            continue
        if i.category == "unsuitable" and gt.detectable:
            rep.add("warning", "unsuitable_but_detectable",
                    f"{i.id}: category 'unsuitable' but labelled detectable")
        generating = {Decision.IOC_BASED, Decision.BEHAVIORAL} & set(gt.decisions)
        if generating and not gt.required_log_source:
            rep.add("blocker", "no_log_source", f"{i.id}: a generating decision needs a "
                    "required_log_source")
        if gt.detectable and not (gt.indicators or gt.techniques):
            rep.add("blocker", "empty_labels", f"{i.id}: detectable but no indicators or "
                    "techniques are labelled")
        if Decision.BEHAVIORAL in gt.decisions and not i.test_events:
            rep.add("blocker", "no_events", f"{i.id}: a behavioural item needs an event set "
                    "(positive, negative, benign look-alike)")
        elif gt.detectable and not i.test_events:
            rep.add("warning", "no_events", f"{i.id}: no event set; functional metrics cannot "
                    "be computed for this item")
        elif i.test_events:
            ts = ds.test_set(i)
            if ts is None or not (ts.positive and ts.negative and ts.lookalike):
                rep.add("blocker", "event_set_incomplete",
                        f"{i.id}: the event set needs positive, negative and benign look-alike "
                        "events")

    if model_cutoff is None:
        rep.add("blocker", "cutoff_unknown", "the pinned model's training cutoff is not recorded "
                "(pending spike S3), so the contamination control cannot be checked")
    for i in d.items:
        if i.published is None:
            rep.add("blocker", "no_publication_date", f"{i.id}: no publication date")
        elif model_cutoff is not None:
            try:
                after = date.fromisoformat(i.published) > model_cutoff
            except ValueError:
                rep.add("blocker", "bad_date", f"{i.id}: {i.published!r} is not an ISO date")
                continue
            if not after:
                rep.add("blocker", "before_cutoff", f"{i.id}: published {i.published}, not after "
                        f"the model's training cutoff {model_cutoff}")

    hashes = _content_hashes(ds)
    by_hash: dict[str, list[str]] = defaultdict(list)
    for item_id, h in hashes.items():
        by_hash[h].append(item_id)
    for ids in by_hash.values():
        if len(ids) > 1:
            rep.add("blocker", "duplicate_content", f"identical report content: {ids}")
    if pilot_root is not None:
        try:
            pilot = load_dataset(pilot_root)
        except (ValidationError, FileNotFoundError, ValueError, yaml.YAMLError) as exc:
            rep.add("blocker", "pilot_invalid", f"the pilot manifest cannot be loaded: {exc}")
        else:
            overlap = set(hashes.values()) & set(_content_hashes(pilot).values())
            if overlap:
                rep.add("blocker", "pilot_overlap", f"{len(overlap)} report(s) appear in both "
                        "the pilot set and the test set; they must be kept entirely separate")
            rep.facts["pilot_items"] = len(pilot.items)
    else:
        rep.add("note", "pilot_not_checked", "no pilot dataset was given, so separation from the "
                "pilot set was not checked")

    sets = assign_order_sets(test, d.seed)
    per: dict[str, Counter] = defaultdict(Counter)
    for i in test:
        per[i.category][sets[i.id]] += 1
    rep.facts["order_sets"] = {c: dict(v) for c, v in sorted(per.items())}
    rep.add("note", "order_sets", "order sets X/Y are assigned from the committed seed "
            f"{d.seed}; the seed must be committed before the assignment is used")

    if second_labels is None:
        rep.add("blocker", "second_labels_missing", "the second labeller's labels were not "
                "supplied")
    else:
        _second_labels(Path(second_labels), ds, rep)
    return rep


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m research.dataset")
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check")
    c.add_argument("dataset")
    c.add_argument("--manifest", default="manifest.yaml")
    c.add_argument("--cutoff", help="the pinned model's training cutoff (ISO date), from its card")
    c.add_argument("--pilot")
    c.add_argument("--second-labels")
    c.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    rep = check_dataset(a.dataset, manifest=a.manifest,
                        model_cutoff=date.fromisoformat(a.cutoff) if a.cutoff else None,
                        pilot_root=a.pilot, second_labels=a.second_labels)
    if a.json:
        print(json.dumps(rep.to_dict(), indent=1))
    else:
        print(f"dataset {rep.facts.get('dataset_id', '?')}: "
              f"{'READY' if rep.ready else 'NOT READY'} for the main run")
        for f in rep.findings:
            print(f"  [{f.level}] {f.code}: {f.message}")
    return 0 if rep.ready else 1


if __name__ == "__main__":
    sys.exit(main())
