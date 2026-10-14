"""Dataset manifest, ground truth and seeded set assignment (blueprint §27.2, §27.3).

A dataset is a manifest plus files. Labels are written *before* any system output is seen and the
whole dataset is hashed (``dataset_sha256``) so the run records can say exactly which version of
the labels and events they used. Items are split into the two crossover order sets X (manual
first) and Y (agentic first) by a seeded, stratified draw.
"""

from __future__ import annotations

import hashlib
import json
import random
from collections import defaultdict
from pathlib import Path
from typing import Literal

import yaml
from pydantic import Field, model_validator

from components.c4_validation.corpus import TestSet, load_test_set
from schemas.common import AttackId, Strict
from schemas.detection_opportunity import Decision

Category = Literal["ioc", "behaviour", "mixed", "unsuitable"]


class GtIndicator(Strict):
    type: str
    value: str


class GroundTruth(Strict):
    """What a careful analyst would extract and decide for this item."""

    detectable: bool
    decisions: list[Decision] = Field(min_length=1)       # acceptable opportunity decisions
    indicators: list[GtIndicator] = Field(default_factory=list)
    techniques: list[AttackId] = Field(default_factory=list)
    required_log_source: str | None = None
    notes: str = ""

    @model_validator(mode="after")
    def _consistent(self) -> GroundTruth:
        generating = {Decision.IOC_BASED, Decision.BEHAVIORAL, Decision.CORRELATION}
        if self.detectable != bool(generating & set(self.decisions)):
            raise ValueError("detectable must agree with the acceptable decisions")
        return self


class SourceInfo(Strict):
    name: str
    reliability: Literal["A", "B", "C", "D", "E", "F"] = "C"
    credibility: Literal[1, 2, 3, 4, 5, 6] = 3
    url: str | None = None


class DatasetItem(Strict):
    id: str = Field(pattern=r"^[A-Z0-9-]{3,20}$")
    file: str
    category: Category
    source: SourceInfo
    published: str | None = None                  # ISO date
    test_events: str | None = None                # folder: positive, negative, benign_lookalike
    ground_truth: GroundTruth | None = None
    adversarial: bool = False                     # kept out of the 30-item test set (§27.2)


class Dataset(Strict):
    dataset_id: str
    synthetic: bool
    seed: int
    description: str = ""
    items: list[DatasetItem]

    @model_validator(mode="after")
    def _unique(self) -> Dataset:
        ids = [i.id for i in self.items]
        if len(ids) != len(set(ids)):
            raise ValueError("item ids must be unique")
        return self


class LoadedDataset:
    def __init__(self, root: Path, data: Dataset) -> None:
        self.root, self.data = Path(root), data

    @property
    def items(self) -> list[DatasetItem]:
        return self.data.items

    def item(self, item_id: str) -> DatasetItem:
        return next(i for i in self.data.items if i.id == item_id)

    def read(self, item: DatasetItem) -> bytes:
        return (self.root / item.file).read_bytes()

    def test_set(self, item: DatasetItem) -> TestSet | None:
        if not item.test_events:
            return None
        return load_test_set(self.root / item.test_events, item.id)

    def sha256(self) -> str:
        """Hash of the manifest and every file it refers to (labels, reports, events)."""
        h = hashlib.sha256()
        h.update(json.dumps(self.data.model_dump(mode="json"), sort_keys=True).encode())
        paths = sorted({self.root / i.file for i in self.items} | {
            p for i in self.items if i.test_events
            for p in (self.root / i.test_events).rglob("*.json")})
        for p in paths:
            h.update(str(p.relative_to(self.root)).encode())
            h.update(p.read_bytes())
        return h.hexdigest()


def load_dataset(root: Path | str, manifest: str = "manifest.yaml") -> LoadedDataset:
    root = Path(root)
    data = Dataset.model_validate(yaml.safe_load((root / manifest).read_text(encoding="utf-8")))
    for item in data.items:
        if not (root / item.file).is_file():
            raise FileNotFoundError(f"{item.id}: {item.file} is missing")
    return LoadedDataset(root, data)


def assign_order_sets(items: list[DatasetItem], seed: int) -> dict[str, str]:
    """Stratified by category: within each category the items are shuffled with the seed and
    alternated X, Y, X, Y...; an odd item goes to the set the previous odd category did not,
    keeping the totals within one."""
    rng = random.Random(seed)
    groups: dict[str, list[str]] = defaultdict(list)
    for item in items:
        if not item.adversarial:
            groups[item.category].append(item.id)
    out: dict[str, str] = {}
    extra = "X"
    for category in sorted(groups):
        ids = sorted(groups[category])
        rng.shuffle(ids)
        for k, item_id in enumerate(ids):
            out[item_id] = "XY"[k % 2]
        if len(ids) % 2:
            last = ids[-1]
            out[last] = extra
            extra = "Y" if extra == "X" else "X"
    return out
