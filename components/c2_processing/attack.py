"""Pinned MITRE ATT&CK release used as a local lookup (blueprint §13, §17.2.2).

The release file is built from the official STIX data and records the ATT&CK version, the
source commit and the source file's hash, so a technique ID can be checked offline and the
result reproduced.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

DEFAULT_PATH = (Path(__file__).resolve().parents[2] / "knowledge" / "attack_release"
                / "enterprise.json")
_ID = re.compile(r"^T\d{4}(\.\d{3})?$")


@dataclass(frozen=True)
class Technique:
    id: str
    name: str
    tactics: tuple[str, ...]
    subtechnique: bool
    deprecated: bool
    revoked: bool

    @property
    def active(self) -> bool:
        return not (self.deprecated or self.revoked)


class AttackRelease:
    def __init__(self, data: dict) -> None:
        self.meta = data["meta"]
        self._tactics = data["tactics"]
        self._techniques = {
            tid: Technique(tid, t["name"], tuple(t["tactics"]), t["subtechnique"], t["deprecated"],
                           t["revoked"])
            for tid, t in data["techniques"].items()}

    @property
    def version(self) -> str:
        return str(self.meta["attack_version"])

    def get(self, technique_id: str) -> Technique | None:
        return self._techniques.get(technique_id)

    def is_active(self, technique_id: str) -> bool:
        t = self.get(technique_id)
        return bool(t and t.active)

    def tactic_names(self, technique_id: str) -> list[str]:
        t = self.get(technique_id)
        return [self._tactics[s]["name"] for s in t.tactics if s in self._tactics] if t else []

    def tags(self, technique_id: str) -> list[str]:
        """Sigma-style ATT&CK tags: one per tactic plus the technique, for example
        ['attack.execution', 'attack.t1059.001']."""
        t = self.get(technique_id)
        if not t:
            return []
        return [f"attack.{s.replace('-', '_')}" for s in t.tactics] + [f"attack.{t.id.lower()}"]

    @staticmethod
    def looks_like_id(value: str) -> bool:
        return bool(_ID.match(value))

    def __len__(self) -> int:
        return len(self._techniques)


@lru_cache(maxsize=1)
def load_release(path: Path | str = DEFAULT_PATH) -> AttackRelease:
    return AttackRelease(json.loads(Path(path).read_text(encoding="utf-8")))
