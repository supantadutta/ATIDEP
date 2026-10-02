"""Candidate telemetry for techniques and indicator types (blueprint §17.2.5, §17.3.1)."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

DEFAULT_PATH = Path(__file__).resolve().parents[2] / "knowledge" / "logsource_mapping.json"


@lru_cache(maxsize=1)
def load_mapping(path: Path | str = DEFAULT_PATH) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def logsources_for_technique(technique_id: str, mapping: dict | None = None) -> list[str]:
    techniques = (mapping or load_mapping())["techniques"]
    if technique_id in techniques:
        return list(techniques[technique_id])
    parent = technique_id.split(".")[0]
    return list(techniques.get(parent, []))


def candidate_logsources(technique_ids: list[str], indicator_types: list[str],
                         mapping: dict | None = None) -> list[str]:
    m = mapping or load_mapping()
    out: list[str] = []
    for tid in technique_ids:
        out += logsources_for_technique(tid, m)
    for it in indicator_types:
        out += m["indicator_types"].get(it, [])
    return list(dict.fromkeys(out))
