"""Facts about the target Wazuh version, read from ``knowledge/wazuh_parent_sids.json`` (built
in spike S1 from the manager's own ruleset) instead of being written from memory
(blueprint §20.5, ADR-001 decision 5).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

DEFAULT_PATH = Path(__file__).resolve().parents[1] / "knowledge" / "wazuh_parent_sids.json"

# Sigma log source category -> key in the knowledge file
CATEGORIES = ("process_creation", "network_connection", "dns_query")


@dataclass(frozen=True)
class Parent:
    category: str
    event_id: int
    sid: int
    shadowing_siblings: tuple[int, ...] = ()

    @property
    def if_sid(self) -> str:
        """Value for ``<if_sid>``: the parent plus known siblings that would shadow it."""
        return ", ".join(str(s) for s in (self.sid, *self.shadowing_siblings))


@lru_cache(maxsize=4)
def load_knowledge(path: Path | str = DEFAULT_PATH) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def parent_for(category: str, knowledge: dict | None = None) -> Parent:
    k = knowledge or load_knowledge()
    try:
        entry = k["windows_sysmon"][category]
    except KeyError as exc:
        raise KeyError(f"no Wazuh parent rule known for log source category {category!r}") \
            from exc
    sid = int(entry["parent_sid"])
    siblings = tuple(int(s["sid"]) for s in k.get("known_shadowing_siblings", {}).get(str(sid), []))
    return Parent(category, int(entry["event_id"]), sid, siblings)
