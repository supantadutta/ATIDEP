"""Post-deployment check in the lab: replay the rule's own events through the live pipeline and
confirm positives alert and the others do not (blueprint §17.5.1 "Tier 2 results")."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from components.c4_validation.corpus import TestSet
from components.c4_validation.tier2 import LabManager


def replay_verifier(lab: LabManager, test_set: TestSet, rule_ids: list[int]
                    ) -> Callable[[], dict[str, Any]]:
    wanted = set(rule_ids)

    def verify() -> dict[str, Any]:
        events = [e.event for e in test_set.all_events()]
        res = lab.replay(events)
        missed = [e.name for e in test_set.positive if not res.matched(e.record_id, wanted)]
        false_alerts = [e.name for e in test_set.negative + test_set.lookalike
                        if res.matched(e.record_id, wanted)]
        return {"ok": not missed and not false_alerts, "tier": 2,
                "positives": f"{len(test_set.positive) - len(missed)}/{len(test_set.positive)}",
                "missed_positives": missed, "false_alerts": false_alerts}
    return verify
