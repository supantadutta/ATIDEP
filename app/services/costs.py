"""Measured quantities for the cost analysis (blueprint §2.4, §22.2). **The application records
quantities and prices nothing.** Money is computed offline from the exported quantities, the rates,
the price register and the scenarios (``research.economics``), because a figure shown here would
need a rate or a price that the application does not have, and an unsourced figure is worse than
none.

Reported: tokens and calls per agent (with how many calls were served from a recording), whether
the token counts came from the provider, model latency of fresh calls, analyst time per condition
(active, wall-clock, and the time the idle rule did not count), machine time per component, and
the distinct rules that were approved or deployed. Platform upkeep ('operations') is reported
apart from per-item analyst time.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from sqlalchemy import distinct, func, select
from sqlalchemy.orm import Session

from app.db import models as m
from components.llm.client import is_cloud_provider
from schemas.common import RuleState
from schemas.effort_cost_record import Component

APPROVED_STATES = (RuleState.APPROVED.value, RuleState.DEPLOYED.value, RuleState.MONITORED.value)


def summary(session: Session) -> dict[str, Any]:
    agents: dict[str, dict[str, float]] = defaultdict(lambda: defaultdict(float))
    by_locality: dict[str, dict[str, float]] = {"local": defaultdict(float),
                                                "cloud": defaultdict(float)}
    sources: dict[str, int] = defaultdict(int)
    for r in session.scalars(select(m.ModelRun)):
        a = agents[r.agent]
        a["calls"] += 1
        a["input_tokens"] += r.input_tokens
        a["output_tokens"] += r.output_tokens
        a["schema_invalid"] += 0 if r.schema_valid else 1
        a["retries"] += r.retry_count
        a["replayed_calls"] += 1 if r.replayed else 0
        if not r.replayed:
            a["latency_ms"] += r.latency_ms or 0          # a replayed call waited for nothing
        loc = by_locality["cloud" if is_cloud_provider(r.provider) else "local"]
        loc["calls"] += 1
        loc["input_tokens"] += r.input_tokens
        loc["output_tokens"] += r.output_tokens
        sources[r.usage_source] += 1
    tokens = {"input": int(sum(a["input_tokens"] for a in agents.values())),
              "output": int(sum(a["output_tokens"] for a in agents.values()))}

    analyst: dict[str, dict[str, float]] = defaultdict(lambda: defaultdict(float))
    upkeep = defaultdict(float)
    machine: dict[str, float] = defaultdict(float)
    for e in session.scalars(select(m.EffortCostRecord)):
        wall = (e.ended_at - e.started_at).total_seconds()
        if e.component != Component.ANALYST.value:
            machine[e.component] += wall
        elif e.activity == "operations":
            upkeep["active_seconds"] += e.analyst_active_seconds
            upkeep["wall_seconds"] += wall
        else:
            c = analyst[e.condition]
            c["active_seconds"] += e.analyst_active_seconds
            c["wall_seconds"] += wall
            c["idle_capped_gaps"] += e.idle_capped_gaps
            c["idle_capped_seconds"] += e.idle_capped_seconds
            c["sessions"] += 1
    item_minutes = sum(c["active_seconds"] for c in analyst.values()) / 60.0

    items = session.scalar(select(func.count()).select_from(m.IntelligenceItem)) or 0
    processed = session.scalar(select(func.count(distinct(m.ModelRun.intel_id)))
                               .where(m.ModelRun.intel_id.is_not(None))) or 0
    approved = session.scalar(select(func.count()).select_from(m.Rule)
                              .where(m.Rule.state.in_(APPROVED_STATES))) or 0
    deployed = session.scalar(
        select(func.count(distinct(m.RuleVersion.rule_id))).select_from(m.Deployment)
        .join(m.RuleVersion, m.RuleVersion.id == m.Deployment.rule_version_id)
        .where(m.Deployment.mode == "lab", m.Deployment.status == "ok")) or 0
    return {
        "agents": {k: dict(v) for k, v in sorted(agents.items())}, "tokens": tokens,
        "by_locality": {k: dict(v) for k, v in by_locality.items()},
        "usage_sources": dict(sorted(sources.items())),
        "analyst": {c: dict(v) for c, v in sorted(analyst.items())},
        "analyst_active_minutes": round(item_minutes, 2),
        "platform_upkeep": dict(upkeep),
        "machine_seconds": dict(machine),
        "items": items, "items_processed": processed,
        "approved_rules": approved, "deployed_rules": deployed,
        "note": "Quantities only. Money is computed offline from the price register and rates "
                "(research.economics); the application prices nothing."}
