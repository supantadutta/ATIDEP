"""Measured effort and cost (blueprint §22.2, §22.7). The application measures; the paper
analyses (TCO, break-even and sensitivity are computed offline from these numbers and
``config/cost_rates.yaml``).

Reported: tokens, calls and model latency per agent; analyst active time per condition; machine
time per component; labour cost at the configured hourly rate; token cost for models that
charge (local inference is recorded as zero); cost per item and per accepted rule.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.config import AppConfig
from app.db import models as m
from schemas.effort_cost_record import Component

LOCAL_PROVIDERS = frozenset({"ollama", "scripted", "replay"})


def summary(session: Session, cfg: AppConfig) -> dict[str, Any]:
    rates = cfg.cost_rates
    currency = rates.get("currency", "")
    hourly = float(rates.get("labor", {}).get("analyst_hourly_rate", 0))
    cloud = rates.get("cloud_ai", {})
    per_in = float(cloud.get("input_cost_per_million_tokens", 0))
    per_out = float(cloud.get("output_cost_per_million_tokens", 0))

    agents: dict[str, dict[str, float]] = defaultdict(lambda: defaultdict(float))
    token_cost = 0.0
    for r in session.scalars(select(m.ModelRun)):
        a = agents[r.agent]
        a["calls"] += 1
        a["input_tokens"] += r.input_tokens
        a["output_tokens"] += r.output_tokens
        a["latency_ms"] += r.latency_ms or 0
        a["schema_invalid"] += 0 if r.schema_valid else 1
        a["retries"] += r.retry_count
        if r.provider not in LOCAL_PROVIDERS:
            token_cost += (r.input_tokens * per_in + r.output_tokens * per_out) / 1e6
    tokens = {"input": int(sum(a["input_tokens"] for a in agents.values())),
              "output": int(sum(a["output_tokens"] for a in agents.values()))}

    by_condition: dict[str, dict[str, float]] = defaultdict(lambda: defaultdict(float))
    machine: dict[str, float] = defaultdict(float)
    for e in session.scalars(select(m.EffortCostRecord)):
        wall = (e.ended_at - e.started_at).total_seconds()
        if e.component == Component.ANALYST.value:
            by_condition[e.condition]["analyst_active_seconds"] += e.analyst_active_seconds
            by_condition[e.condition]["analyst_wall_seconds"] += wall
        else:
            machine[e.component] += wall
    analyst_seconds = sum(c["analyst_active_seconds"] for c in by_condition.values())
    labour = analyst_seconds / 3600.0 * hourly

    items = session.scalar(select(func.count()).select_from(m.IntelligenceItem)) or 0
    accepted = session.scalar(select(func.count()).select_from(m.Approval)
                              .where(m.Approval.decision == "approved")) or 0
    total = labour + token_cost
    return {
        "currency": currency,
        "agents": {k: dict(v) for k, v in sorted(agents.items())}, "tokens": tokens,
        "analyst": {c: dict(v) for c, v in sorted(by_condition.items())},
        "analyst_active_minutes": round(analyst_seconds / 60.0, 2),
        "machine_seconds": dict(machine),
        "cost": {"labour": round(labour, 2), "tokens": round(token_cost, 4),
                 "total": round(total, 2),
                 "per_item": round(total / items, 2) if items else None,
                 "per_accepted_rule": round(total / accepted, 2) if accepted else None},
        "items": items, "accepted_rules": accepted,
        "note": "local inference is recorded with zero token cost; infrastructure is allocated "
                "offline (blueprint §22.3)"}
