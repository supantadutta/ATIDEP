"""Record every model call in ``model_runs`` (blueprint §18 required metadata)."""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.db import models as m
from components.llm.prompts import Prompt
from components.llm.structured import CallRecord


def log_calls(session: Session, *, run_id: str, agent: str, intel_id: str | None,
              calls: list[CallRecord], prompt: Prompt, repair_attempt: int = 0) -> int:
    for rec in calls:
        r, req = rec.response, rec.request
        session.add(m.ModelRun(
            run_id=run_id, intel_id=intel_id, agent=agent, repair_attempt=repair_attempt,
            provider=r.provider, model=r.model, temperature=req.temperature, seed=req.seed,
            prompt_version=prompt.version, prompt_sha256=prompt.sha256,
            input_tokens=r.input_tokens, output_tokens=r.output_tokens, latency_ms=r.latency_ms,
            estimated_cost=r.cost, schema_valid=rec.schema_valid, retry_count=rec.attempt))
    session.flush()
    return len(calls)
