"""One intelligence item through the pipeline, for conditions B, B-V and B-R (blueprint §27.1).

* B    full ATIDEP: extraction, opportunity, rule generation with repair, all eleven gates.
* B-V  the validators are *logged but not enforced*: the repair loop accepts the first draft
       whatever the gates say, and the gates are applied afterwards for comparison.
* B-R  no repair loop (zero repair attempts).

Every stage is independent of the others' failures: a model outage or a rule that cannot be
generated is recorded in the result and does not stop the remaining stages.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import AppConfig
from app.db import models as m
from app.services.detection import DetectionError, assess_item, create_ioc_rule, create_sigma_rule
from app.services.governance import GovernanceError, loop_validator, validate_rule
from app.services.process import ProcessOutcome, process_item
from components.c1_ingest.evidence import EvidenceStore
from components.c2_processing.attack import AttackRelease
from components.c3_detection.rule_agent import LoopCheck, RuleContext
from components.c4_validation.corpus import TestEvent, TestSet
from components.llm.client import LLMClient
from components.llm.prompts import PromptSet
from schemas.detection_opportunity import GENERATING_DECISIONS, Decision
from schemas.sigma_subset import Assumption

CONDITIONS = ("B", "B-V", "B-R")


@dataclass
class PipelineOptions:
    condition: str = "B"
    seed: int | None = None
    allow_test_tlds: bool = False
    run_id: str = "run"

    def __post_init__(self) -> None:
        if self.condition not in CONDITIONS:
            raise ValueError(f"condition must be one of {CONDITIONS}")


@dataclass
class RuleRun:
    opportunity_id: int
    decision: str
    kind: str
    rule_id: str | None = None
    loop_status: str | None = None
    first_pass_valid: bool | None = None
    repairs_used: int | None = None
    attempts: int = 0
    outcome: str | None = None
    failed_gates: list[str] = field(default_factory=list)
    quality_score: int | None = None
    shadow_defects: list[list[dict[str, Any]]] = field(default_factory=list)
    skipped: str | None = None


@dataclass
class PipelineRun:
    intel_id: str
    condition: str
    processed: ProcessOutcome | None = None
    opportunity_ids: list[int] = field(default_factory=list)
    rules: list[RuleRun] = field(default_factory=list)
    error: str | None = None
    seconds: float = 0.0


def _shadow(real, log: list[list[dict[str, Any]]]):
    """B-V: record what the gates say, but let every draft through."""
    def validator(sigma_yaml: str, assumptions: list[Assumption], ctx: RuleContext) -> LoopCheck:
        check = real(sigma_yaml, assumptions, ctx)
        log.append([d.model_dump(mode="json") for d in check.defects])
        return LoopCheck()
    return validator


def run_pipeline(session: Session, store: EvidenceStore, intel_id: str, *, cfg: AppConfig,
                 attack: AttackRelease, client: LLMClient, prompts: PromptSet,
                 options: PipelineOptions, benign_domains: list[str],
                 test_set: TestSet | None = None, baseline: list[TestEvent] | None = None,
                 now: datetime | None = None) -> PipelineRun:
    t0 = time.monotonic()
    now = now or datetime.now(UTC)
    run = PipelineRun(intel_id, options.condition)
    proc = process_item(session, store, intel_id, cfg=cfg, attack=attack, client=client,
                        prompt=prompts.extraction, benign_domains=benign_domains,
                        allow_test_tlds=options.allow_test_tlds, seed=options.seed)
    run.processed = proc
    if not proc.ok:
        run.error, run.seconds = proc.error, time.monotonic() - t0
        return run
    try:
        run.opportunity_ids = assess_item(
            session, intel_id, cfg=cfg, attack=attack, client=client, prompt=prompts.opportunity,
            now=now, seed=options.seed, run_id=options.run_id)
    except DetectionError as exc:
        run.error, run.seconds = str(exc), time.monotonic() - t0
        return run
    for opp_id in run.opportunity_ids:
        row = session.get(m.DetectionOpportunity, opp_id)
        if Decision(row.decision) not in GENERATING_DECISIONS:
            continue
        rr = RuleRun(opp_id, row.decision, "ioc_list" if row.decision == "ioc_based" else "sigma")
        run.rules.append(rr)
        try:
            if rr.kind == "ioc_list":
                rr.rule_id = create_ioc_rule(session, opp_id, cfg=cfg,
                                             benign_domains=benign_domains, now=now)
            else:
                real = loop_validator(session, cfg, attack)
                validator = _shadow(real, rr.shadow_defects) if options.condition == "B-V" \
                    else real
                rule_id, res = create_sigma_rule(
                    session, opp_id, cfg=cfg, client=client, prompt=prompts.rule,
                    validate=validator, seed=options.seed, run_id=options.run_id,
                    max_repairs=0 if options.condition == "B-R" else None)
                rr.rule_id, rr.loop_status = rule_id, res.status
                rr.first_pass_valid, rr.repairs_used = res.first_pass_valid, res.repairs_used
                rr.attempts = len(res.attempts)
                if options.condition == "B-V" and rr.shadow_defects:
                    rr.first_pass_valid = not rr.shadow_defects[0]
            if rr.rule_id is None:
                rr.skipped = "the model produced no valid draft"
                continue
            if rr.kind == "sigma" and test_set is None:
                rr.skipped = "no test events for this item"
                continue
            out = validate_rule(session, rr.rule_id, cfg=cfg, attack=attack, test_set=test_set,
                                baseline=baseline if baseline is not None else [])
            rr.outcome, rr.quality_score = out.outcome.value, out.quality_score
            rr.failed_gates = [g.value for g in out.failed]
        except (DetectionError, GovernanceError) as exc:
            rr.skipped = str(exc)[:200]
    run.seconds = time.monotonic() - t0
    return run


def count_artifacts(session: Session) -> dict[str, int]:
    """A few counts for the results table (rules by state)."""
    states: dict[str, int] = {}
    for (state,) in session.execute(select(m.Rule.state)):
        states[state] = states.get(state, 0) + 1
    return states
