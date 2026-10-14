"""Experiment runner (blueprint §27). Runs automated conditions over a dataset.

Conditions B, B-V and B-R go through the pipeline; C is the single-prompt baseline judged by the
same gates afterwards. Condition A (manual) is human work measured with the analyst timer and is
not run here.

Every run gets its **own database**, so runs cannot influence each other and any run can be
inspected later. The results database holds one ``experiment_runs`` row per run (pointing at the
run's output), the ingested items, and the machine-effort records. Seeds are derived from the
base seed, the item, the condition and the run number; finished runs are skipped on a restart.
"""

from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from sqlalchemy import Engine, select

from app.config import AppConfig
from app.db import models as m
from app.db.session import init_db, make_engine, session_scope
from app.services.ingest import get_or_create_source, ingest
from app.services.model_runs import log_calls
from app.services.pipeline import PipelineOptions, PipelineRun, RuleRun, run_pipeline
from components.c1_ingest.collect import collect_bytes
from components.c1_ingest.evidence import EvidenceStore
from components.c1_ingest.ssrf import host_allowed, is_public_address
from components.c2_processing.attack import AttackRelease
from components.c3_detection.baseline import posthoc_report, run_single_prompt
from components.c4_validation.corpus import TestEvent
from components.llm.client import LLMClient, is_budget_error
from components.llm.prompts import PromptSet
from research import metrics as mt
from research.dataset.model import DatasetItem, LoadedDataset, assign_order_sets
from schemas.detection_opportunity import GENERATING_DECISIONS, Decision
from schemas.effort_cost_record import Condition

AUTOMATED = ("B", "C", "B-V", "B-R")
COMPONENT_OF_AGENT = {"extraction": "c2_processing", "opportunity": "c3_detection",
                      "rule": "c3_detection", "single_prompt_baseline": "c3_detection",
                      "improvement": "c5_deploy_feedback"}
ClientFactory = Callable[[str, str, int], LLMClient]


@dataclass
class RunRecord:
    item_id: str
    condition: str
    run_number: int
    seed: int
    order_set: str
    output_ref: str
    metrics: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    seconds: float = 0.0
    resumed: bool = False


def run_seed(base_seed: int, item_id: str, condition: str, run_number: int) -> int:
    digest = hashlib.sha256(f"{base_seed}:{item_id}:{condition}:{run_number}".encode()).hexdigest()
    return int(digest[:8], 16) % (2**31)


class ExperimentRunner:
    def __init__(self, *, cfg: AppConfig, attack: AttackRelease, prompts: PromptSet,
                 dataset: LoadedDataset, workdir: Path | str, results_engine: Engine,
                 client_factory: ClientFactory, baseline: list[TestEvent],
                 benign_domains: list[str], model_id: str = "unknown",
                 base_seed: int | None = None, now: datetime | None = None,
                 allow_test_tlds: bool = True) -> None:
        self.cfg, self.attack, self.prompts, self.dataset = cfg, attack, prompts, dataset
        self.workdir = Path(workdir)
        self.results_engine = results_engine
        self.client_factory, self.baseline = client_factory, baseline
        self.benign_domains, self.model_id = benign_domains, model_id
        self.base_seed = dataset.data.seed if base_seed is None else base_seed
        self.now = now or datetime(2026, 10, 2, 9, 0, tzinfo=UTC)
        self.allow_test_tlds = allow_test_tlds
        self.order_sets = assign_order_sets(dataset.items, self.base_seed)
        self.store = EvidenceStore(self.workdir / "evidence")
        init_db(results_engine)

    # ---- helpers ---------------------------------------------------------------------------
    def _run_dir(self, item_id: str, condition: str, run_number: int) -> Path:
        d = self.workdir / "runs" / condition / item_id / f"run{run_number}"
        d.mkdir(parents=True, exist_ok=True)
        return d

    def _ingest(self, session, item: DatasetItem):
        published = datetime.fromisoformat(item.published).replace(tzinfo=UTC) \
            if item.published else None
        doc = collect_bytes(self.dataset.read(item), source_name=item.source.name,
                            url=item.source.url, title=item.id, published_at=published,
                            retrieved_at=self.now)
        src = get_or_create_source(session, name=item.source.name,
                                   reliability_rating=item.source.reliability,
                                   default_credibility=item.source.credibility)
        return ingest(session, self.store, doc, src, actor="experiment")

    def _canonical_item(self, item: DatasetItem) -> str:
        """The item in the results database (ingested once; runs point at it)."""
        with session_scope(self.results_engine) as s:
            out = self._ingest(s, item)
            return out.intel_id

    # ---- one run ----------------------------------------------------------------------------
    def run_item(self, item: DatasetItem, condition: str, run_number: int) -> RunRecord:
        if condition not in AUTOMATED:
            raise ValueError(f"the runner handles {AUTOMATED}; condition A is human work")
        seed = run_seed(self.base_seed, item.id, condition, run_number)
        order = self.order_sets.get(item.id, "X")
        run_dir = self._run_dir(item.id, condition, run_number)
        out_path = run_dir / "output.json"
        rec = RunRecord(item.id, condition, run_number, seed, order, str(out_path))
        if out_path.exists():
            saved = json.loads(out_path.read_text())
            rec.metrics, rec.error, rec.seconds, rec.resumed = (
                saved["metrics"], saved.get("error"), saved.get("seconds", 0.0), True)
            self._record(rec, item, saved.get("stages", {}), saved.get("cost", {}))
            return rec
        t0 = time.monotonic()
        engine = make_engine(f"sqlite:///{run_dir}/run.db")
        init_db(engine)
        client = self.client_factory(condition, item.id, run_number)
        gt = item.ground_truth
        stages: dict[str, float] = {}
        metrics: dict[str, Any] = {"failed": True}
        cost: dict[str, Any] = {}
        try:
            with session_scope(engine) as s:
                try:
                    t_ingest = time.monotonic()
                    iid = self._ingest(s, item).intel_id
                    ingest_seconds = time.monotonic() - t_ingest
                    test_set = self.dataset.test_set(item)
                    if condition == "C":
                        run, extra = self._run_c(s, iid, item, client, seed, test_set)
                    else:
                        run = run_pipeline(
                            s, self.store, iid, cfg=self.cfg, attack=self.attack, client=client,
                            prompts=self.prompts,
                            options=PipelineOptions(condition=condition, seed=seed,
                                                    allow_test_tlds=self.allow_test_tlds,
                                                    run_id=f"{condition}-{item.id}-{run_number}"),
                            benign_domains=self.benign_domains, test_set=test_set,
                            baseline=self.baseline, now=self.now)
                        extra = {}
                        rec.error = run.error
                    stages = {"ingest": ingest_seconds, **run.stage_seconds}
                    metrics = self._metrics(s, run, gt, extra)
                except Exception as exc:  # noqa: BLE001 - one bad run must not stop the experiment
                    rec.error = f"{type(exc).__name__}: {exc}"[:300]
                # What a run spent before it failed is still spent, so it is always counted.
                cost = mt.cost_metrics(s)
        except Exception as exc:  # noqa: BLE001 - the run database itself failed
            rec.error = rec.error or f"{type(exc).__name__}: {exc}"[:300]
        if is_budget_error(rec.error):
            metrics = {**metrics, "failed": True, "budget_exceeded": True}   # missing, not a fail
        rec.metrics = metrics
        rec.seconds = round(time.monotonic() - t0, 3)
        if cost:
            cost["time"] = mt.time_kinds(stages, cost.get("model_latency_ms", 0), rec.seconds)
        out_path.write_text(json.dumps({
            "item": item.id, "condition": condition, "run": run_number, "seed": seed,
            "order_set": order, "model": self.model_id, "prompt_set_sha256": self.prompts.sha256,
            "dataset_sha256": self.dataset.sha256(), "error": rec.error, "seconds": rec.seconds,
            "stages": stages, "metrics": metrics, "cost": cost}, indent=1, sort_keys=True,
            default=str))
        self._record(rec, item, stages, cost)
        return rec

    def _run_c(self, session, iid: str, item: DatasetItem, client: LLMClient, seed: int,
               test_set) -> tuple[PipelineRun, dict[str, Any]]:
        t0 = time.monotonic()
        row = session.get(m.IntelligenceItem, iid)
        text = self.store.load_text(row.raw_sha256)
        res = run_single_prompt(client, text, self.cfg, self.prompts.baseline, seed=seed)
        log_calls(session, run_id=f"C-{item.id}", agent="single_prompt_baseline", intel_id=iid,
                  calls=res.calls, prompt=self.prompts.baseline)
        run = PipelineRun(iid, "C", error=res.error)
        extra: dict[str, Any] = {"c_output": res.output is not None}
        if res.output is None:
            run.seconds = time.monotonic() - t0
            return run, extra
        out = res.output
        run.rules.extend(self._judge_sigma(out.sigma_rules, text, out.attack_techniques,
                                           out.decision.value, test_set, "C"))
        benign_in_list = 0
        for ioc in out.iocs:
            v = ioc.value.strip().lower()
            if host_allowed(v, self.benign_domains) or (
                    ioc.type.startswith("ipv") and not is_public_address(v)):
                benign_in_list += 1
        extra.update(iocs=[(i.type, i.value) for i in out.iocs], techniques=out.attack_techniques,
                     decision=out.decision.value, benign_in_list=benign_in_list,
                     rationale_len=len(out.rationale))
        run.seconds = time.monotonic() - t0
        run.stage_seconds["single_prompt"] = run.seconds
        return run, extra

    def _judge_sigma(self, texts: list[str], report_text: str, claimed: list[str], decision: str,
                     test_set, label: str) -> list[RuleRun]:
        """Judge Sigma rules written outside the pipeline (a single prompt, or a person) with the
        same gates the pipeline's rules face, applied afterwards."""
        counter = iter(range(110000, 119999))
        ids: dict[str, int] = {}
        out: list[RuleRun] = []
        for n, text_rule in enumerate(texts):
            rep = posthoc_report(text_rule, report_text, self.cfg, self.attack,
                                 claimed_techniques=claimed,
                                 allocate=lambda k, _i=ids: _i.setdefault(k, next(counter)),
                                 test_set=test_set, baseline=self.baseline)
            failed = rep.failed_gates
            outcome = "blocked" if "G6" in failed else (
                "validated" if rep.passed else "revision_required")
            out.append(RuleRun(
                opportunity_id=0, decision=decision, kind="sigma", rule_id=f"{label}-{n + 1}",
                loop_status="single_shot", first_pass_valid=rep.static.passed, repairs_used=0,
                attempts=1, outcome=outcome, failed_gates=failed,
                first_attempt_codes=[d.code for d in rep.static.defects],
                events=rep.events.details if rep.events else None,
                skipped=None if (rep.events or not rep.static.passed or test_set is None)
                else "no test events"))
        return out

    def register_manual(self, item: DatasetItem, rules_dir: Path | str, *,
                        disposition: str | None = None) -> RunRecord:
        """Record the rules an analyst wrote by hand for an item (condition A) so that the
        manual condition has detections to count and to judge with the same gates. Analyst time
        is not here: it comes from the timer. Only Sigma files (``*.yml``, ``*.yaml``) are
        judged; any other file is counted as an unjudged detection."""
        folder = Path(rules_dir)
        sigma = sorted([*folder.glob("*.yml"), *folder.glob("*.yaml")])
        other = sorted(p for p in folder.iterdir() if p.is_file() and p not in sigma)
        run_dir = self._run_dir(item.id, "A", 1)
        out_path = run_dir / "output.json"
        rec = RunRecord(item.id, "A", 1, 0, self.order_sets.get(item.id, "X"), str(out_path))
        with session_scope(self.results_engine) as s:
            iid = self._ingest(s, item).intel_id
            text = self.store.load_text(s.get(m.IntelligenceItem, iid).raw_sha256)
        rules = self._judge_sigma([p.read_text(encoding="utf-8") for p in sigma], text, [],
                                  "manual", self.dataset.test_set(item), "A")
        run = PipelineRun(iid, "A")
        run.rules.extend(rules)
        metrics = {"rules": mt.rule_metrics(run), "manual_rule_files": len(sigma),
                   "unjudged_files": [p.name for p in other], "disposition": disposition,
                   "per_rule": [{"kind": r.kind, "outcome": r.outcome,
                                 "first_pass_valid": r.first_pass_valid,
                                 "failed_gates": r.failed_gates} for r in rules]}
        rec.metrics = metrics
        out_path.write_text(json.dumps({
            "item": item.id, "condition": "A", "run": 1, "model": None,
            "dataset_sha256": self.dataset.sha256(), "error": None, "seconds": 0.0, "stages": {},
            "metrics": metrics, "cost": {}}, indent=1, sort_keys=True, default=str))
        self._record(rec, item, {}, {})
        return rec

    def _metrics(self, session, run: PipelineRun, gt, extra: dict[str, Any]) -> dict[str, Any]:
        if run.condition == "C":
            return self._metrics_c(run, gt, extra)
        return {"extraction": mt.extraction_metrics(session, gt),
                "opportunity": mt.opportunity_metrics(session, gt),
                "rules": mt.rule_metrics(run), "pipeline_error": run.error,
                "seconds": round(run.seconds, 3),
                "per_rule": [{"kind": r.kind, "decision": r.decision,
                              "first_pass_valid": r.first_pass_valid,
                              "repairs_used": r.repairs_used, "outcome": r.outcome,
                              "failed_gates": r.failed_gates, "quality_score": r.quality_score,
                              "loop_status": r.loop_status,
                              "first_attempt_codes": r.first_attempt_codes}
                             for r in run.rules]}

    def _metrics_c(self, run: PipelineRun, gt, extra: dict[str, Any]) -> dict[str, Any]:
        out: dict[str, Any] = {"rules": mt.rule_metrics(run), "pipeline_error": run.error,
                               "seconds": round(run.seconds, 3), "valid_output": extra["c_output"]}
        if not extra["c_output"]:
            return out
        pred_ind = {mt.canon(t, v) for t, v in extra["iocs"]}
        decision = Decision(extra["decision"])
        detectable = decision in GENERATING_DECISIONS
        ext: dict[str, Any] = {"indicators_found": len(pred_ind),
                               "techniques_found": sorted(extra["techniques"]),
                               "benign_in_list": extra["benign_in_list"]}
        opp: dict[str, Any] = {"decisions": [decision.value], "detectable_predicted": detectable}
        if gt is not None:
            ext["indicators"] = mt.prf(pred_ind, {mt.canon(i.type, i.value) for i in gt.indicators})
            ext["techniques"] = mt.technique_scores(set(extra["techniques"]), set(gt.techniques))
            allowed = {d.value for d in gt.decisions}
            opp["detectable_correct"] = detectable == gt.detectable
            opp["decision_set_match"] = round(
                len({decision.value} & allowed) / len({decision.value} | allowed), 4)
        out.update(extraction=ext, opportunity=opp)
        out["per_rule"] = [{"kind": r.kind, "decision": r.decision,
                            "first_pass_valid": r.first_pass_valid, "outcome": r.outcome,
                            "failed_gates": r.failed_gates,
                            "first_attempt_codes": r.first_attempt_codes} for r in run.rules]
        return out

    # ---- results database ---------------------------------------------------------------------
    def _record(self, rec: RunRecord, item: DatasetItem, stages: dict[str, float],
                cost: dict[str, Any]) -> None:
        intel_id = self._canonical_item(item)
        with session_scope(self.results_engine) as s:
            exists = s.scalars(select(m.ExperimentRun).where(
                m.ExperimentRun.condition == rec.condition, m.ExperimentRun.intel_id == intel_id,
                m.ExperimentRun.run_number == rec.run_number)).first()
            if exists:
                return
            s.add(m.ExperimentRun(
                condition=rec.condition, intel_id=intel_id, run_number=rec.run_number,
                order_set=rec.order_set, seed=rec.seed, model_id=self.model_id,
                prompt_set_sha256=self.prompts.sha256, output_ref=rec.output_ref))
            t = self.now
            for stage, seconds in stages.items():
                component = {"ingest": "c1_ingest", "processing": "c2_processing",
                             "opportunity": "c3_detection", "rules": "c3_detection",
                             "single_prompt": "c3_detection"}.get(stage, "c3_detection")
                agents = {"processing": ("extraction",), "opportunity": ("opportunity",),
                          "rules": ("rule",), "single_prompt": ("single_prompt_baseline",)
                          }.get(stage, ())
                a = [cost.get("agents", {}).get(x, {}) for x in agents]
                s.add(m.EffortCostRecord(
                    run_id=f"{rec.condition}-{item.id}-{rec.run_number}", intel_id=intel_id,
                    condition=Condition(rec.condition).value, component=component, activity=stage,
                    started_at=t, ended_at=t + timedelta(seconds=seconds),
                    api_calls=int(sum(x.get("calls", 0) for x in a)),
                    input_tokens=int(sum(x.get("input_tokens", 0) for x in a)),
                    output_tokens=int(sum(x.get("output_tokens", 0) for x in a)),
                    result_status="failed" if rec.error else "ok"))

    def run_all(self, conditions: tuple[str, ...] = AUTOMATED, runs: int | None = None,
                include_adversarial: bool = False,
                progress: Callable[[RunRecord], None] | None = None) -> list[RunRecord]:
        n_runs = runs if runs is not None else self.cfg.experiment.runs_per_item
        out: list[RunRecord] = []
        for item in self.dataset.items:
            if item.adversarial and not include_adversarial:
                continue
            for condition in conditions:
                for k in range(1, n_runs + 1):
                    rec = self.run_item(item, condition, k)
                    out.append(rec)
                    if progress:
                        progress(rec)
        return out
