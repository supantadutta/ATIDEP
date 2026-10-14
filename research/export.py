"""Flat analysis datasets from a results folder (blueprint §22, §29): ``runs.csv`` (one row per
run, metrics flattened), ``rules.csv`` (one row per generated rule), ``effort.csv`` (machine
effort records), ``analyst_effort.csv`` (analyst timer records from the live application
database, keyed by the content hash of the item so they join to the dataset) and
``manifest.json`` (what the files were made from). Plain CSV so the analysis can be redone in
any tool."""

from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path
from typing import Any

from sqlalchemy import Engine, select

from app.db import models as m
from app.db.session import session_scope


def flatten(d: dict[str, Any], prefix: str = "") -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in d.items():
        key = f"{prefix}{k}"
        if isinstance(v, dict):
            out.update(flatten(v, key + "."))
        elif isinstance(v, (list, tuple, set)):
            out[key] = ";".join(str(x) for x in v) if all(
                not isinstance(x, (dict, list)) for x in v) else json.dumps(v, default=str)
        else:
            out[key] = v
    return out


def _write(path: Path, rows: list[dict[str, Any]]) -> str:
    cols: list[str] = []
    for r in rows:
        for k in r:
            if k not in cols:
                cols.append(k)
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        w.writerows(rows)
    return hashlib.sha256(path.read_bytes()).hexdigest()


def analyst_effort_rows(engine: Engine) -> list[dict[str, Any]]:
    """One row per stopped analyst timer. Active time (the idle rule applied) and wall-clock
    time are separate columns; ``item_key`` is the item's raw-content SHA-256."""
    rows: list[dict[str, Any]] = []
    with session_scope(engine) as s:
        for e in s.scalars(select(m.EffortCostRecord).where(
                m.EffortCostRecord.component == "analyst").order_by(m.EffortCostRecord.id)):
            item = s.get(m.IntelligenceItem, e.intel_id) if e.intel_id else None
            first = s.scalars(select(m.TimerEvent).where(
                m.TimerEvent.session_id == e.run_id.removeprefix("timer-"))
                .order_by(m.TimerEvent.id)).first()
            rows.append({"item_key": item.raw_sha256 if item else None,
                         "condition": e.condition, "activity": e.activity,
                         "analyst": first.analyst if first else None,
                         "active_seconds": e.analyst_active_seconds,
                         "wall_seconds": (e.ended_at - e.started_at).total_seconds(),
                         "idle_capped_gaps": e.idle_capped_gaps,
                         "idle_capped_seconds": e.idle_capped_seconds,
                         "disposition": e.disposition})
    return rows


def export_results(results_engine: Engine, out_dir: Path | str,
                   analyst_engines: tuple[Engine, ...] = ()) -> dict[str, Any]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    runs: list[dict[str, Any]] = []
    rules: list[dict[str, Any]] = []
    with session_scope(results_engine) as s:
        for er in s.scalars(select(m.ExperimentRun).order_by(
                m.ExperimentRun.condition, m.ExperimentRun.intel_id, m.ExperimentRun.run_number)):
            doc = json.loads(Path(er.output_ref).read_text()) if er.output_ref else {}
            title = s.get(m.IntelligenceItem, er.intel_id).title
            base = {"item": doc.get("item", title), "condition": er.condition,
                    "run": er.run_number, "order_set": er.order_set, "seed": er.seed,
                    "model": er.model_id, "prompt_set_sha256": er.prompt_set_sha256,
                    "dataset_sha256": doc.get("dataset_sha256"), "error": doc.get("error"),
                    "seconds": doc.get("seconds")}
            met = dict(doc.get("metrics", {}))
            per_rule = met.pop("per_rule", [])
            runs.append({**base, **flatten(met), **{f"cost.{k}": v for k, v in flatten(
                {x: y for x, y in doc.get("cost", {}).items() if x != "agents"}).items()}})
            for i, r in enumerate(per_rule, 1):
                rules.append({**{k: base[k] for k in ("item", "condition", "run")}, "rule_no": i,
                              **flatten(r)})
        effort = [{"run_id": e.run_id, "intel_id": e.intel_id, "condition": e.condition,
                   "component": e.component, "activity": e.activity,
                   "seconds": (e.ended_at - e.started_at).total_seconds(),
                   "analyst_active_seconds": e.analyst_active_seconds, "api_calls": e.api_calls,
                   "input_tokens": e.input_tokens, "output_tokens": e.output_tokens,
                   "status": e.result_status}
                  for e in s.scalars(select(m.EffortCostRecord).where(
                      m.EffortCostRecord.component != "analyst").order_by(m.EffortCostRecord.id))]
    analyst = [r for e in (results_engine, *analyst_engines) for r in analyst_effort_rows(e)]
    hashes = {name: _write(out / name, rows) for name, rows in
              (("runs.csv", runs), ("rules.csv", rules), ("effort.csv", effort),
               ("analyst_effort.csv", analyst))}
    manifest = {"rows": {"runs": len(runs), "rules": len(rules), "effort": len(effort),
                         "analyst_effort": len(analyst)}, "sha256": hashes}
    (out / "manifest.json").write_text(json.dumps(manifest, indent=1, sort_keys=True))
    return manifest
