"""Flat analysis datasets from a results folder (blueprint §22, §29): ``runs.csv`` (one row per
run, metrics flattened), ``rules.csv`` (one row per generated rule), ``effort.csv`` (machine
and analyst effort records) and ``manifest.json`` (what the files were made from). Plain CSV so
the analysis can be redone in any tool."""

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


def export_results(results_engine: Engine, out_dir: Path | str) -> dict[str, Any]:
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
                  for e in s.scalars(select(m.EffortCostRecord).order_by(m.EffortCostRecord.id))]
    hashes = {name: _write(out / name, rows) for name, rows in
              (("runs.csv", runs), ("rules.csv", rules), ("effort.csv", effort))}
    manifest = {"rows": {"runs": len(runs), "rules": len(rules), "effort": len(effort)},
                "sha256": hashes}
    (out / "manifest.json").write_text(json.dumps(manifest, indent=1, sort_keys=True))
    return manifest
