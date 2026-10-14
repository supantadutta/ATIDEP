"""Write the economic evaluation's tables and a summary from the exported results.

Everything here is regenerated from the exports and the four cost files; nothing is typed in. The
summary states what was measured, what was assumed, what is missing and who has to supply it, and
it prints the exact wording ``Vendor quote required / public price unavailable`` for every
unpriced line.
"""

from __future__ import annotations

import csv
import hashlib
import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from research.economics import analysis as an
from research.economics.inputs import CostInputs, load_cost_inputs, readiness
from research.economics.ledger import candidate_cost, evaluate, evidence_shares
from research.economics.measured import Measured, load_measured
from schemas.cost_model import QUOTE_REQUIRED


def _write(path: Path, rows: list[dict[str, Any]]) -> None:
    cols: list[str] = []
    for r in rows:
        for k in r:
            if k not in cols:
                cols.append(k)
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        w.writerows(rows)


def _flat(d: dict[str, Any], prefix: str = "") -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in d.items():
        if isinstance(v, dict):
            out.update(_flat(v, f"{prefix}{k}."))
        elif isinstance(v, list):
            out[f"{prefix}{k}"] = "; ".join(map(str, v))
        else:
            out[f"{prefix}{k}"] = v
    return out


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


# ---- tables ----------------------------------------------------------------------------------
def ledger_rows(inputs: CostInputs, meas: Measured) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    sc = inputs.scenarios
    for sid in (sc.oss_local, sc.oss_api, sc.paid, sc.manual):
        for w in sc.workloads:
            q = meas.quantities(w.items_per_month.value or 0.0, storage_gb=w.storage_gb.value,
                                siem_ingest_gb=w.siem_ingest_gb_per_month.value,
                                endpoints=w.monitored_endpoints.value)
            for view in inputs.economics.views:
                for case in inputs.economics.price_cases:
                    for perimeter in ("workflow", "platform"):
                        led = evaluate(inputs, sid, w.id, q, view=view, case=case,
                                       perimeter=perimeter)  # type: ignore[arg-type]
                        for r in led.rows:
                            rows.append({"scenario": sid, "workload": w.id, "view": view,
                                         "price_case": case, "perimeter": perimeter,
                                         "line": r.line, "function": r.function,
                                         "category": r.category, "recurrence": r.recurrence,
                                         "quantity": r.quantity, "unit": r.unit,
                                         "unit_price": r.unit_price, "amount_per_month": r.amount,
                                         "hours_per_month": r.hours, "labour": r.labour,
                                         "quantity_basis": r.quantity_basis,
                                         "price_basis": r.price_basis, "register_entry": r.entry,
                                         "status": r.status, "missing": "; ".join(r.missing),
                                         "note": r.note})
    return rows


def costed_register(inputs: CostInputs, meas: Measured) -> list[dict[str, Any]]:
    """Every register entry with its provenance and, per workload, the calculated monthly cost
    (or the exact wording when it has no public price)."""
    rows: list[dict[str, Any]] = []
    for e in inputs.register.entries:
        base = {"entry": e.id, "group": e.group, "status": e.status, "adequate": e.adequate,
                "adequacy_note": e.adequacy_note, "vendor": e.vendor, "product": e.product,
                "tier": e.tier, "currency": e.currency, "pricing_source": e.pricing_source,
                "pricing_url": e.pricing_url, "checked_on": e.checked_on,
                "price_basis": e.price_basis.value if e.price_basis else None,
                "archive_ref": e.archive_ref, "workload_assumption": e.workload_assumption,
                "components": "; ".join(f"{c.price} {e.currency} {c.billing_unit} (included "
                                        f"{c.included_quantity})" for c in e.components),
                "fixed_monthly_fee": e.fixed_monthly_fee, "notes": e.notes}
        for w in inputs.scenarios.workloads:
            q = meas.quantities(w.items_per_month.value or 0.0, storage_gb=w.storage_gb.value,
                                siem_ingest_gb=w.siem_ingest_gb_per_month.value,
                                endpoints=w.monitored_endpoints.value)
            if e.status != "priced":
                calc, why = QUOTE_REQUIRED, ""
            else:
                cost, miss, _ = candidate_cost(e, q, "cloud", inputs)
                calc, why = ("not computable" if cost is None else cost), "; ".join(miss)
            rows.append({**base, "workload": w.id,
                         "items_per_month": w.items_per_month.value,
                         "calculated_monthly_cost": calc, "calculation_missing": why})
    return rows


def time_kinds_rows(export_dir: Path, meas: Measured) -> list[dict[str, Any]]:
    """The four kinds of time, side by side and never summed, per condition. Analyst active time
    is the timer's (per item); the others are the means of the runs' own records."""
    path = export_dir / "runs.csv"
    rows: list[dict[str, Any]] = []
    if path.exists():
        with path.open(newline="", encoding="utf-8") as fh:
            runs = list(csv.DictReader(fh))
        for cond in sorted({r["condition"] for r in runs}):
            rs = [r for r in runs if r["condition"] == cond and r.get("budget_exceeded") != "True"]

            def mean(col: str, rs=rs) -> float | None:
                xs = [float(r[col]) for r in rs if r.get(col) not in (None, "", "None")]
                return sum(xs) / len(xs) if xs else None

            rows.append({"condition": cond, "runs": len(rs),
                         "automated_s_per_run": mean("cost.time.automated_seconds"),
                         "model_inference_s_per_run": mean("cost.time.model_wait_seconds"),
                         "wall_s_per_run": mean("cost.time.wall_seconds"),
                         "harness_s_per_run": mean("cost.time.harness_seconds")})
    for cond in ("A", "B"):
        xs = [i.analyst_h.get(cond) for i in meas.items]
        if xs and all(x is not None for x in xs):
            rows.append({"condition": f"{cond} (analyst, running-stopwatch active time)",
                         "runs": len(xs),
                         "analyst_active_s_per_item": 3600.0 * sum(xs) / len(xs)})  # type: ignore
    return rows


# ---- the report ------------------------------------------------------------------------------
def run_report(config_dir: Path | str, export_dir: Path | str, out_dir: Path | str, *,
               categories: dict[str, str] | None = None, technical: dict[str, bool | None]
               | None = None, resamples: int | None = None) -> dict[str, Any]:
    exp, out = Path(export_dir), Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    inputs = load_cost_inputs(config_dir)
    meas = load_measured(exp, categories)
    eco, sc = inputs.economics, inputs.scenarios

    gaps = readiness(inputs)
    (out / "readiness.json").write_text(json.dumps([asdict(g) for g in gaps], indent=1))
    _write(out / "ledger.csv", ledger_rows(inputs, meas))
    _write(out / "price_register_costed.csv", costed_register(inputs, meas))
    _write(out / "time_kinds.csv", time_kinds_rows(exp, meas))

    units = []
    for sid in (sc.oss_local, sc.paid, sc.manual):
        for w in sc.workloads:
            units.append(_flat(an.unit_costs(inputs, meas, sid, w.id)))
    _write(out / "unit_costs.csv", units)

    primary = eco.primary_workload
    bases = ("differential", "technology")
    cells = {b: an.grid(inputs, meas, basis=b) for b in bases}
    summary: dict[str, Any] = {"primary_workload": primary, "delta_c_pct": eco.delta_c_pct,
                               "bases": {}}
    for b in bases:
        label, failing = an.robustness(cells[b])
        entry: dict[str, Any] = {"robustness": label, "cells_not_supported": failing,
                                 "grid": [_cell(c) for c in cells[b]]}
        if primary:
            r = an.h7(inputs, meas, primary, basis=b)
            entry["primary"] = _cell(r)
            t = technical or {}
            entry["joint"] = an.joint_verdict(
                an.technical_adequacy(t.get("h2"), t.get("h3"), t.get("h4")), r)
        summary["bases"][b] = entry
    be = an.break_even_volume(inputs, meas)
    summary["break_even_vs_manual"] = be
    n = resamples or inputs.bootstrap_resamples
    if primary:
        def stat(m: Measured, w: str = primary) -> float | None:
            r = an.h7(inputs, m, w, basis="differential", delta_c_pct=eco.delta_c_pct or 1.0)
            return (r.paid.value - r.open_source.value) if (r.open_source.complete
                                                            and r.paid.complete) else None
        summary["bootstrap_paid_minus_open_source"] = an.bootstrap_bca(
            meas, stat, n_resamples=n, seed=20261014)
    sh = {}
    if primary:
        w = sc.workload(primary)
        q = meas.quantities(w.items_per_month.value or 0.0, storage_gb=w.storage_gb.value,
                            siem_ingest_gb=w.siem_ingest_gb_per_month.value,
                            endpoints=w.monitored_endpoints.value)
        for sid in (sc.oss_local, sc.paid):
            sh[sid] = evidence_shares(evaluate(inputs, sid, primary, q, view=eco.primary_view,
                                               case=eco.primary_price_case))
    summary["evidence_shares_at_primary"] = sh
    (out / "economics.json").write_text(json.dumps(summary, indent=1, default=str))
    (out / "economics.md").write_text(_markdown(inputs, meas, gaps, summary))

    manifest = {"config_sha256": inputs.hashes,
                "export_sha256": {p.name: _sha(p) for p in sorted(exp.glob("*.csv"))},
                "outputs": {p.name: _sha(p) for p in sorted(out.glob("*")) if p.is_file()
                            and p.name != "manifest.json"}}
    (out / "manifest.json").write_text(json.dumps(manifest, indent=1, sort_keys=True))
    return summary


def _cell(r: an.H7Result) -> dict[str, Any]:
    return {"workload": r.workload, "view": r.view, "price_case": r.case, "basis": r.basis,
            "verdict": r.verdict, "reason": r.reason, "open_source": r.open_source.value,
            "open_source_complete": r.open_source.complete, "paid": r.paid.value,
            "paid_complete": r.paid.complete, "saving_pct": r.saving_pct,
            "paid_needed": r.paid_needed, "flip": r.flip, "screening": r.screening,
            "missing_open_source": r.open_source.missing, "missing_paid": r.paid.missing}


def _markdown(inputs: CostInputs, meas: Measured, gaps, summary: dict[str, Any]) -> str:
    eco = inputs.economics
    L = ["# Economic evaluation: generated summary", "",
         "Generated from the exported results and the four cost files. Nothing in it is typed in.",
         "The paid side is a **modelled counterfactual** (S-PAID) with **assumed equal technical "
         "performance**; nothing here establishes parity with any paid system. Review labour is "
         "common to the automated scenarios and is left out of the comparison (reported in hours).",
         "", f"Currency: {inputs.rates.reporting_currency or 'NOT SET'}. "
         f"Primary workload: {eco.primary_workload or 'NOT CHOSEN'}. "
         f"delta_c: {eco.delta_c_pct if eco.delta_c_pct is not None else 'NOT SET'}%. "
         f"Items measured: {len(meas.items)}.", "", "## What is still missing", ""]
    for g in gaps:
        L.append(f"- {g.what} (needed for {g.needed_for}; **{g.supplied_by}**): {g.how}")
    L += ["", "## H7 (cost advantage) at the primary cell", ""]
    for b, e in summary["bases"].items():
        p = e.get("primary")
        if p:
            L.append(f"- basis **{b}**: **{p['verdict']}** ({p['reason']}); robustness: "
                     f"{e['robustness']}. Saving: {p['saving_pct']}.")
            if p["flip"]:
                L.append("  - flips with the engineer rate: supported for "
                         f"{p['flip']['supported_for']}")
            for m in p["missing_paid"]:
                L.append(f"  - paid side unpriced: {m}")
            for m in p["missing_open_source"]:
                L.append(f"  - open-source side missing: {m}")
        else:
            L.append(f"- basis **{b}**: no primary workload chosen; grid robustness "
                     f"{e['robustness']}.")
    L += ["", "## Break-even against the manual workflow", "",
          f"{summary['break_even_vs_manual']}", "",
          "## Not covered by money", "",
          "Vendor support and SLAs, curated content, certifications, liability, the single "
          "maintainer risk of an open-source stack, and data leaving the premises when a hosted "
          "model is used are real differences that this evaluation does not convert to money. "
          "List prices usually exceed prices paid, which biases the comparison towards the "
          "open-source side; the lowest-priced adequate candidate is used, which biases it the "
          "other way.", ""]
    return "\n".join(L)
