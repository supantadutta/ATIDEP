"""Loading measured quantities from exported CSVs, and regenerating the report."""

import csv
import json

import pytest

from research.economics.__main__ import main
from research.economics.measured import load_measured
from research.economics.report import run_report
from schemas.cost_model import QUOTE_REQUIRED
from tests.unit.economics_fixtures import make_inputs  # noqa: F401 - re-exported for fixtures

RUN_COLS = ["item", "item_key", "condition", "run", "cost.input_tokens", "cost.output_tokens",
            "cost.tokens_reliable", "cost.time.automated_seconds", "cost.time.model_wait_seconds",
            "cost.time.wall_seconds", "cost.time.harness_seconds", "rules.sigma_rules",
            "rules.ioc_bundles", "rules.assessed", "rules.validated", "budget_exceeded"]


def write(path, cols, rows):
    with path.open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        w.writerows(rows)


def run(item, cond="B", k=1, **kw):
    base = {"item": item, "item_key": f"key-{item}", "condition": cond, "run": k,
            "cost.input_tokens": 2000, "cost.output_tokens": 500, "cost.tokens_reliable": "True",
            "cost.time.automated_seconds": 36, "cost.time.model_wait_seconds": 144,
            "cost.time.wall_seconds": 200, "cost.time.harness_seconds": 20,
            "rules.sigma_rules": 1, "rules.ioc_bundles": 1, "rules.assessed": 2,
            "rules.validated": 1, "budget_exceeded": ""}
    base.update(kw)
    return base


def session(item, cond, active, disp="", activity="review_approval"):
    return {"item_key": f"key-{item}", "condition": cond, "activity": activity, "analyst": "a",
            "active_seconds": active, "wall_seconds": active, "idle_capped_gaps": 0,
            "idle_capped_seconds": 0, "disposition": disp}


@pytest.fixture()
def export(tmp_path):
    d = tmp_path / "export"
    d.mkdir()
    items = ["I1", "I2", "I3"]
    runs = [run(i, k=k) for i in items for k in (1, 2, 3)]
    runs += [run("I1", "C", 1), run("I2", "B-V", 1, **{"budget_exceeded": "True"})]
    write(d / "runs.csv", RUN_COLS, runs)
    sessions = []
    for i in items:
        sessions += [session(i, "B", 450, "in_progress"), session(i, "B", 450, "accepted"),
                     session(i, "A", 3600, "accepted")]
    sessions.append({**session("I1", "B", 999), "item_key": "", "activity": "operations"})
    write(d / "analyst_effort.csv", list(sessions[0]), sessions)
    write(d / "live_rules.csv", ["item_key", "rule_id", "kind", "state", "approved", "deployed_lab"],
          [{"item_key": "key-I1", "rule_id": "R1", "kind": "sigma", "state": "approved",
            "approved": True, "deployed_lab": False},
           {"item_key": "key-I1", "rule_id": "R2", "kind": "ioc_list", "state": "deployed",
            "approved": True, "deployed_lab": True},
           {"item_key": "key-I2", "rule_id": "R3", "kind": "sigma", "state": "blocked",
            "approved": False, "deployed_lab": False}])
    return d


def test_measured_quantities_join_the_two_planes_by_content_hash(export):
    m = load_measured(export, {"I1": "ioc", "I2": "behaviour", "I3": "behaviour"})
    assert [i.item for i in m.items] == ["I1", "I2", "I3"] and all(i.runs == 3 for i in m.items)
    i1 = m.items[0]
    assert i1.tokens_in == 2000 and i1.tokens_out == 500 and i1.category == "ioc"
    assert i1.automated_h == pytest.approx(36 / 3600) and i1.inference_h == pytest.approx(0.04)
    assert i1.analyst_h["B"] == pytest.approx(900 / 3600)               # two sessions summed
    assert i1.analyst_h["A"] == pytest.approx(1.0)
    assert i1.accepted == {"A": True, "B": True}                         # the last session's
    assert (i1.approved_rules, i1.deployed_rules) == (2, 1)
    assert (m.items[1].approved_rules, m.items[1].deployed_rules) == (0, 0)
    assert m.items[2].approved_rules == 0                                # no rule recorded: zero
    # the operations session has no item and never enters per-item minutes
    assert sum(i.analyst_h["B"] for i in m.items) == pytest.approx(3 * 0.25)
    assert m.budget_stopped == 1 and m.runs_by_condition == {"B": 9, "C": 1, "B-V": 1}
    assert m.overhead["C"].runs == 1 and "B-V" not in m.overhead     # a cap stop is left out
    q = m.quantities(100)
    assert q.local_tokens == (2000, 500) and q.review_hours_per_item["A"] == pytest.approx(1.0)


def test_tokens_that_the_provider_did_not_report_are_missing_not_zero(export):
    d = export
    rows = list(csv.DictReader((d / "runs.csv").open()))
    rows[0]["cost.tokens_reliable"] = "False"                          # one run of I1
    write(d / "runs.csv", RUN_COLS, rows)
    m = load_measured(d)
    assert m.items[0].tokens_in is None and m.items[1].tokens_in == 2000
    assert m.quantities(100).local_tokens is None                      # any gap makes the mean missing


def test_an_item_without_live_data_has_no_approved_count(tmp_path, export):
    (export / "live_rules.csv").unlink()
    m = load_measured(export)
    assert all(i.approved_rules is None for i in m.items) and m.approved_rate() is None


def test_the_report_is_regenerated_from_the_exports_and_marks_everything_unpriced(export,
                                                                                  tmp_path):
    out = tmp_path / "out"
    summary = run_report("config", export, out, resamples=100)
    for name in ("ledger.csv", "price_register_costed.csv", "unit_costs.csv", "time_kinds.csv",
                 "readiness.json", "economics.json", "economics.md", "manifest.json"):
        assert (out / name).exists(), name
    md = (out / "economics.md").read_text()
    assert "modelled counterfactual" in md and "NOT SET" in md and "NOT CHOSEN" in md
    assert "nothing here establishes parity with any paid system" in md
    costed = list(csv.DictReader((out / "price_register_costed.csv").open()))
    assert costed and all(r["calculated_monthly_cost"] == QUOTE_REQUIRED for r in costed)
    ledger = list(csv.DictReader((out / "ledger.csv").open()))
    unpriced = [r for r in ledger if r["line"] == "llm_api" and r["scenario"] == "S-PAID"]
    assert unpriced and all(r["amount_per_month"] == "" and QUOTE_REQUIRED in r["missing"]
                            for r in unpriced)
    tk = list(csv.DictReader((out / "time_kinds.csv").open()))
    b = next(r for r in tk if r["condition"] == "B")
    assert float(b["automated_s_per_run"]) == 36 and float(b["model_inference_s_per_run"]) == 144
    manifest = json.loads((out / "manifest.json").read_text())
    assert set(manifest["config_sha256"]) >= {"cost_rates.yaml", "price_register.yaml",
                                              "cost_scenarios.yaml"}
    assert "runs.csv" in manifest["export_sha256"]
    assert summary["bases"]["differential"]["robustness"] == "not evaluable"


def test_the_command_line_reports_what_is_missing(capsys):
    assert main(["check"]) == 1
    text = capsys.readouterr().out
    assert "input(s) still missing" in text and "[coordinator]" in text and "[researcher]" in text
