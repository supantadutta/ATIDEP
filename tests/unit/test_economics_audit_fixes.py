"""One test per finding of the economics audit of 15 October 2026 (synthetic inputs only): each
pins the corrected behaviour so that it cannot quietly return."""

import pytest
from pydantic import ValidationError

from app.config import EconomicConfig
from research.economics.analysis import h7, side, unit_costs
from research.economics.inputs import load_cost_inputs, readiness
from research.economics.ledger import evaluate, evidence_shares, lines_without_amount
from research.economics.measured import Measured, load_measured
from schemas.cost_model import Host, PriceComponent, PriceRegister
from tests.unit.economics_fixtures import (
    comp,
    entry,
    make_inputs,
    rates_doc,
    register_doc,
    val,
)
from tests.unit.test_economics_analysis import item, measured
from tests.unit.test_economics_ledger import Q, row
from tests.unit.test_economics_report import RUN_COLS, run, session, write


# ---- 1. a candidate that cannot be costed leaves its line incomplete ---------------------------
def test_a_group_with_an_uncostable_candidate_is_incomplete_not_silently_cheaper():
    reg = register_doc([
        entry("llm.usd_cheap", "llm_api", [comp("mtok_in", 0.1), comp("mtok_out", 0.4)],
              currency="USD"),
        entry("llm.tst_dear", "llm_api", [comp("mtok_in", 3000.0), comp("mtok_out", 12000.0)])])
    led = evaluate(make_inputs(register=reg), "S-PAID", "scale_200", Q)
    llm = row(led, "llm_api")
    assert llm.status == "incomplete" and llm.amount is None
    assert any("exchange rate USD to TST" in m for m in llm.missing)
    assert "1 of 2 adequate candidates costable" in llm.note
    assert not led.totals.technology_complete
    assert h7(make_inputs(register=reg), measured(), "scale_200",
              delta_c_pct=20.0).paid.complete is False


def test_an_excluded_candidate_is_named_with_its_reason():
    reg = register_doc([
        entry("llm.a", "llm_api", [comp("mtok_in", 1.0), comp("mtok_out", 4.0)],
              adequate=False, adequacy_note="context window too small for the reports"),
        entry("llm.b", "llm_api", [comp("mtok_in", 3.0), comp("mtok_out", 12.0)])])
    llm = row(evaluate(make_inputs(register=reg), "S-PAID", "scale_200", Q), "llm_api")
    assert llm.entry == "llm.b" and "llm.a (context window too small" in llm.note


# ---- 2. the amortisation horizon is a pre-registered decision -----------------------------------
def test_the_horizon_must_be_chosen_and_must_be_one_of_the_reported_ones(tmp_path):
    with pytest.raises(ValueError, match="horizon"):
        evaluate(make_inputs(horizon=None), "S-OSS-LOCAL", "scale_200", Q)
    r = h7(make_inputs(horizon=None), measured(), "scale_200", delta_c_pct=4.0)
    assert r.verdict == "not_evaluable" and r.horizon_months is None
    assert h7(make_inputs(), measured(), "scale_200", delta_c_pct=4.0).horizon_months == 12
    assert any(g.what == "economics.primary_horizon_months" for g in readiness(load_cost_inputs()))


# ---- 3. each scenario is divided by its own arm's detections ------------------------------------
def test_the_manual_scenario_is_divided_by_the_manual_arms_rules():
    items = [item(i, counts_by_condition={"A": {"generated": 1.0, "assessed": 1.0,
                                                "valid": 1.0}}) for i in range(8)]
    meas = Measured(items, {})
    u = unit_costs(make_inputs(), meas, "S-MANUAL", "scale_200")
    assert u["detections_from_condition"] == "A"
    assert u["rates_per_item"]["generated"] == 1.0                    # not condition B's 2.0
    assert u["per_generated_detection"] == pytest.approx(u["monthly"]["total"] / 200)
    assert u["rates_per_item"]["approved"] is None                    # not attributable
    assert unit_costs(make_inputs(), meas, "S-OSS-LOCAL", "scale_200")[
        "rates_per_item"]["generated"] == 2.0


# ---- 4. readiness says what the ledger still lacks --------------------------------------------
def test_readiness_lists_workload_quantities_exchange_rates_and_pending_licences():
    reg = register_doc([entry("siem.usd", "siem_platform",
                              [comp("gb_ingested_month", 0.3)], currency="USD")])
    inputs = make_inputs(register=reg, keep_pending=True,
                         workload_overrides={"siem_ingest_gb_per_month": {"value": None}})
    what = {g.what for g in readiness(inputs)}
    assert "exchange rate USD to TST" in what
    assert any(w.startswith("siem_ingest_gb_per_month of workload") for w in what)
    assert "licence of model_weights" in what


# ---- 5. evidence shares do not promote a price or an assumption --------------------------------
def test_a_list_price_is_supplied_evidence_and_hardware_is_as_weak_as_its_inputs():
    reg = register_doc([
        entry("llm.a", "llm_api", [comp("mtok_in", 1.0), comp("mtok_out", 4.0)]),
        entry("vm.flat", "cloud_compute", [comp("month", 900.0)]),
        entry("disk.a", "cloud_storage", [comp("gb_month", 0.05)]),
        entry("siem.a", "siem_platform", [comp("gb_ingested_month", 0.3)])])
    paid = evaluate(make_inputs(register=reg), "S-PAID", "scale_200", Q)
    assert row(paid, "cloud_compute").quantity_basis == "supplied"
    shares = evidence_shares(paid)
    assert "measured" not in shares or shares["measured"] < 1.0
    local = evaluate(make_inputs(), "S-OSS-LOCAL", "scale_200", Q)
    assert row(local, "hardware").price_basis == "assumed"            # fixtures are assumptions
    assert lines_without_amount(local) == []
    unpriced = evaluate(load_cost_inputs(), "S-PAID", "scale_50", Q, horizon_months=12)
    assert any(x["quote_required"] for x in lines_without_amount(unpriced))


# ---- 6. register provenance is enforced --------------------------------------------------------
@pytest.mark.parametrize("change, message", [
    ({"price_basis": None}, "price_basis"),
    ({"archive_ref": None}, "archive_ref"),
    ({"adequate": False}, "adequacy_note"),
])
def test_a_priced_entry_needs_its_provenance(change, message):
    bad = entry("llm.a", "llm_api", [comp("mtok_in", 1.0), comp("mtok_out", 4.0)], **change)
    with pytest.raises(ValidationError, match=message):
        PriceRegister(**register_doc([bad]))


def test_a_zero_price_needs_a_reason_and_a_billing_unit_must_name_its_kind():
    with pytest.raises(ValidationError, match="zero_price_reason"):
        PriceComponent(unit_kind="hour", price=0.0, billing_unit="per hour")
    PriceComponent(unit_kind="hour", price=0.0, billing_unit="per hour",
                   zero_price_reason="free tier up to 750 hours")
    with pytest.raises(ValidationError, match="does not name the unit kind"):
        PriceComponent(unit_kind="mtok_in", price=1.0, billing_unit="per 1K input tokens")


# ---- 7, 8, 9, 10. the measured quantities ------------------------------------------------------
def _export(tmp_path, runs, sessions):
    d = tmp_path / "x"
    d.mkdir()
    cols = RUN_COLS + ["cost.providers", "cost.replayed_calls", "error"]
    write(d / "runs.csv", cols, runs)
    write(d / "analyst_effort.csv", list(sessions[0]), sessions)
    return d


def test_hosted_runs_are_kept_apart_and_feed_the_hosted_tokens(tmp_path):
    runs = [run("I1", **{"cost.providers": "ollama"}),
            run("I1", k=2, **{"cost.providers": "cloud-openai", "cost.input_tokens": 3000,
                              "cost.output_tokens": 700, "cost.time.model_wait_seconds": 10})]
    m = load_measured(_export(tmp_path, runs, [session("I1", "B", 900)]))
    q = m.quantities(100)
    assert q.local_tokens == (2000.0, 500.0) and q.cloud_tokens == (3000.0, 700.0)
    assert q.inference_hours_per_item == pytest.approx(144 / 3600) and m.hosted_runs == 1


def test_review_time_is_averaged_over_analysts_not_summed(tmp_path):
    s = [session("I1", "B", 900), {**session("I1", "B", 900), "analyst": "independent"},
         session("I1", "A", 3600), {**session("I1", "A", 3600), "analyst": "independent"}]
    m = load_measured(_export(tmp_path, [run("I1")], s))
    assert m.items[0].analyst_h == {"B": 0.25, "A": 1.0}


def test_replayed_runs_do_not_count_as_zero_model_wait(tmp_path):
    runs = [run("I1"), run("I1", k=2, **{"cost.time.model_wait_seconds": 0,
                                         "cost.replayed_calls": 9})]
    m = load_measured(_export(tmp_path, runs, [session("I1", "B", 900)]))
    assert m.items[0].inference_h == pytest.approx(144 / 3600)
    assert m.replayed_runs_without_wait == 1


def test_an_item_lost_to_the_spend_cap_is_listed_and_a_crash_counts_as_nothing(tmp_path):
    runs = [run("I1"), run("I2", **{"budget_exceeded": "True"}),
            run("I1", k=2, **{"rules.sigma_rules": "", "rules.ioc_bundles": "",
                              "rules.assessed": "", "rules.validated": "", "error": "crash"})]
    m = load_measured(_export(tmp_path, runs, [session("I1", "B", 900)]))
    assert m.dropped_items == ["I2"] and m.budget_stopped == 1
    assert m.items[0].generated == pytest.approx(1.0) and m.items[0].valid == pytest.approx(0.5)
    assert m.report()["dropped_items"] == ["I2"]


# ---- 11. labour money and completeness ---------------------------------------------------------
def test_an_engineer_rate_that_is_set_is_never_reported_missing():
    rates = rates_doc()
    rates["maintenance"]["monthly_rule_tuning_hours"] = {"value": None}
    led = evaluate(make_inputs(rates=rates), "S-OSS-LOCAL", "scale_200", Q)
    s = side(led, basis="differential")
    assert "labour.engineer_hourly" not in s.missing and not s.complete
    assert s.value > led.totals.technology                 # the known hours are in the bound
    no_eng = rates_doc()
    no_eng["labour"]["engineer_hourly"] = {"value": None}
    u = unit_costs(make_inputs(rates=no_eng), measured(), "S-OSS-LOCAL", "scale_200")
    assert u["complete"] is False and u["monthly"]["total"] is None


# ---- 12. a pending licence is not a free licence -----------------------------------------------
def test_a_pending_model_licence_leaves_the_open_source_side_incomplete():
    led = evaluate(make_inputs(keep_pending=True), "S-OSS-LOCAL", "scale_200", Q)
    w = row(led, "model_weights")
    assert w.status == "incomplete" and w.amount is None
    assert not led.totals.technology_complete


# ---- 13. money needs a currency ----------------------------------------------------------------
def test_without_a_reporting_currency_nothing_is_complete():
    rates = rates_doc()
    rates["reporting_currency"] = None
    t = evaluate(make_inputs(rates=rates), "S-OSS-LOCAL", "scale_200", Q).totals
    assert not t.technology_complete and "reporting_currency" in t.missing
    assert t.differential is None and t.operating_money is None


# ---- 14. units that a typo would break ---------------------------------------------------------
def test_a_useful_life_in_years_or_a_zero_draw_is_refused():
    with pytest.raises(ValidationError, match="months"):
        Host(useful_life_months=val(3))
    with pytest.raises(ValidationError, match="positive"):
        Host(power_active_watts=val(0))


# ---- 15 and 16. no invented spend cap; a meaningful threshold ----------------------------------
def test_the_shipped_spend_cap_is_unset_and_delta_c_of_100_is_refused():
    from app.config import load_config
    assert load_config().policies.llm.daily_cost_limit is None
    base = load_config().experiment.economics.model_dump()
    with pytest.raises(ValidationError):
        EconomicConfig(**{**base, "delta_c_pct": 100})
