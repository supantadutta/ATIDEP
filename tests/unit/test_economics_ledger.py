"""The cost ledger, checked against hand-computed numbers (synthetic inputs, currency TST)."""

import pytest

from research.economics.inputs import load_cost_inputs, readiness
from research.economics.ledger import Quantities, evaluate, evidence_shares
from schemas.cost_model import QUOTE_REQUIRED
from tests.unit.economics_fixtures import (
    comp,
    entry,
    make_inputs,
    rates_doc,
    register_doc,
    val,
)

Q = Quantities(items_per_month=200, review_hours_per_item={"A": 1.0, "B": 0.25},
               automated_hours_per_item=0.01, inference_hours_per_item=0.04,
               local_tokens=(2000.0, 500.0), storage_gb=50, siem_ingest_gb=100, endpoints=10)


def row(ledger, line):
    return next(r for r in ledger.rows if r.line == line)


# ---- the open-source scenario, by hand ---------------------------------------------------------------
def test_the_local_scenario_adds_up_to_the_hand_calculation():
    led = evaluate(make_inputs(), "S-OSS-LOCAL", "scale_200", Q, horizon_months=12)
    # 10 busy hours a month on a host that offers 365 hours at a 0.5 share: one host
    assert led.hosts_needed == 1
    assert row(led, "hardware").amount == pytest.approx(12000 * 0.5 / 24)          # 250
    assert row(led, "electricity").quantity == pytest.approx(10 * 100 / 1000)      # 1 kWh
    assert row(led, "electricity").amount == pytest.approx(0.2)
    assert row(led, "local_storage").amount == pytest.approx(5.0)
    t = led.totals
    assert t.technology == pytest.approx(255.2) and t.technology_complete
    # 6 maintenance hours a month, setup 10 h over 12 months; development is a build-view cost
    assert t.operating_hours == pytest.approx(6 + 10 / 12)
    assert t.operating_money == pytest.approx((6 + 10 / 12) * 200)
    assert t.review_hours == pytest.approx(50) and t.review_money == pytest.approx(5000)
    assert t.differential == pytest.approx(255.2 + (6 + 10 / 12) * 200)
    assert t.total == pytest.approx(t.differential + 5000)
    assert t.missing == [] and not t.proxy
    assert all(r.status == "free" for r in led.rows if r.category == "software_licence"
               or r.line == "public_sources")


def test_the_build_view_adds_the_development_hours_and_adopt_does_not():
    adopt = evaluate(make_inputs(), "S-OSS-LOCAL", "scale_200", Q, view="adopt", horizon_months=12)
    build = evaluate(make_inputs(), "S-OSS-LOCAL", "scale_200", Q, view="build",
                     horizon_months=12)
    assert all(r.line != "development" for r in adopt.rows)
    assert row(build, "development").hours == pytest.approx(120 / 12)
    assert build.totals.operating_hours == pytest.approx(adopt.totals.operating_hours + 10)
    longer = evaluate(make_inputs(), "S-OSS-LOCAL", "scale_200", Q, view="build",
                      horizon_months=24)
    assert longer.totals.operating_hours < build.totals.operating_hours   # amortised over more


def test_the_platform_perimeter_is_off_unless_asked_for():
    wf = evaluate(make_inputs(), "S-PAID", "scale_200", Q)
    pf = evaluate(make_inputs(), "S-PAID", "scale_200", Q, perimeter="platform")
    assert all(r.perimeter == "workflow" for r in wf.rows)
    siem = row(pf, "siem")
    assert siem.amount == pytest.approx(100 * 0.3) and siem.perimeter == "platform"
    assert pf.totals.technology == pytest.approx(wf.totals.technology + 30)


# ---- the paid scenario, by hand -----------------------------------------------------------------------
def test_the_paid_scenario_picks_the_lowest_calculated_candidate_and_names_it():
    inputs = make_inputs()
    base = evaluate(inputs, "S-PAID", "scale_200", Q, case="base", horizon_months=12)
    upper = evaluate(inputs, "S-PAID", "scale_200", Q, case="upper", horizon_months=12)
    # 0.4 Mtok in and 0.1 Mtok out a month: candidate A costs 0.8, candidate B 2.4
    assert row(base, "llm_api").amount == pytest.approx(0.4 * 1.0 + 0.1 * 4.0)
    assert row(base, "llm_api").entry == "llm.a"
    assert row(upper, "llm_api").amount == pytest.approx(0.4 * 3.0 + 0.1 * 12.0)
    assert row(upper, "llm_api").entry == "llm.b"
    assert row(base, "cloud_compute").amount == pytest.approx(0.01 * 200 * 0.5)    # 1.0
    assert row(base, "cloud_storage").amount == pytest.approx(50 * 0.05)           # 2.5
    t = base.totals
    assert t.technology == pytest.approx(0.8 + 1.0 + 2.5)
    # maintenance 6 h, setup 10/12 h, integration 20/12 h
    assert t.operating_hours == pytest.approx(6 + 10 / 12 + 20 / 12)
    assert t.differential == pytest.approx(4.3 + (6 + 30 / 12) * 200)
    assert t.proxy                                     # tokens were borrowed from the local model
    assert row(base, "llm_api").quantity_basis == "proxy"


def test_measured_cloud_tokens_replace_the_proxy():
    q = Quantities(**{**Q.__dict__, "cloud_tokens": (3000.0, 600.0)})
    led = evaluate(make_inputs(), "S-PAID", "scale_200", q)
    assert row(led, "llm_api").amount == pytest.approx(0.6 * 1.0 + 0.12 * 4.0)
    assert row(led, "llm_api").quantity_basis == "measured" and not led.totals.proxy


def test_included_usage_and_a_fixed_fee_are_part_of_the_candidate_cost():
    reg = register_doc([
        entry("llm.free", "llm_api", [comp("mtok_in", 1.0, included=0.3),
                                      comp("mtok_out", 4.0, included=1.0)], fixed_monthly_fee=2.0),
        entry("vm.a", "cloud_compute", [comp("hour", 0.5)]),
        entry("disk.a", "cloud_storage", [comp("gb_month", 0.05)]),
        entry("siem.a", "siem_platform", [comp("gb_ingested_month", 0.3)])])
    led = evaluate(make_inputs(register=reg), "S-PAID", "scale_200", Q)
    # 0.4 Mtok in with 0.3 free = 0.1 charged; 0.1 Mtok out is all inside the 1.0 allowance; + 2.0
    assert row(led, "llm_api").amount == pytest.approx(0.1 * 1.0 + 0.0 + 2.0)


def test_a_price_in_another_currency_needs_a_sourced_exchange_rate():
    reg = register_doc([
        entry("llm.usd", "llm_api", [comp("mtok_in", 1.0), comp("mtok_out", 4.0)], currency="USD"),
        entry("vm.a", "cloud_compute", [comp("hour", 0.5)]),
        entry("disk.a", "cloud_storage", [comp("gb_month", 0.05)]),
        entry("siem.a", "siem_platform", [comp("gb_ingested_month", 0.3)])])
    led = evaluate(make_inputs(register=reg), "S-PAID", "scale_200", Q)
    r = row(led, "llm_api")
    assert r.amount is None and r.status == "incomplete"
    assert any("exchange rate USD to TST" in m for m in r.missing)
    rates = rates_doc(fx=[{"from_currency": "USD", "to_currency": "TST", "rate": 110.0,
                           "source": "synthetic", "checked_on": "2026-10-01"}])
    fixed = evaluate(make_inputs(rates=rates, register=reg), "S-PAID", "scale_200", Q)
    assert row(fixed, "llm_api").amount == pytest.approx(0.8 * 110.0)


# ---- nothing is invented ------------------------------------------------------------------------------
def test_an_unpriced_product_is_incomplete_and_prints_the_mandated_wording_never_zero():
    real = load_cost_inputs()                          # the repository's own, number-free config
    q = Q
    led = evaluate(real, "S-PAID", "scale_50", q)
    llm = row(led, "llm_api")
    assert llm.amount is None and llm.status == "incomplete"
    assert any(QUOTE_REQUIRED in m for m in llm.missing)
    t = led.totals
    assert not t.technology_complete and QUOTE_REQUIRED in " ".join(t.missing)
    assert t.differential is None and t.total is None


def test_an_unset_rate_leaves_money_unknown_but_keeps_the_hours():
    rates = rates_doc()
    rates["labour"] = {"analyst_hourly": val(None) | {"basis": None, "source": None},
                       "engineer_hourly": {"value": None}}
    led = evaluate(make_inputs(rates=rates), "S-OSS-LOCAL", "scale_200", Q, horizon_months=12)
    t = led.totals
    assert t.operating_hours == pytest.approx(6 + 10 / 12) and t.review_hours == pytest.approx(50)
    assert t.operating_money is None and t.review_money is None
    assert t.differential is None and t.total is None
    assert t.technology == pytest.approx(255.2) and t.technology_complete   # hours stay usable


def test_a_quantity_that_was_not_measured_is_missing_not_zero():
    q = Quantities(items_per_month=200, review_hours_per_item={"B": None},
                   automated_hours_per_item=None, inference_hours_per_item=None)
    led = evaluate(make_inputs(), "S-OSS-LOCAL", "scale_200", q)
    assert row(led, "electricity").amount is None
    assert any("machine hours" in m for m in row(led, "electricity").missing)
    assert row(led, "analyst_review").hours is None and not led.totals.review_hours_complete
    assert row(led, "local_storage").amount is None            # no storage_gb stated either
    assert not led.totals.technology_complete and led.totals.total is None


def test_the_repositorys_own_config_has_no_number_in_it():
    real = load_cost_inputs()
    r = real.rates
    for sec in (r.labour, r.host, r.maintenance, r.build):
        assert all(v.value is None for v in sec.__dict__.values()), sec
    assert r.reporting_currency is None and r.fx == []
    assert all(e.status == "quote_required" and not e.components and not e.fixed_monthly_fee
               and QUOTE_REQUIRED in (e.notes or "") for e in real.register.entries)
    assert real.economics.delta_c_pct is None and real.economics.primary_workload is None


def test_readiness_names_who_has_to_supply_each_missing_input():
    gaps = readiness(load_cost_inputs())
    by = {g.what: g.supplied_by for g in gaps}
    assert by["host.power_active_watts"] == "researcher"
    assert by["labour.analyst_hourly"] == "coordinator"
    assert by["economics.delta_c_pct"] == "coordinator"
    assert any(g.what.startswith("price register group") for g in gaps)
    ready = readiness(make_inputs(rates=rates_doc()))
    assert not any(g.what.startswith(("host.", "labour.", "maintenance.", "build.", "price"))
                   for g in ready)                       # the synthetic inputs are complete


# ---- capacity, the manual comparison, and where the money comes from ---------------------------------------
def test_a_workload_the_host_cannot_carry_needs_more_hosts():
    big = Quantities(**{**Q.__dict__, "items_per_month": 10_000})
    led = evaluate(make_inputs(), "S-OSS-LOCAL", "scale_1000", big)
    # 500 busy hours a month against 730 * 0.5 = 365: two hosts, so the hardware doubles
    assert led.hosts_needed == 2
    assert row(led, "hardware").amount == pytest.approx(2 * 250)


def test_the_manual_scenario_counts_the_analysts_manual_hours_and_nothing_automated():
    led = evaluate(make_inputs(), "S-MANUAL", "scale_200", Q)
    assert row(led, "analyst_work").hours == pytest.approx(1.0 * 200)       # condition A minutes
    assert led.totals.review_money == pytest.approx(200 * 100)
    assert led.totals.technology == 0 and led.totals.operating_hours == 0


def test_evidence_shares_show_how_much_of_a_total_is_measured():
    led = evaluate(make_inputs(), "S-OSS-LOCAL", "scale_200", Q, horizon_months=12)
    shares = evidence_shares(led)
    assert sum(shares.values()) == pytest.approx(1.0, abs=1e-3)
    assert "assumed" in shares                          # the synthetic rates are all 'assumed'
