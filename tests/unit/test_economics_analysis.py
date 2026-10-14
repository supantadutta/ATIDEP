"""H7, unit costs, break-even and the bootstrap, against hand-computed numbers (synthetic inputs)."""

import pytest

from research.economics.analysis import (
    bootstrap_bca,
    break_even_volume,
    decide,
    fixed_and_variable,
    grid,
    h7,
    joint_verdict,
    robustness,
    technical_adequacy,
    unit_costs,
)
from research.economics.inputs import load_cost_inputs
from research.economics.measured import ItemMeasure, Measured
from schemas.cost_model import QUOTE_REQUIRED
from tests.unit.economics_fixtures import make_inputs, rates_doc, register_doc


def item(i, category="behaviour", **kw):
    base = dict(item=f"I{i}", item_key=f"k{i}", category=category, runs=3, tokens_in=2000.0,
                tokens_out=500.0, automated_h=0.01, inference_h=0.04, generated=2.0, assessed=2.0,
                valid=1.0, analyst_h={"A": 1.0, "B": 0.25}, accepted={"A": True, "B": True},
                approved_rules=1, deployed_rules=0)
    base.update(kw)
    return ItemMeasure(**base)


def measured(n=8):
    return Measured([item(i, "ioc" if i % 2 else "behaviour") for i in range(n)], {})


# ---- the four bound cases of the H7 rule ----------------------------------------------------------------
def test_h7_numbers_by_hand_and_the_threshold_between_supported_and_not():
    inputs, meas = make_inputs(), measured()
    # O = 255.2 + (6 + 10/12) * 200 = 1621.867 ; P = 4.3 + (6 + 30/12) * 200 = 1704.3
    r = h7(inputs, meas, "scale_200", horizon_months=12, delta_c_pct=4.0)
    assert r.open_source.value == pytest.approx(1621.8667, abs=1e-3)
    assert r.paid.value == pytest.approx(1704.3)
    assert r.saving_pct == pytest.approx(100 * (1704.3 - 1621.8667) / 1704.3, abs=1e-3)
    assert r.verdict == "supported"
    assert r.screening                               # the paid-side tokens are borrowed (proxy)
    assert "SCREENING" in r.reason
    assert h7(inputs, meas, "scale_200", horizon_months=12, delta_c_pct=5.0).verdict == \
        "not_supported"                              # 0.95 * 1704.3 = 1619.1 < 1621.87


def test_the_verdict_needs_the_coordinators_threshold():
    r = h7(make_inputs(), measured(), "scale_200")
    assert r.verdict == "not_evaluable" and "delta_c" in r.reason and r.saving_pct is not None


def test_a_complete_open_source_total_against_an_unpriced_paid_total_can_only_support():
    inputs = make_inputs(register=register_doc([]))               # nothing priced for S-PAID
    r = h7(inputs, measured(), "scale_200", horizon_months=12, delta_c_pct=4.0)
    assert r.paid.complete is False and r.open_source.complete
    # P is at least its operating labour (1700) even with nothing priced: 0.96 * 1700 = 1632 > O
    assert r.verdict == "supported" and "lower bound" in r.reason
    assert any(QUOTE_REQUIRED in m for m in r.paid.missing)
    weak = h7(inputs, measured(), "scale_200", horizon_months=12, delta_c_pct=10.0)
    assert weak.verdict == "inconclusive"                          # may be true; cannot be shown


def test_an_incomplete_open_source_total_can_only_refute():
    rates = rates_doc()
    rates["host"]["electricity_per_kwh"] = {"value": None}        # O is now a lower bound
    inputs = make_inputs(rates=rates)
    refuted = h7(inputs, measured(), "scale_200", horizon_months=12, delta_c_pct=10.0)
    assert refuted.open_source.complete is False
    assert refuted.verdict == "not_supported"                      # fails even on the lower bound
    assert h7(inputs, measured(), "scale_200", horizon_months=12,
              delta_c_pct=4.0).verdict == "inconclusive"


def test_two_lower_bounds_conclude_nothing_and_the_repositorys_own_config_is_not_evaluable():
    o = h7(load_cost_inputs(), measured(), "scale_50", delta_c_pct=20.0)
    assert o.verdict == "inconclusive" and not o.open_source.complete and not o.paid.complete
    assert decide(*_sides(False, False), 10.0)[0] == "inconclusive"


def _sides(oc, pc):
    from research.economics.analysis import Side
    mk = lambda c: Side("s", 100.0, c, [], 100.0, c, 0.0, True, 0.0, False)  # noqa: E731
    return mk(oc), mk(pc)


# ---- the labour rate at which the verdict flips ----------------------------------------------------------------
def test_the_flip_rate_is_where_the_verdict_changes():
    inputs, meas = make_inputs(), measured()
    r = h7(inputs, meas, "scale_200", horizon_months=12, delta_c_pct=4.0)
    # a + b*rate >= 0 with a = 0.96*4.3 - 255.2, b = 0.96*8.5 - 6.8333 -> supported from ~189.25
    assert r.flip["rate"] == pytest.approx(189.25, abs=0.05)
    assert r.flip["supported_for"].startswith("rates from 189")
    cheap = make_inputs(rates=rates_doc(labour={"analyst_hourly": {"value": 100, "basis": "assumed",
                                                                   "source": "x"},
                                                "engineer_hourly": {"value": 150,
                                                                    "basis": "assumed",
                                                                    "source": "x"}}))
    assert h7(cheap, meas, "scale_200", horizon_months=12,
              delta_c_pct=4.0).verdict == "not_supported"          # below the flip rate


def test_technology_only_basis_needs_no_labour_rate():
    rates = rates_doc()
    rates["labour"] = {"analyst_hourly": {"value": None}, "engineer_hourly": {"value": None}}
    r = h7(make_inputs(rates=rates), measured(), "scale_200", basis="technology",
           horizon_months=12, delta_c_pct=50.0)
    # O technology 255.2 against P 4.3: O is far more expensive in technology (owned hardware)
    assert r.open_source.value == pytest.approx(255.2) and r.paid.value == pytest.approx(4.3)
    assert r.verdict == "not_supported" and r.open_source.operating_hours > 0
    assert r.flip["supported_for"] in ("no rate",) or "rates" in r.flip["supported_for"]


# ---- the grid and robustness -----------------------------------------------------------------------------------------
def test_the_grid_covers_every_cell_and_a_claim_is_robust_only_if_it_holds_in_all_of_them():
    inputs, meas = make_inputs(), measured()
    undecided = grid(inputs, meas)
    assert len(undecided) == 3 * 2 * 2
    assert {c.verdict for c in undecided} == {"not_evaluable"}       # no threshold set
    assert robustness(undecided)[0] == "not evaluable"
    cells = grid(inputs, meas, delta_c_pct=4.0)
    label, failing = robustness(cells)
    # the build view adds the same development hours to both sides, which shrinks the gap, so the
    # claim holds in the adopt view and fails in the build view: conditional, with cells named
    assert label == "conditional" and len(failing) == 6
    assert all("/build/" in f for f in failing)
    assert all(c.verdict == "supported" for c in cells if c.view == "adopt")
    assert robustness(grid(inputs, meas, delta_c_pct=0.5)) == ("robust", [])


# ---- unit costs, by hand ---------------------------------------------------------------------------------------------------
def test_unit_costs_follow_from_the_monthly_total_and_the_measured_rates():
    inputs, meas = make_inputs(), measured()
    u = unit_costs(inputs, meas, "S-OSS-LOCAL", "scale_200", horizon_months=12)
    total = 255.2 + (6 + 10 / 12) * 200 + 50 * 100                   # 6621.867
    assert u["complete"] and u["monthly"]["total"] == pytest.approx(total, abs=1e-3)
    assert u["annual"]["total"] == pytest.approx(12 * total, abs=1e-2)
    assert u["per_report"] == pytest.approx(total / 200, abs=1e-4)
    assert u["per_generated_detection"] == pytest.approx(total / (200 * 2.0), abs=1e-4)
    assert u["per_valid_detection"] == pytest.approx(total / (200 * 1.0), abs=1e-4)
    assert u["per_accepted_item"] == pytest.approx(total / 200, abs=1e-4)      # all accepted
    assert u["per_approved_rule"] == pytest.approx(total / 200, abs=1e-4)
    assert u["analyst_minutes_per_report"] == pytest.approx(15.0)              # 0.25 h
    assert u["analyst_minutes_per_generated_detection"] == pytest.approx(7.5)
    # local inference: the share of hardware + energy used while waiting on the model (0.04 / 0.05)
    assert u["llm_inference_cost_per_report"] == pytest.approx((250 + 0.2) * 0.8 / 200, abs=1e-4)


def test_a_unit_whose_denominator_does_not_exist_is_none_not_zero():
    meas = Measured([item(i, deployed_rules=None, approved_rules=None) for i in range(4)], {})
    u = unit_costs(make_inputs(), meas, "S-OSS-LOCAL", "scale_200")
    assert u["per_deployed_rule"] is None and u["per_approved_rule"] is None
    none_valid = Measured([item(i, valid=0.0) for i in range(4)], {})
    u2 = unit_costs(make_inputs(), none_valid, "S-OSS-LOCAL", "scale_200")
    assert u2["per_valid_detection"] is None                   # zero valid detections: undefined


def test_unreliable_tokens_make_the_paid_llm_cost_missing_rather_than_zero():
    meas = Measured([item(i, tokens_in=None, tokens_out=None) for i in range(4)], {})
    u = unit_costs(make_inputs(), meas, "S-PAID", "scale_200")
    assert u["monthly"]["technology"] is None and not u["complete"]
    assert any("tokens" in m for m in u["missing"])


# ---- break-even against the manual workflow ----------------------------------------------------------------------------
def test_break_even_volume_against_the_manual_workflow_by_hand():
    inputs, meas = make_inputs(), measured()
    fv = fixed_and_variable(inputs, meas, "S-OSS-LOCAL", horizon_months=12)
    assert fv is not None
    fixed, var = fv
    assert var == pytest.approx(25.001, abs=1e-4)                  # 0.25 h * 100 + 0.001 kWh * 0.2
    assert fixed == pytest.approx(250 + 5 + (6 + 10 / 12) * 200, abs=1e-3)
    be = break_even_volume(inputs, meas, horizon_months=12)
    assert be["n_star"] == pytest.approx(1621.667 / (100 - 25.001), abs=1e-2)       # about 21.6


def test_no_break_even_when_atidep_does_not_save_time_per_item():
    meas = Measured([item(i, analyst_h={"A": 0.1, "B": 0.25}) for i in range(4)], {})
    be = break_even_volume(make_inputs(), meas, horizon_months=12)
    assert be["n_star"] is None and "no break-even" in be["reason"]


def test_break_even_is_none_when_the_analyst_rate_is_not_supplied():
    be = break_even_volume(load_cost_inputs(), measured())
    assert be["n_star"] is None


# ---- bootstrap -------------------------------------------------------------------------------------------------------------------
def test_the_bootstrap_is_deterministic_stratified_and_marked_as_descriptive():
    meas = Measured([item(i, "ioc" if i < 6 else "behaviour", generated=float(i % 3))
                     for i in range(12)], {})

    def stat(m):
        return m.rate("generated")

    a = bootstrap_bca(meas, stat, n_resamples=500, seed=7)
    b = bootstrap_bca(meas, stat, n_resamples=500, seed=7)
    assert a == b and a["valid"] and a["lo"] <= a["estimate"] <= a["hi"]
    assert "not a test" in a["note"] and a["undefined_resamples"] == 0
    assert bootstrap_bca(meas, lambda m: None, n_resamples=50, seed=1)["valid"] is False


# ---- the joint statement -----------------------------------------------------------------------------------------------------------------
def test_technical_adequacy_is_the_conjunction_of_the_preregistered_criteria():
    assert technical_adequacy(True, True, True) == "met"
    assert technical_adequacy(True, False, True) == "not_met"
    assert technical_adequacy(True, None, True) == "unknown"
    assert technical_adequacy(False, None, None) == "not_met"


def test_the_joint_statement_never_claims_parity_with_a_paid_system():
    inputs, meas = make_inputs(), measured()
    sup = h7(inputs, meas, "scale_200", horizon_months=12, delta_c_pct=4.0)
    not_sup = h7(inputs, meas, "scale_200", horizon_months=12, delta_c_pct=5.0)
    cases = [("met", sup, "adequate and substantially cheaper"),
             ("not_met", sup, "cheaper but technically inferior"),
             ("met", not_sup, "adequate, not substantially cheaper"),
             ("not_met", not_sup, "not adequate and not substantially cheaper"),
             ("unknown", sup, "not evaluable")]
    for adequacy, h, outcome in cases:
        j = joint_verdict(adequacy, h)
        assert j["outcome"] == outcome
        assert "does not establish parity" in j["limit"] and "modelled" in j["limit"]
    incomplete = h7(load_cost_inputs(), meas, "scale_50", delta_c_pct=10.0)
    assert joint_verdict("met", incomplete)["outcome"] == "not evaluable"
