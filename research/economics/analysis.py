"""Unit costs, the H7 decision, tipping points, break-even and the descriptive bootstrap
(blueprint §22). Nothing here estimates a price: it only combines what the ledger could cost.

**H7 (cost advantage)** is a pre-registered *decision rule*, not a significance test, because the
paid side is a modelled counterfactual. At the primary cell, S-OSS-LOCAL is *substantially
cheaper* than S-PAID when ``O <= (1 - delta_c) * P`` on the differential cost: technology plus
the operating labour that differs between the scenarios. The analyst's review time is common to
the automated scenarios and is left out of the comparison (it cancels), and is reported apart.

Totals can be incomplete (a rate is unset, a product is unpriced, a quantity is unmeasured). An
incomplete total is only a lower bound, so the verdict is a function of which side is bounded:

====================  =====================  =========================================
S-OSS-LOCAL           S-PAID                 what can be concluded
====================  =====================  =========================================
complete              complete               supported or not supported
complete              lower bound            supported, or inconclusive
lower bound           complete               not supported, or inconclusive
lower bound           lower bound            inconclusive
====================  =====================  =========================================

The paid side is not measured, so nothing here says a paid system performs as well as ATIDEP.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any, Literal

import numpy as np
from scipy.stats import norm

from research.economics.inputs import CostInputs
from research.economics.ledger import Case, Ledger, Totals, evaluate
from research.economics.measured import Measured
from schemas.cost_model import QUOTE_REQUIRED

Verdict = Literal["supported", "not_supported", "inconclusive", "not_evaluable"]


# ---- one side of the comparison --------------------------------------------------------------
@dataclass
class Side:
    scenario: str
    value: float                  # the known part: a lower bound unless ``complete``
    complete: bool
    missing: list[str]
    technology: float
    technology_complete: bool
    operating_hours: float
    operating_hours_complete: bool
    review_hours: float
    proxy: bool


def side(ledger: Ledger, *, basis: str) -> Side:
    """``differential`` includes operating labour in money (needs the engineer rate);
    ``technology`` leaves operating labour out and reports its hours instead."""
    t: Totals = ledger.totals
    value, complete = t.technology, t.technology_complete
    missing = list(t.missing)
    if basis == "differential":
        if t.operating_money is not None:
            value += t.operating_money          # known hours x rate: a lower bound if hours lack
        elif "reporting_currency" not in missing:
            missing.append("labour.engineer_hourly")
        if t.operating_money is None or not t.operating_hours_complete:
            complete = False
    return Side(ledger.scenario, value, complete, sorted(set(missing)), t.technology,
                t.technology_complete, t.operating_hours, t.operating_hours_complete,
                t.review_hours, t.proxy)


# ---- H7 --------------------------------------------------------------------------------------
@dataclass
class H7Result:
    basis: str
    workload: str
    view: str
    case: str
    horizon_months: int | None
    delta_c_pct: float | None
    verdict: Verdict
    reason: str
    open_source: Side
    paid: Side
    saving_pct: float | None = None               # (P - O) / P when both are complete
    paid_needed: float | None = None              # paid total at which O is delta_c below
    flip: dict[str, Any] = field(default_factory=dict)
    screening: bool = False                       # a quantity was borrowed from another arm


def decide(o: Side, p: Side, delta_c_pct: float | None) -> tuple[Verdict, str]:
    if delta_c_pct is None:
        return "not_evaluable", "delta_c is not set (the coordinator's decision)"
    factor = 1.0 - delta_c_pct / 100.0
    if o.complete and p.complete:
        ok = o.value <= factor * p.value + 1e-9
        return ("supported" if ok else "not_supported",
                f"O={o.value:.2f} against {factor:.2f} x P={factor * p.value:.2f}")
    if o.complete and not p.complete:
        if o.value <= factor * p.value + 1e-9:
            return "supported", ("holds even on the paid lower bound "
                                 f"(P is at least {p.value:.2f}; unpriced: {len(p.missing)})")
        return "inconclusive", "the paid total is only a lower bound and may be higher"
    if not o.complete and p.complete:
        if o.value > factor * p.value + 1e-9:
            return "not_supported", ("fails even on the open-source lower bound "
                                     f"(O is at least {o.value:.2f})")
        return "inconclusive", "the open-source total is only a lower bound and may be higher"
    return "inconclusive", "both totals are lower bounds"


def flip_rate(o: Side, p: Side, delta_c_pct: float | None) -> dict[str, Any]:
    """The engineer hourly rate at which the verdict changes, when technology costs and operating
    hours are known on both sides: supported iff a + b*r >= 0."""
    if delta_c_pct is None or not (o.technology_complete and p.technology_complete
                                   and o.operating_hours_complete and p.operating_hours_complete):
        return {}
    f = 1.0 - delta_c_pct / 100.0
    a = f * p.technology - o.technology
    b = f * p.operating_hours - o.operating_hours
    if b == 0:
        return {"supported_for": "every rate" if a >= 0 else "no rate", "a": a, "b": b}
    root = -a / b
    if b < 0:
        text = f"rates up to {root:.2f}" if a >= 0 else "no rate"
    else:
        text = "every rate" if a >= 0 else f"rates from {root:.2f}"
    return {"supported_for": text, "rate": root if root >= 0 else None, "a": a, "b": b,
            "operating_hours_open_source": o.operating_hours,
            "operating_hours_paid": p.operating_hours}


def h7(inputs: CostInputs, measured: Measured, workload_id: str, *, basis: str = "differential",
       view: str | None = None, case: Case | None = None, horizon_months: int | None = None,
       delta_c_pct: float | None = None) -> H7Result:
    eco, sc = inputs.economics, inputs.scenarios
    w = sc.workload(workload_id)
    q = measured.quantities(w.items_per_month.value or 0.0, storage_gb=w.storage_gb.value,
                            siem_ingest_gb=w.siem_ingest_gb_per_month.value,
                            endpoints=w.monitored_endpoints.value)
    view = view or eco.primary_view
    case = case or eco.primary_price_case
    delta = delta_c_pct if delta_c_pct is not None else eco.delta_c_pct
    horizon = horizon_months or eco.primary_horizon_months
    if horizon is None:
        gap = ["economics.primary_horizon_months"]
        blank = [Side(s, 0.0, False, gap, 0.0, False, 0.0, False, 0.0, False)
                 for s in (sc.oss_local, sc.paid)]
        return H7Result(basis, workload_id, view, case, None, delta, "not_evaluable",
                        "the amortisation horizon is not set (economics.primary_horizon_months, "
                        "the coordinator's decision)", blank[0], blank[1])
    lo = evaluate(inputs, sc.oss_local, workload_id, q, view=view, case=case,
                  horizon_months=horizon)
    lp = evaluate(inputs, sc.paid, workload_id, q, view=view, case=case,
                  horizon_months=horizon)
    o, p = side(lo, basis=basis), side(lp, basis=basis)
    verdict, reason = decide(o, p, delta)
    screening = o.proxy or p.proxy
    if screening and verdict == "supported":
        reason += "; SCREENING ONLY (a quantity was borrowed from another arm)"
    res = H7Result(basis, workload_id, view, case, lo.horizon_months, delta, verdict, reason, o,
                   p, screening=screening)
    if o.complete and p.complete and p.value > 0:
        res.saving_pct = 100.0 * (p.value - o.value) / p.value
    if delta is not None and delta < 100 and o.complete:
        res.paid_needed = o.value / (1.0 - delta / 100.0)
    res.flip = flip_rate(o, p, delta)
    return res


def grid(inputs: CostInputs, measured: Measured, *, basis: str = "differential",
         delta_c_pct: float | None = None) -> list[H7Result]:
    """H7 at every workload, view, price case and amortisation horizon: the sensitivity map
    around the primary cell. The claim is *robust* only if it holds in every cell where it can be
    evaluated."""
    eco = inputs.economics
    out = []
    for w in inputs.scenarios.workloads:
        for view in eco.views:
            for case in eco.price_cases:
                for horizon in inputs.rates.amortisation_horizon_months:
                    out.append(h7(inputs, measured, w.id, basis=basis, view=view, case=case,
                                  horizon_months=horizon, delta_c_pct=delta_c_pct))
    return out


def robustness(cells: list[H7Result]) -> tuple[str, list[str]]:
    evaluable = [c for c in cells if c.verdict in ("supported", "not_supported")]
    if not evaluable:
        return "not evaluable", ["no cell has complete or bounding inputs"]
    failing = [f"{c.workload}/{c.view}/{c.case}/{c.horizon_months}m" for c in cells
               if c.verdict != "supported"]
    if not failing:
        return "robust", []
    return "conditional", failing


# ---- unit costs ------------------------------------------------------------------------------
def _div(a: float | None, b: float | None) -> float | None:
    return None if a is None or not b else a / b


def unit_costs(inputs: CostInputs, measured: Measured, scenario_id: str, workload_id: str, *,
               view: str | None = None, case: Case | None = None,
               horizon_months: int | None = None) -> dict[str, Any]:
    """Normalised unit costs at a named workload. Each is None when a numerator or denominator is
    missing; a denominator of zero is None, never a division by zero or a zero cost."""
    eco = inputs.economics
    view = view or eco.primary_view
    case = case or eco.primary_price_case
    w = inputs.scenarios.workload(workload_id)
    n = w.items_per_month.value or 0.0
    q = measured.quantities(n, storage_gb=w.storage_gb.value,
                            siem_ingest_gb=w.siem_ingest_gb_per_month.value,
                            endpoints=w.monitored_endpoints.value)
    led = evaluate(inputs, scenario_id, workload_id, q, view=view, case=case,
                   horizon_months=horizon_months)
    t = led.totals
    sc = inputs.scenarios.scenario(scenario_id)
    cond = sc.review_condition
    # each scenario is divided by its own arm's detections: the manual workflow by the manual
    # condition's rules, never by ATIDEP's
    gen, valid = measured.rate("generated", cond), measured.rate("valid", cond)
    accepted = measured.accepted_rate(cond)
    approved, deployed = measured.approved_rate(cond), measured.deployed_rate(cond)
    total = t.total
    differential = t.differential
    review_min = t.review_hours * 60.0 if t.review_hours_complete else None

    def per(amount: float | None, rate: float | None) -> float | None:
        return _div(amount, None if rate is None else n * rate)

    inference = _inference_cost(led, measured, sc.backend)
    out: dict[str, Any] = {
        "scenario": scenario_id, "workload": workload_id, "view": view, "price_case": case,
        "horizon_months": led.horizon_months, "detections_from_condition": cond,
        "items_per_month": n, "complete": total is not None, "missing": t.missing,
        "proxy": t.proxy,
        "monthly": {"technology": t.technology if t.technology_complete else None,
                    "operating_hours": t.operating_hours if t.operating_hours_complete else None,
                    "review_hours": t.review_hours if t.review_hours_complete else None,
                    "differential": differential, "total": total},
        "annual": {"differential": None if differential is None else 12 * differential,
                   "total": None if total is None else 12 * total},
        "per_report": _div(total, n or None),
        "per_generated_detection": per(total, gen),
        "per_valid_detection": per(total, valid),
        "per_accepted_item": per(total, accepted),
        "per_approved_rule": per(total, approved),
        "per_deployed_rule": per(total, deployed),
        "analyst_minutes_per_report": _div(review_min, n or None),
        "analyst_minutes_per_accepted_item": per(review_min, accepted),
        "analyst_minutes_per_generated_detection": per(review_min, gen),
        "llm_inference_cost_per_report": _div(inference, n or None),
        "llm_inference_cost_per_generated_detection": per(inference, gen),
        "rates_per_item": {"generated": gen, "valid": valid, "accepted": accepted,
                           "approved": approved, "deployed": deployed},
        "hosts_needed": led.hosts_needed,
    }
    if led.hosts_needed and led.hosts_needed > 1:
        out["capacity_note"] = (f"{led.hosts_needed} hosts are needed at this workload "
                                "(the hardware line already counts them)")
    return out


def _inference_cost(led: Ledger, measured: Measured, backend: str) -> float | None:
    """Model-inference cost per month: metered spend for a hosted model; for a local one, the
    share of hardware and energy used while waiting on the model. A view, not an extra ledger
    line, so nothing is counted twice."""
    if backend == "cloud":
        rows = [r for r in led.rows if r.category == "model_inference"]
        return sum(r.amount for r in rows) if rows and all(r.amount is not None for r in rows) \
            else None
    rows = [r for r in led.rows if r.category in ("hardware", "energy")]
    if not rows or any(r.amount is None for r in rows):
        return None
    auto = _mean_attr(measured, "automated_h")
    inf = _mean_attr(measured, "inference_h")
    if auto is None or inf is None or auto + inf == 0:
        return None
    return sum(r.amount for r in rows) * inf / (auto + inf)  # type: ignore[misc]


def _mean_attr(measured: Measured, attr: str) -> float | None:
    xs = [getattr(i, attr) for i in measured.items]
    return None if not xs or any(x is None for x in xs) else float(np.mean(xs))


# ---- fixed and variable cost, and break-even against the manual workflow ---------------------
def fixed_and_variable(inputs: CostInputs, measured: Measured, scenario_id: str, *,
                       view: str | None = None, case: Case | None = None,
                       horizon_months: int | None = None) -> tuple[float, float] | None:
    """(fixed per month, variable per item) of the total cost, read from the ledger at one and
    two items a month, so every line is classified by how it actually behaves. The host step
    function cancels. None if the total is not computable."""
    eco = inputs.economics
    view, case = view or eco.primary_view, case or eco.primary_price_case
    wid = inputs.scenarios.workloads[0].id
    totals = []
    for n in (1.0, 2.0):
        w = inputs.scenarios.workload(wid)
        q = measured.quantities(n, storage_gb=w.storage_gb.value,
                                siem_ingest_gb=w.siem_ingest_gb_per_month.value,
                                endpoints=w.monitored_endpoints.value)
        tot = evaluate(inputs, scenario_id, wid, q, view=view, case=case,
                       horizon_months=horizon_months).totals.total
        if tot is None:
            return None
        totals.append(tot)
    variable = totals[1] - totals[0]
    return totals[0] - variable, variable


def break_even_volume(inputs: CostInputs, measured: Measured, *, view: str | None = None,
                      case: Case | None = None, horizon_months: int | None = None
                      ) -> dict[str, Any]:
    """The monthly volume N* above which S-OSS-LOCAL costs less in total (review labour
    included) than the manual workflow: N* = F_a / (v_m - v_a), only if each item is cheaper to do
    with ATIDEP. Needs the analyst rate, because here labour is what differs."""
    sc = inputs.scenarios
    a = fixed_and_variable(inputs, measured, sc.oss_local, view=view, case=case,
                           horizon_months=horizon_months)
    m = fixed_and_variable(inputs, measured, sc.manual, view=view, case=case,
                           horizon_months=horizon_months)
    if a is None or m is None:
        return {"n_star": None, "reason": "a total is not computable (see the ledger's missing "
                                          "inputs)"}
    (fa, va), (fm, vm) = a, m
    if vm <= va:
        return {"n_star": None, "reason": "each item costs no less with ATIDEP than by hand, so "
                                          "there is no break-even", "fixed_atidep": fa,
                "variable_atidep": va, "variable_manual": vm}
    n_star = (fa - fm) / (vm - va)
    return {"n_star": max(0.0, n_star), "fixed_atidep": fa, "fixed_manual": fm,
            "variable_atidep": va, "variable_manual": vm,
            "reason": "ATIDEP is cheaper in total above this volume"}


# ---- descriptive bootstrap -------------------------------------------------------------------
def bootstrap_bca(measured: Measured, stat, *, n_resamples: int, seed: int,
                  alpha: float = 0.05) -> dict[str, Any]:
    """BCa interval for ``stat(measured) -> float | None`` over items, resampled within category
    strata (the same resample for every arm that ``stat`` computes). It describes the sampling
    noise of the measured per-item quantities *conditional on the price case*; it does not make
    the verdict a significance test, and says nothing about price or workload uncertainty."""
    theta = stat(measured)
    if theta is None:
        return {"valid": False, "reason": "the statistic is not computable on the data"}
    items = measured.items
    strata: dict[str | None, list[int]] = {}
    for i, it in enumerate(items):
        strata.setdefault(it.category, []).append(i)
    rng = np.random.default_rng(seed)
    boots, undefined = [], 0
    for _ in range(n_resamples):
        idx = [j for members in strata.values()
               for j in rng.choice(members, size=len(members), replace=True)]
        v = stat(measured.resample([int(j) for j in idx]))
        if v is None or not math.isfinite(v):
            undefined += 1
        else:
            boots.append(v)
    if len(boots) < max(50, n_resamples // 2):
        return {"valid": False, "reason": "too many resamples were undefined",
                "undefined_resamples": undefined}
    boots_a = np.array(boots)
    prop = float(np.mean(boots_a < theta))
    z0 = norm.ppf(min(max(prop, 1e-6), 1 - 1e-6))
    jack = []
    for k in range(len(items)):
        v = stat(measured.resample([j for j in range(len(items)) if j != k]))
        if v is not None and math.isfinite(v):
            jack.append(v)
    if len(jack) >= 3:
        jm = np.mean(jack)
        num = np.sum((jm - np.array(jack)) ** 3)
        den = 6.0 * (np.sum((jm - np.array(jack)) ** 2) ** 1.5)
        acc = float(num / den) if den else 0.0
    else:
        acc = 0.0

    def adj(a: float) -> float:
        za = norm.ppf(a)
        return float(norm.cdf(z0 + (z0 + za) / (1 - acc * (z0 + za))))

    lo, hi = np.quantile(boots_a, [adj(alpha / 2), adj(1 - alpha / 2)])
    up = np.quantile(boots_a, adj(1 - alpha))
    return {"valid": True, "estimate": float(theta), "lo": float(lo), "hi": float(hi),
            "upper_one_sided": float(up), "resamples": len(boots), "undefined_resamples": undefined,
            "bias_z0": float(z0), "acceleration": acc,
            "note": "describes sampling noise of measured per-item quantities, conditional on the "
                    "price case; not a test"}


# ---- the joint statement ---------------------------------------------------------------------
def technical_adequacy(h2: bool | None, h3: bool | None, h4: bool | None) -> str:
    """Met only if all three pre-registered criteria are met: H2 (structural validity), H3 (no
    defective rule reaches approval) and H4 (quality not worse than manual by more than the
    margin). Unknown if any is not yet measured and none has failed."""
    flags = (h2, h3, h4)
    if any(f is False for f in flags):
        return "not_met"
    return "met" if all(f is True for f in flags) else "unknown"


def joint_verdict(adequacy: str, h7: H7Result) -> dict[str, str]:
    """The cost-consequence reading. Wording is capped: the paid side is modelled and its
    technical performance is assumed equal, so no sentence claims parity with a paid system."""
    cap = ("The paid side is a modelled counterfactual with assumed equal technical performance; "
           "this does not establish parity with any paid system.")
    unpriced = ", ".join(sorted({m for m in h7.paid.missing if QUOTE_REQUIRED in m}))
    if adequacy == "unknown" or h7.verdict in ("inconclusive", "not_evaluable"):
        outcome = "not evaluable"
        text = ("Not evaluable yet: "
                + ("technical adequacy is not fully measured; " if adequacy == "unknown" else "")
                + (f"the cost rule is {h7.verdict} ({h7.reason})" if h7.verdict in (
                    "inconclusive", "not_evaluable") else "") + ".")
    elif adequacy == "met" and h7.verdict == "supported":
        outcome = "adequate and substantially cheaper"
        text = ("The technical criteria were met and the open-source configuration cost "
                f"substantially less than the modelled paid configuration (base case: {h7.case}, "
                f"workload {h7.workload}).")
    elif adequacy == "not_met" and h7.verdict == "supported":
        outcome = "cheaper but technically inferior"
        text = "The open-source configuration was cheaper, but a technical criterion was not met."
    elif adequacy == "met":
        outcome = "adequate, not substantially cheaper"
        text = ("The technical criteria were met; the cost advantage over the modelled paid "
                "configuration did not reach the pre-registered threshold.")
    else:
        outcome = "not adequate and not substantially cheaper"
        text = ("A technical criterion was not met and the cost advantage did not reach the "
                "threshold.")
    return {"outcome": outcome, "statement": text, "limit": cap, "unpriced": unpriced}
