"""The cost ledger: one scenario at one workload, view and price case (blueprint §22.3).

Every line is either costed from sourced inputs or reported as *missing*, with the exact list of
what is missing. Nothing is ever substituted: an unset rate, an unpriced product, a quantity that
was not measured or a currency without a sourced exchange rate leaves its line incomplete and the
totals that depend on it flagged. Money is in the reporting currency; labour is also kept in
hours, so the comparison does not depend on an hourly rate that nobody has supplied.

Totals are kept apart on purpose:

* **technology**: everything that is not people's time (licences, hardware allocation,
  electricity, storage, metered model use, cloud services);
* **operating hours**: maintenance, setup, development and integration time, which differs
  between scenarios and is the part of labour the comparison is about;
* **review hours**: the analyst's measured review time, which is common to the automated
  scenarios and so cancels in a comparison between them (it still matters for the manual one).
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Literal

from research.economics.inputs import CostInputs, sourced
from schemas.cost_model import (
    HOURS_PER_MONTH,
    OPERATING_CATEGORIES,
    QUOTE_REQUIRED,
    CostCategory,
    Driver,
    Line,
    PriceEntry,
    Recurrence,
    Scenario,
    UnitKind,
    View,
)

Case = Literal["base", "upper"]
Perimeter = Literal["workflow", "platform"]


@dataclass(frozen=True)
class Quantities:
    """What the experiment measured (per item) and what the workload assumes (per month).
    ``None`` means "not measured or not stated", and anything that needs it is incomplete."""

    items_per_month: float
    review_hours_per_item: dict[str, float | None] = field(default_factory=dict)  # by condition
    automated_hours_per_item: float | None = None      # non-model machine time
    inference_hours_per_item: float | None = None      # waiting for a local model (fresh calls)
    local_tokens: tuple[float, float] | None = None    # (input, output) per item, local model
    cloud_tokens: tuple[float, float] | None = None    # the same, measured on a paid model
    storage_gb: float | None = None
    siem_ingest_gb: float | None = None
    endpoints: float | None = None


@dataclass
class Row:
    scenario: str
    line: str
    function: str
    category: str
    perimeter: str
    recurrence: str
    quantity: float | None
    unit: str
    unit_price: float | None
    amount: float | None                 # per month, reporting currency; None if not computable
    hours: float | None = None           # per month, for labour lines
    labour: str | None = None            # "review" | "operating" | None
    quantity_basis: str = "n/a"
    price_basis: str = "n/a"
    entry: str | None = None             # register entry chosen
    status: str = "ok"                   # ok | free | incomplete
    missing: list[str] = field(default_factory=list)
    note: str = ""


@dataclass
class Totals:
    technology: float                    # the money that is known
    technology_complete: bool
    operating_hours: float
    operating_hours_complete: bool
    review_hours: float
    review_hours_complete: bool
    operating_money: float | None        # None when the engineer rate is unset
    review_money: float | None
    missing: list[str]
    proxy: bool                          # a quantity was borrowed from another arm

    @property
    def differential(self) -> float | None:
        """Technology plus operating labour in money: the figure two automated scenarios are
        compared on. ``None`` unless every part is known."""
        if not (self.technology_complete and self.operating_hours_complete):
            return None
        if self.operating_money is None:
            return None
        return self.technology + self.operating_money

    @property
    def total(self) -> float | None:
        d = self.differential
        if d is None or self.review_money is None or not self.review_hours_complete:
            return None
        return d + self.review_money


@dataclass
class Ledger:
    scenario: str
    workload: str
    view: str
    case: str
    perimeter: str
    horizon_months: int
    rows: list[Row]
    totals: Totals
    hosts_needed: int | None = None


def _amortised(line: Line, horizon: int) -> float:
    return 1.0 / horizon if line.recurrence is Recurrence.ONE_OFF else 1.0


def machine_hours(q: Quantities, backend: str) -> float | None:
    """Hours per month the owned host is busy: its own automated work plus, for a local model,
    the time spent waiting on that model. A paid model runs elsewhere."""
    if q.automated_hours_per_item is None:
        return None
    per_item = q.automated_hours_per_item
    if backend == "local":
        if q.inference_hours_per_item is None:
            return None
        per_item += q.inference_hours_per_item
    return per_item * q.items_per_month


# ---- register pricing ---------------------------------------------------------------------------
def _component_quantity(unit: UnitKind, q: Quantities, backend: str
                        ) -> tuple[float | None, str, str | None]:
    """(quantity per month, basis, what is missing)."""
    n = q.items_per_month
    if unit is UnitKind.MONTH:
        return 1.0, "n/a", None
    if unit is UnitKind.ITEM:
        return n, "workload", None
    if unit is UnitKind.HOUR:
        if q.automated_hours_per_item is None:
            return None, "measured", "automated hours per item (not measured)"
        return q.automated_hours_per_item * n, "measured", None
    if unit in (UnitKind.MTOK_IN, UnitKind.MTOK_OUT):
        tokens, basis = (q.cloud_tokens, "measured") if q.cloud_tokens else (q.local_tokens,
                                                                            "proxy")
        if tokens is None:
            return None, "measured", "tokens per item (not measured)"
        per_item = tokens[0] if unit is UnitKind.MTOK_IN else tokens[1]
        return per_item * n / 1e6, basis, None
    if unit is UnitKind.GB_MONTH:
        return (q.storage_gb, "workload", None) if q.storage_gb is not None else (
            None, "workload", "storage_gb (workload)")
    if unit is UnitKind.GB_INGESTED:
        return (q.siem_ingest_gb, "workload", None) if q.siem_ingest_gb is not None else (
            None, "workload", "siem_ingest_gb_per_month (workload)")
    if unit is UnitKind.ENDPOINT_MONTH:
        return (q.endpoints, "workload", None) if q.endpoints is not None else (
            None, "workload", "monitored_endpoints (workload)")
    return None, "n/a", f"no quantity for unit {unit.value}"


def candidate_cost(entry: PriceEntry, q: Quantities, backend: str, inputs: CostInputs
                   ) -> tuple[float | None, list[str], str]:
    """Monthly cost of one priced candidate in the reporting currency, including included usage
    and the fixed fee, or None with what is missing. Third value: the quantity basis."""
    total, missing, bases = entry.fixed_monthly_fee, [], set()
    for c in entry.components:
        qty, basis, miss = _component_quantity(c.unit_kind, q, backend)
        if qty is None:
            missing.append(f"{entry.id}: {miss}")
            continue
        bases.add(basis)
        total += max(0.0, qty - c.included_quantity) * c.price
    if missing:
        return None, missing, "measured"
    assert entry.currency is not None
    converted = inputs.rates.convert(total, entry.currency)
    if converted is None:
        return None, [f"{entry.id}: a sourced exchange rate {entry.currency} to "
                      f"{inputs.rates.reporting_currency}"], "measured"
    basis = "proxy" if "proxy" in bases else ("workload" if "workload" in bases else "measured")
    return converted, [], basis


def _register_row(sc: Scenario, ln: Line, q: Quantities, inputs: CostInputs, case: Case,
                  horizon: int) -> Row:
    group = ln.price.ref
    assert group is not None
    base = Row(sc.id, ln.id, ln.function, ln.category.value, ln.perimeter.value,
               ln.recurrence.value, None, "per product", None, None, price_basis="supplied")
    usable = [e for e in inputs.register.group(group) if e.usable]
    if not usable:
        base.status, base.missing = "incomplete", [f"{group}: {QUOTE_REQUIRED}"]
        return base
    priced: list[tuple[float, PriceEntry, str]] = []
    gaps: list[str] = []
    for e in usable:
        cost, miss, basis = candidate_cost(e, q, sc.backend, inputs)
        if cost is None:
            gaps += miss
        else:
            priced.append((cost, e, basis))
    if not priced:
        base.status, base.missing = "incomplete", gaps
        return base
    priced.sort(key=lambda t: t[0])
    cost, entry, basis = priced[0] if case == "base" else priced[-1]
    base.amount = cost * _amortised(ln, horizon)
    base.entry, base.quantity_basis = entry.id, basis
    base.price_basis = entry.price_basis.value if entry.price_basis else "supplied"
    base.note = f"{len(priced)} priced candidate(s); case {case}"
    if gaps:
        base.note += f"; not costable: {'; '.join(gaps)}"
    return base


# ---- rate and free lines -----------------------------------------------------------------------
def _rate_row(sc: Scenario, ln: Line, q: Quantities, inputs: CostInputs, horizon: int,
              hosts: int | None) -> Row:
    rates = inputs.rates
    ref = ln.price.ref
    assert ref is not None and ln.driver is not None
    rate = rates.rate(ref)
    price_basis = ("derived" if ref.startswith("derived.") else sourced(rates, ref).basis or
                   "unset")
    price_basis = getattr(price_basis, "value", price_basis)
    am = _amortised(ln, horizon)
    row = Row(sc.id, ln.id, ln.function, ln.category.value, ln.perimeter.value,
              ln.recurrence.value, None, ln.driver.value, rate, None, price_basis=str(price_basis))
    missing: list[str] = []
    if rate is None:
        missing.append(ref)

    d = ln.driver
    if d is Driver.MONTHLY:
        row.quantity = float(hosts or 1)
        row.unit, row.quantity_basis = "host-months", "derived" if hosts else "assumed"
        if ref == "derived.hardware_monthly" and rate is None:
            missing = ["host.purchase_price, host.useful_life_months and "
                       "host.project_usage_share (all three)"]
    elif d is Driver.ANALYST_HOURS:
        h = q.review_hours_per_item.get(sc.review_condition)
        row.labour, row.unit, row.quantity_basis = "review", "hours", "measured"
        if h is None:
            missing.append(f"analyst hours per item, condition {sc.review_condition} (timer)")
        else:
            row.quantity = h * q.items_per_month
            row.hours = row.quantity
    elif d is Driver.ENERGY_KWH:
        watts = rates.host.power_active_watts.value
        hours = machine_hours(q, sc.backend)
        row.unit, row.quantity_basis = "kWh", "derived"
        if watts is None:
            missing.append("host.power_active_watts")
        if hours is None:
            missing.append("machine hours per item (automated and, for a local model, "
                           "inference time)")
        if watts is not None and hours is not None:
            row.quantity = hours * watts / 1000.0
    elif d is Driver.STORAGE_GB:
        row.unit, row.quantity_basis = "GB", "workload"
        if q.storage_gb is None:
            missing.append("storage_gb (workload)")
        else:
            row.quantity = q.storage_gb
    elif d is Driver.FIXED_HOURS:
        assert ln.quantity_ref is not None
        s = sourced(rates, ln.quantity_ref)
        row.labour, row.unit = "operating", "hours"
        row.quantity_basis = str(getattr(s.basis, "value", s.basis) or "unset")
        if not s.set:
            missing.append(ln.quantity_ref)
        else:
            row.quantity = s.value
            row.hours = s.value * am  # type: ignore[operator]

    row.missing = missing
    if row.quantity is not None and rate is not None:
        row.amount = row.quantity * rate * am
    row.status = "incomplete" if missing else "ok"
    return row


def _free_row(sc: Scenario, ln: Line) -> Row:
    return Row(sc.id, ln.id, ln.function, ln.category.value, ln.perimeter.value,
               ln.recurrence.value, 1.0, "licence", 0.0, 0.0, quantity_basis="n/a",
               price_basis="licence", status="free", note=ln.price.licence or "")


# ---- the ledger --------------------------------------------------------------------------------
def evaluate(inputs: CostInputs, scenario: str, workload: str, q: Quantities, *,
             view: str = "adopt", case: Case = "base", perimeter: Perimeter = "workflow",
             horizon_months: int | None = None) -> Ledger:
    sc = inputs.scenarios.scenario(scenario)
    horizon = horizon_months or inputs.rates.amortisation_horizon_months[0]
    hours = machine_hours(q, sc.backend)
    share = inputs.rates.host.project_usage_share.value
    hosts = None
    if hours is not None and share:
        hosts = max(1, math.ceil(hours / (HOURS_PER_MONTH * share)))
    rows: list[Row] = []
    for ln in sc.lines:
        if perimeter == "workflow" and ln.perimeter.value == "platform":
            continue
        if View(view) not in ln.views:
            continue
        if ln.price.source == "free":
            rows.append(_free_row(sc, ln))
        elif ln.price.source == "register":
            rows.append(_register_row(sc, ln, q, inputs, case, horizon))
        else:
            rows.append(_rate_row(sc, ln, q, inputs, horizon, hosts))
    return Ledger(scenario, workload, view, case, perimeter, horizon, rows,
                  _totals(rows, inputs, sc, q), hosts)


def _totals(rows: list[Row], inputs: CostInputs, sc: Scenario, q: Quantities) -> Totals:
    tech = sum(r.amount or 0.0 for r in rows if r.labour is None and r.amount is not None)
    tech_missing = [m for r in rows if r.labour is None for m in r.missing]
    op = [r for r in rows if r.labour == "operating"]
    rev = [r for r in rows if r.labour == "review"]
    op_hours_ok = all(r.hours is not None for r in op)
    rev_hours_ok = all(r.hours is not None for r in rev)
    op_hours = sum(r.hours or 0.0 for r in op)
    rev_hours = sum(r.hours or 0.0 for r in rev)
    eng = inputs.rates.labour.engineer_hourly.value
    ana = inputs.rates.labour.analyst_hourly.value
    missing = list(tech_missing)
    for r in op + rev:
        missing += [m for m in r.missing if m not in missing]
    return Totals(
        technology=tech, technology_complete=not tech_missing,
        operating_hours=op_hours, operating_hours_complete=op_hours_ok,
        review_hours=rev_hours, review_hours_complete=rev_hours_ok,
        operating_money=(op_hours * eng if eng is not None and op_hours_ok else None),
        review_money=(rev_hours * ana if ana is not None and rev_hours_ok else None),
        missing=sorted(set(missing)),
        proxy=any(r.quantity_basis == "proxy" for r in rows))


def evidence_shares(ledger: Ledger) -> dict[str, float]:
    """The share of the known money that rests on measured quantities and licences, supplied
    figures, or assumptions, so a reader sees how much of a total is data."""
    order = ["proxy", "assumed", "workload", "derived", "supplied", "measured", "licence"]
    out: dict[str, float] = {}
    known = [r for r in ledger.rows if r.amount]
    total = sum(r.amount for r in known if r.amount)
    if not total:
        return out
    for r in known:
        bases = [r.quantity_basis, r.price_basis]
        worst = min((b for b in bases if b in order), key=order.index, default="supplied")
        out[worst] = out.get(worst, 0.0) + (r.amount or 0.0) / total
    return {k: round(v, 4) for k, v in sorted(out.items())}


def is_operating(category: str) -> bool:
    return CostCategory(category) in OPERATING_CATEGORIES
