"""Load and cross-check the cost inputs (rates, price register, scenarios, economics settings),
and say what is still missing and who has to supply it."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from app.config import DEFAULT_CONFIG_DIR, EconomicConfig, load_config
from schemas.cost_model import (
    FIXED_HOUR_QUANTITIES,
    QUOTE_REQUIRED,
    CostRates,
    CostScenarios,
    Driver,
    PriceRegister,
    Sourced,
    UnitKind,
)

# register unit kinds that need a workload quantity, and the workload field that holds it
WORKLOAD_FIELDS = {UnitKind.GB_MONTH: "storage_gb",
                   UnitKind.GB_INGESTED: "siem_ingest_gb_per_month",
                   UnitKind.ENDPOINT_MONTH: "monitored_endpoints"}

FILES = ("cost_rates.yaml", "price_register.yaml", "cost_scenarios.yaml")

# Who can supply each input, and how. The researcher measures; the coordinator decides or sources.
SUPPLIED_BY: dict[str, tuple[str, str]] = {
    "labour.analyst_hourly": ("coordinator", "the organisation's documented hourly cost of an "
                              "analyst, with its source and date"),
    "labour.engineer_hourly": ("coordinator", "the organisation's documented hourly cost of "
                               "engineering or administration work, with its source and date"),
    "host.purchase_price": ("researcher", "the receipt, or a dated price reference, for the "
                            "machine that runs the automated work"),
    "host.useful_life_months": ("coordinator", "an accounting or policy life for that machine, "
                                "with its source"),
    "host.project_usage_share": ("coordinator", "the fraction of the machine given to this work, "
                                 "stated as an assumption"),
    "host.power_active_watts": ("researcher", "one plug-in wall-meter reading under load, with "
                                "the meter and the procedure"),
    "host.electricity_per_kwh": ("coordinator", "the tariff on an electricity bill, with its date"),
    "host.storage_per_gb_month": ("coordinator", "the local disk price allocated per gigabyte-"
                                  "month, with its source"),
    "maintenance.monthly_connector_hours": ("researcher", "the 'operations' timer gives a "
                                            "measured floor during the study; the rest is an "
                                            "assumption"),
    "maintenance.monthly_rule_tuning_hours": ("researcher", "as above"),
    "maintenance.monthly_platform_admin_hours": ("researcher", "as above"),
    "build.development_hours": ("researcher", "reconstructed from a development log; never "
                                "guessed"),
    "build.adoption_setup_hours": ("researcher", "timed on a clean installation"),
    "build.integration_hours": ("coordinator", "an assumption for a paid build, with its basis"),
}


@dataclass
class CostInputs:
    rates: CostRates
    register: PriceRegister
    scenarios: CostScenarios
    economics: EconomicConfig
    hashes: dict[str, str] = field(default_factory=dict)
    bootstrap_resamples: int = 10000


@dataclass(frozen=True)
class Gap:
    what: str
    needed_for: str
    supplied_by: str
    how: str


def _read(path: Path) -> tuple[dict[str, Any], str]:
    raw = path.read_bytes()
    return yaml.safe_load(raw), hashlib.sha256(raw).hexdigest()


def load_cost_inputs(config_dir: Path | str = DEFAULT_CONFIG_DIR) -> CostInputs:
    d = Path(config_dir)
    docs, hashes = {}, {}
    for name in FILES:
        docs[name], hashes[name] = _read(d / name)
    cfg = load_config(d)
    hashes["experiment.yaml"] = hashlib.sha256((d / "experiment.yaml").read_bytes()).hexdigest()
    rates = CostRates(**docs["cost_rates.yaml"])
    register = PriceRegister(**docs["price_register.yaml"])
    scenarios = CostScenarios(**docs["cost_scenarios.yaml"])
    economics = cfg.experiment.economics
    groups = set(register.groups())
    for sc in scenarios.scenarios:
        for ln in sc.lines:
            if ln.price.source == "register" and ln.price.ref not in groups:
                raise ValueError(f"{sc.id}/{ln.id}: the price register has no group "
                                 f"{ln.price.ref!r}")
    if economics.primary_workload is not None and economics.primary_workload not in {
            w.id for w in scenarios.workloads}:
        raise ValueError(f"primary_workload {economics.primary_workload!r} is not a workload")
    if economics.primary_horizon_months is not None and economics.primary_horizon_months not in \
            rates.amortisation_horizon_months:
        raise ValueError(f"primary_horizon_months {economics.primary_horizon_months} is not one "
                         "of amortisation_horizon_months in cost_rates.yaml")
    return CostInputs(rates, register, scenarios, economics, hashes,
                      cfg.experiment.bootstrap_resamples)


def sourced(rates: CostRates, path: str) -> Sourced:
    section, key = path.split(".")
    return getattr(getattr(rates, section), key)


def readiness(inputs: CostInputs) -> list[Gap]:
    """Everything the verdict still needs: unset rates and hours that the S-OSS-LOCAL and S-PAID
    lines use, register groups without a priced adequate candidate, a sourced exchange rate for
    every priced candidate in another currency, the workload quantities that a line or a candidate
    is metered on, a free line whose licence is still pending, and the coordinator's
    pre-registration decisions. When this list is empty the ledger can be complete."""
    gaps: list[Gap] = []
    seen: set[str] = set()
    sc = inputs.scenarios
    for sid in (sc.oss_local, sc.paid, sc.manual):
        for ln in sc.scenario(sid).lines:
            refs: list[str] = []
            if ln.price.source == "rate":
                if ln.price.ref == "derived.hardware_monthly":
                    refs += ["host.purchase_price", "host.useful_life_months",
                             "host.project_usage_share"]
                else:
                    refs.append(ln.price.ref)  # type: ignore[arg-type]
                if ln.driver and ln.driver.value == "energy_kwh":
                    refs.append("host.power_active_watts")
                if ln.quantity_ref:
                    refs.append(ln.quantity_ref)
            for ref in refs:
                if ref in seen or sourced(inputs.rates, ref).set:
                    continue
                seen.add(ref)
                who, how = SUPPLIED_BY.get(ref, ("coordinator", "a sourced value"))
                gaps.append(Gap(ref, f"{sid}/{ln.id}", who, how))
            if ln.price.source == "free" and (ln.price.licence or "").strip().lower() \
                    .startswith("pending") and f"licence:{ln.id}" not in seen:
                seen.add(f"licence:{ln.id}")
                gaps.append(Gap(f"licence of {ln.id}", f"{sid}/{ln.id}", "researcher",
                                "record the licence (and any fee or use restriction) once the "
                                "component is chosen"))
            needs: set[str] = set()
            if ln.price.source == "rate" and ln.driver is Driver.STORAGE_GB:
                needs.add("storage_gb")
            if ln.price.source == "register":
                g = ln.price.ref
                key = f"register:{g}"
                usable = [e for e in inputs.register.group(g) if e.usable]  # type: ignore[arg-type]
                if not usable and key not in seen:
                    seen.add(key)
                    gaps.append(Gap(f"price register group {g!r}", f"{sid}/{ln.id}",
                                    "coordinator",
                                    f"candidate products with prices from the vendors' own "
                                    f"pages; until then: {QUOTE_REQUIRED}"))
                cur = inputs.rates.reporting_currency
                for e in usable:
                    needs |= {WORKLOAD_FIELDS[c.unit_kind] for c in e.components
                              if c.unit_kind in WORKLOAD_FIELDS}
                    fx = f"fx:{e.currency}"
                    if cur and e.currency and e.currency != cur and fx not in seen and \
                            inputs.rates.convert(1.0, e.currency) is None:
                        seen.add(fx)
                        gaps.append(Gap(f"exchange rate {e.currency} to {cur}", f"{sid}/{ln.id}",
                                        "coordinator", "a sourced, dated rate (fx in "
                                        "cost_rates.yaml)"))
            for w in sc.workloads:
                for f in sorted(needs):
                    if getattr(w, f).value is None and f"wl:{w.id}:{f}" not in seen:
                        seen.add(f"wl:{w.id}:{f}")
                        gaps.append(Gap(f"{f} of workload {w.id}", f"{sid}/{ln.id}",
                                        "coordinator", "the workload's volume, with its basis "
                                        "(cost_scenarios.yaml)"))
    if inputs.rates.reporting_currency is None:
        gaps.append(Gap("reporting_currency", "all money", "coordinator",
                        "the currency every amount is reported in"))
    eco = inputs.economics
    if eco.primary_workload is None:
        gaps.append(Gap("economics.primary_workload", "the H7 verdict", "coordinator",
                        "name the one workload that carries the headline claim, before the freeze"))
    if eco.primary_horizon_months is None:
        gaps.append(Gap("economics.primary_horizon_months", "the H7 verdict", "coordinator",
                        "name the one amortisation horizon that carries the headline claim, "
                        "before the freeze (every horizon is still reported)"))
    if eco.delta_c_pct is None:
        gaps.append(Gap("economics.delta_c_pct", "the H7 verdict", "coordinator",
                        "the threshold for 'substantially cheaper', with a one-line rationale"))
    return gaps


def fixed_hour_paths() -> tuple[str, ...]:
    return FIXED_HOUR_QUANTITIES
