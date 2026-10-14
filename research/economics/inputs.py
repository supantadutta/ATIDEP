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
    PriceRegister,
    Sourced,
)

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
    return CostInputs(rates, register, scenarios, economics, hashes,
                      cfg.experiment.bootstrap_resamples)


def sourced(rates: CostRates, path: str) -> Sourced:
    section, key = path.split(".")
    return getattr(getattr(rates, section), key)


def readiness(inputs: CostInputs) -> list[Gap]:
    """Everything the verdict still needs: unset rates and hours that the S-OSS-LOCAL and S-PAID
    lines use, register groups without a priced adequate candidate, and the coordinator's two
    pre-registration decisions."""
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
    if inputs.rates.reporting_currency is None:
        gaps.append(Gap("reporting_currency", "all money", "coordinator",
                        "the currency every amount is reported in"))
    eco = inputs.economics
    if eco.primary_workload is None:
        gaps.append(Gap("economics.primary_workload", "the H7 verdict", "coordinator",
                        "name the one workload that carries the headline claim, before the freeze"))
    if eco.delta_c_pct is None:
        gaps.append(Gap("economics.delta_c_pct", "the H7 verdict", "coordinator",
                        "the threshold for 'substantially cheaper', with a one-line rationale"))
    return gaps


def fixed_hour_paths() -> tuple[str, ...]:
    return FIXED_HOUR_QUANTITIES
