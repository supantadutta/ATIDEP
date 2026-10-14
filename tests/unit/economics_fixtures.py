"""Synthetic cost inputs for the economics tests. Every number here is made up, in the currency
'TST', and exists only so that the arithmetic can be checked by hand. None of it is a rate, a
price or a volume that means anything; the repository's own config holds no numbers."""

from __future__ import annotations

import copy
from pathlib import Path

import yaml

from app.config import DEFAULT_CONFIG_DIR, load_config
from research.economics.inputs import CostInputs
from schemas.cost_model import CostRates, CostScenarios, PriceRegister

SRC = {"basis": "assumed", "source": "synthetic test value"}


def val(v):
    return {"value": v, **SRC}


def raw(name):
    return yaml.safe_load((Path(DEFAULT_CONFIG_DIR) / name).read_text())


def rates_doc(**over):
    doc = raw("cost_rates.yaml")
    doc["reporting_currency"] = "TST"
    doc["labour"] = {"analyst_hourly": val(100), "engineer_hourly": val(200)}
    doc["host"] = {"purchase_price": val(12000), "useful_life_months": val(24),
                   "project_usage_share": val(0.5), "power_active_watts": val(100),
                   "electricity_per_kwh": val(0.2), "storage_per_gb_month": val(0.1)}
    doc["maintenance"] = {"monthly_connector_hours": val(2), "monthly_rule_tuning_hours": val(3),
                          "monthly_platform_admin_hours": val(1)}
    doc["build"] = {"development_hours": val(120), "adoption_setup_hours": val(10),
                    "integration_hours": val(20)}
    for k, v in over.items():
        doc[k] = v
    return doc


def entry(eid, group, components, **kw):
    base = dict(id=eid, group=group, status="priced", vendor="Vendor", product="Product",
                tier="standard", currency="TST", components=components,
                pricing_source="vendor price page (synthetic)", pricing_url="https://example.test/p",
                checked_on="2026-10-01", workload_assumption="synthetic workload")
    base.update(kw)
    return base


def comp(kind, price, unit="per unit", included=0.0):
    return {"unit_kind": kind, "price": price, "billing_unit": unit, "included_quantity": included}


def register_doc(entries=None):
    doc = raw("price_register.yaml")
    doc["entries"] = entries if entries is not None else [
        entry("llm.a", "llm_api", [comp("mtok_in", 1.0, "per 1M input tokens"),
                                   comp("mtok_out", 4.0, "per 1M output tokens")]),
        entry("llm.b", "llm_api", [comp("mtok_in", 3.0, "per 1M input tokens"),
                                   comp("mtok_out", 12.0, "per 1M output tokens")]),
        entry("vm.a", "cloud_compute", [comp("hour", 0.5, "per hour")]),
        entry("disk.a", "cloud_storage", [comp("gb_month", 0.05, "per GB-month")]),
        entry("siem.a", "siem_platform", [comp("gb_ingested_month", 0.3, "per GB ingested")]),
    ]
    return doc


def make_inputs(rates=None, register=None, workload_overrides=None) -> CostInputs:
    sc_doc = raw("cost_scenarios.yaml")
    for w in sc_doc["workloads"]:
        w["storage_gb"] = val(50)
        w["siem_ingest_gb_per_month"] = val(100)
        w["monitored_endpoints"] = val(10)
        if workload_overrides:
            w.update(workload_overrides)
    cfg = load_config()
    return CostInputs(CostRates(**(rates or rates_doc())),
                      PriceRegister(**(register or register_doc())),
                      CostScenarios(**sc_doc), copy.deepcopy(cfg.experiment.economics))
