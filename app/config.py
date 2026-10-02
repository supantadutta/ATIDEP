"""Configuration loading with the safety invariants of the blueprint enforced as validation.

Editing ``config/policies.yaml`` so that, for example, the quality score becomes a gate or an
LLM gets tools makes loading fail, instead of silently weakening the design.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal, Self

import yaml
from pydantic import Field, model_validator

from schemas.common import Strict
from schemas.validation_result import ALL_GATES

DEFAULT_CONFIG_DIR = Path(__file__).resolve().parent.parent / "config"


class ScoringConfig(Strict):
    priority_weights: dict[str, float]
    priority_bands: dict[str, float]
    admiralty: dict[str, dict[str | int, int]]
    recency_half_life_days: dict[str, float]
    cross_source: dict[str, int]
    environmental_relevance: dict[str, dict[str, float]]
    potential_impact: dict[str, Any]
    quality_ranking_weights: dict[str, float]
    indicator_expiry_days: dict[str, int]

    @model_validator(mode="after")
    def _invariants(self) -> Self:
        expected = {"source_reliability", "intelligence_confidence", "environmental_relevance",
                    "recency", "cross_source_correlation", "potential_impact"}
        if set(self.priority_weights) != expected:
            raise ValueError(f"priority_weights must have exactly {sorted(expected)}")
        if abs(sum(self.priority_weights.values()) - 1.0) > 1e-9:
            raise ValueError("priority_weights must sum to 1.0")
        if abs(sum(self.quality_ranking_weights.values()) - 1.0) > 1e-9:
            raise ValueError("quality_ranking_weights must sum to 1.0")
        if set(self.indicator_expiry_days) != {"ip", "domain", "url", "hash"} \
                or any(d <= 0 for d in self.indicator_expiry_days.values()):
            raise ValueError(
                "indicator_expiry_days needs positive values for ip, domain, url, hash")
        if abs(sum(self.environmental_relevance["weights"].values()) - 1.0) > 1e-9:
            raise ValueError("environmental_relevance weights must sum to 1.0")
        bands = self.priority_bands
        if [bands[k] for k in ("low", "medium", "high", "critical")] != sorted(bands.values()):
            raise ValueError("priority band lower bounds must be ascending")
        if bands["low"] != 0:
            raise ValueError("the lowest band must start at 0")
        return self


class _Rule(Strict):
    minimum_intelligence_confidence: int = Field(ge=0, le=100)
    minimum_evidence_support_pct: int = Field(ge=0, le=100)
    require_evidence_ids: bool
    repair_max_attempts: int = Field(ge=0, le=5)


class _Validation(Strict):
    hard_gates: list[str]
    all_hard_gates_required: bool
    quality_score_is_a_gate: bool
    max_benign_match_pct: float = Field(ge=0, le=100)
    require_positive_test: bool
    require_negative_test: bool
    require_benign_lookalike_test: bool


class _Approval(Strict):
    deployment_requires_human: bool
    approval_bound_to_content_hash: bool
    edit_voids_approval: bool
    allow_automatic_production_deployment: bool


class _Llm(Strict):
    tools_enabled: bool
    permit_command_generation: bool
    redact_sensitive_fields: bool
    reject_non_schema_output: bool
    use_stated_confidence_in_decisions: bool
    local_first: bool
    cloud_enabled: bool
    daily_cost_limit: float = Field(ge=0)
    runs_per_item: int = Field(ge=1)


class _Ingest(Strict):
    allowed_schemes: list[str]
    max_redirects: int = Field(ge=0, le=10)
    max_response_mb: int = Field(ge=1)
    block_private_and_reserved_ranges: bool
    connect_to_validated_ip: bool


class _Deployment(Strict):
    mode_default: str
    wazuh_api_allowlist: list[str]
    custom_rule_id_range: tuple[int, int]
    max_sibling_rules_per_sigma_rule: int = Field(ge=1)


class PoliciesConfig(Strict):
    rule_generation: _Rule
    validation: _Validation
    approval: _Approval
    llm: _Llm
    ingest: _Ingest
    deployment: _Deployment

    @model_validator(mode="after")
    def _safety_invariants(self) -> Self:
        v, a, m, i, d = self.validation, self.approval, self.llm, self.ingest, self.deployment
        if v.hard_gates != [g.value for g in ALL_GATES] or not v.all_hard_gates_required:
            raise ValueError("every hard gate G1-G11 must be listed and required")
        if v.quality_score_is_a_gate:
            raise ValueError("the quality score must not be a gate (ranking only)")
        if not (v.require_positive_test and v.require_negative_test
                and v.require_benign_lookalike_test):
            raise ValueError("positive, negative and benign look-alike tests are mandatory")
        if not (a.deployment_requires_human and a.approval_bound_to_content_hash
                and a.edit_voids_approval) or a.allow_automatic_production_deployment:
            raise ValueError("deployment must need a hash-bound human approval; no automatic "
                             "production deployment")
        if m.tools_enabled or m.permit_command_generation or m.use_stated_confidence_in_decisions:
            raise ValueError("LLM agents must have no tools, no command generation, and their "
                             "stated confidence must not drive decisions")
        if not (m.redact_sensitive_fields and m.reject_non_schema_output):
            raise ValueError("redaction and strict schema validation must stay on")
        if not m.local_first:
            raise ValueError("inference must be local-first; cloud is an explicit opt-in")
        if m.cloud_enabled and m.daily_cost_limit <= 0:
            raise ValueError("cloud inference needs a positive daily cost cap")
        if i.allowed_schemes != ["https"] or not i.block_private_and_reserved_ranges \
                or not i.connect_to_validated_ip:
            raise ValueError("ingest must be https-only, block private ranges, and connect to "
                             "the validated IP")
        if d.mode_default != "dry_run":
            raise ValueError("the default deployment mode must be dry_run")
        lo, hi = d.custom_rule_id_range
        if not 100000 <= lo < hi <= 120000:
            raise ValueError("custom rule IDs must stay within 100000-120000")
        return self


class CostCriteria(Strict):
    """Pre-registered, descriptive cost-effectiveness settings (blueprint §22.6)."""

    primary_view: Literal["adopt", "build"]
    views: list[Literal["adopt", "build"]]
    inference_modes_reported_separately: list[Literal["local", "cloud"]]

    @model_validator(mode="after")
    def _primary_in_views(self) -> Self:
        if self.primary_view not in self.views:
            raise ValueError("primary_view must be one of the reported views")
        return self


class ExperimentConfig(Strict):
    design: str
    washout_days_min: int = Field(ge=14)
    set_assignment_seed: Any
    runs_per_item: int = Field(ge=3)
    model: dict[str, Any]
    primary_endpoint: str
    delta_t_pct: float = Field(gt=0, le=100)
    delta_q_rubric_points: float = Field(gt=0)
    h6_min_fp_reduction_pct: float = Field(gt=0, le=100)
    h6_min_tp_retention_pct: float = Field(gt=0, le=100)
    alpha_familywise: float = Field(gt=0, lt=1)
    bootstrap_resamples: int = Field(ge=1000)
    second_labeler_min_items: int = Field(ge=10)
    independent_analyst_min_items: int = Field(ge=0)
    cost_criteria: CostCriteria


class AppConfig(Strict):
    scoring: ScoringConfig
    policies: PoliciesConfig
    experiment: ExperimentConfig
    settings: dict[str, Any]
    org_profile: dict[str, Any]
    telemetry_catalog: dict[str, Any]
    sources: dict[str, Any]
    wazuh_mapping: dict[str, Any]
    cost_rates: dict[str, Any]


def _load(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    if not isinstance(data, dict):
        raise ValueError(f"{path.name} must contain a mapping")
    return data


def load_config(config_dir: Path | str = DEFAULT_CONFIG_DIR) -> AppConfig:
    d = Path(config_dir)
    return AppConfig(
        scoring=_load(d / "scoring.yaml"),
        policies=_load(d / "policies.yaml"),
        experiment=_load(d / "experiment.yaml"),
        settings=_load(d / "settings.yaml"),
        org_profile=_load(d / "org_profile.yaml"),
        telemetry_catalog=_load(d / "telemetry_catalog.yaml"),
        sources=_load(d / "sources.yaml"),
        wazuh_mapping=_load(d / "wazuh_mapping.yaml"),
        cost_rates=_load(d / "cost_rates.yaml"),
    )
