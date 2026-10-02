import copy
import re
from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from app.config import DEFAULT_CONFIG_DIR, PoliciesConfig, ScoringConfig, load_config
from app.db.models import TABLE_NAMES
from schemas.intelligence import BAND_LOWER_BOUNDS, CREDIBILITY_SCORE, RELIABILITY_SCORE

ROOT = Path(__file__).resolve().parents[2]


def raw(name):
    return yaml.safe_load((DEFAULT_CONFIG_DIR / name).read_text())


def test_default_config_loads():
    cfg = load_config()
    assert cfg.policies.llm.runs_per_item == 3
    assert cfg.experiment.washout_days_min >= 14


def test_scoring_config_matches_schema_constants():
    s = ScoringConfig(**raw("scoring.yaml"))
    assert {k: v for k, v in s.admiralty["reliability"].items()} == RELIABILITY_SCORE
    assert {int(k): v for k, v in s.admiralty["credibility"].items()} == CREDIBILITY_SCORE
    by_band = {b.value: lo for b, lo in BAND_LOWER_BOUNDS}
    assert s.priority_bands == by_band


@pytest.mark.parametrize("mutate", [
    lambda p: p["validation"].update(quality_score_is_a_gate=True),
    lambda p: p["validation"].update(hard_gates=p["validation"]["hard_gates"][:-1]),
    lambda p: p["validation"].update(require_benign_lookalike_test=False),
    lambda p: p["llm"].update(tools_enabled=True),
    lambda p: p["llm"].update(permit_command_generation=True),
    lambda p: p["llm"].update(use_stated_confidence_in_decisions=True),
    lambda p: p["approval"].update(allow_automatic_production_deployment=True),
    lambda p: p["approval"].update(deployment_requires_human=False),
    lambda p: p["approval"].update(edit_voids_approval=False),
    lambda p: p["ingest"].update(allowed_schemes=["http", "https"]),
    lambda p: p["ingest"].update(connect_to_validated_ip=False),
    lambda p: p["deployment"].update(mode_default="lab"),
    lambda p: p["deployment"].update(custom_rule_id_range=[1, 120000]),
])
def test_weakening_a_safety_policy_fails_loading(mutate):
    p = copy.deepcopy(raw("policies.yaml"))
    PoliciesConfig(**p)  # baseline is valid
    mutate(p)
    with pytest.raises(ValidationError):
        PoliciesConfig(**p)


def test_scoring_weights_must_sum_to_one():
    s = copy.deepcopy(raw("scoring.yaml"))
    s["priority_weights"]["recency"] = 0.5
    with pytest.raises(ValidationError):
        ScoringConfig(**s)


def test_blueprint_table_list_matches_the_database():
    text = (ROOT / "docs" / "ATIDEP_Blueprint_v3.md").read_text()
    section = text[text.index("## 39."):text.index("## 40.")]
    documented = set(re.findall(r"^- `([a-z_]+)`", section, re.M))
    # the code names validation_results/effort_cost_records exactly as documented
    assert documented == set(TABLE_NAMES)
