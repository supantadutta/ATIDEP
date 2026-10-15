"""Opting in to a hosted model: refused unless every safeguard is in place. The register entry used
here is a fictional test fixture in a temporary config folder; it is not a price of anything."""

import shutil
from pathlib import Path

import pytest
import yaml

from app.wiring import build_context
from components.llm.client import BudgetExceeded, LLMRequest, store_usage
from tests.unit.test_llm_usage import OPENAI, Stub

ROOT = Path(__file__).resolve().parents[2]
KEY = "k" * 32

ENTRY = {
    "id": "test.priced", "group": "llm_api", "status": "priced", "vendor": "Test Vendor",
    "product": "Test Model", "tier": "standard", "currency": "USD",
    "components": [
        {"unit_kind": "mtok_in", "price": 1000.0, "billing_unit": "per million input tokens"},
        {"unit_kind": "mtok_out", "price": 2000.0, "billing_unit": "per million output tokens"}],
    "pricing_source": "test fixture", "pricing_url": "https://example.invalid/prices",
    "checked_on": "2026-10-15", "price_basis": "list", "archive_ref": "test-fixture",
    "workload_assumption": "test fixture only"}


@pytest.fixture()
def conf(tmp_path):
    d = tmp_path / "config"
    shutil.copytree(ROOT / "config", d)
    s = yaml.safe_load((d / "settings.yaml").read_text())
    s["database"]["url"] = f"sqlite:///{tmp_path}/platform.db"
    s["paths"].update(evidence_dir=str(tmp_path / "evidence"),
                      deployment_dir=str(tmp_path / "deployment"))
    (d / "settings.yaml").write_text(yaml.safe_dump(s))
    return d


def enable_cloud(conf, limit=5.0):
    p = yaml.safe_load((conf / "policies.yaml").read_text())
    p["llm"]["cloud_enabled"], p["llm"]["daily_cost_limit"] = True, limit
    (conf / "policies.yaml").write_text(yaml.safe_dump(p))


def add_entry(conf, entry=ENTRY):
    r = yaml.safe_load((conf / "price_register.yaml").read_text())
    r["entries"].append(entry)
    (conf / "price_register.yaml").write_text(yaml.safe_dump(r))


def env(stub, tmp_path, **over):
    return {"ATIDEP_API_KEY": KEY, "ATIDEP_LLM_PROVIDER": "cloud",
            "ATIDEP_CLOUD_URL": stub.url + "/v1", "ATIDEP_CLOUD_MODEL": "test-model",
            "ATIDEP_CLOUD_KEY": "sk-test-secret", "ATIDEP_CLOUD_PRICE_ENTRY": "test.priced",
            "ATIDEP_REPLAY_STORE": str(tmp_path / "replay.jsonl"), **over}


def req(user="hello"):
    return LLMRequest(agent="extraction", system="s", user=user, prompt_version="v", seed=1)


def test_the_default_provider_stays_local_and_an_unknown_one_is_refused(conf):
    ctx = build_context(conf, {"ATIDEP_API_KEY": KEY, "ATIDEP_LLM_MODEL": "m"})
    assert ctx.llm().provider == "ollama"
    with pytest.raises(RuntimeError, match="ATIDEP_LLM_PROVIDER"):
        build_context(conf, {"ATIDEP_API_KEY": KEY, "ATIDEP_LLM_PROVIDER": "vendor-x"})


def test_cloud_is_refused_while_the_policy_keeps_it_off(conf, tmp_path):
    add_entry(conf)
    with pytest.raises(RuntimeError, match="cloud inference is off"):
        build_context(conf, env(Stub(OPENAI), tmp_path))


@pytest.mark.parametrize("drop", ["ATIDEP_CLOUD_URL", "ATIDEP_CLOUD_MODEL", "ATIDEP_CLOUD_KEY",
                                  "ATIDEP_CLOUD_PRICE_ENTRY"])
def test_cloud_is_refused_when_any_setting_is_missing(conf, tmp_path, drop):
    enable_cloud(conf)
    add_entry(conf)
    e = env(Stub(OPENAI), tmp_path)
    del e[drop]
    with pytest.raises(RuntimeError, match=drop):
        build_context(conf, e)


def test_cloud_is_refused_without_a_priced_register_entry(conf, tmp_path):
    enable_cloud(conf)
    stub = Stub(OPENAI)
    with pytest.raises(RuntimeError, match="no price register entry"):
        build_context(conf, env(stub, tmp_path))
    with pytest.raises(RuntimeError, match="no public price"):                   # the placeholder
        build_context(conf, env(stub, tmp_path, ATIDEP_CLOUD_PRICE_ENTRY="llm_api.placeholder"))
    one_sided = dict(ENTRY, components=ENTRY["components"][:1])
    add_entry(conf, one_sided)
    with pytest.raises(RuntimeError, match="both input and output"):
        build_context(conf, env(stub, tmp_path))


def test_a_hosted_call_is_capped_recorded_and_replayed_not_paid_twice(conf, tmp_path):
    enable_cloud(conf, limit=0.20)         # 120 in + 30 out tokens at 1000/2000 per Mtok = 0.18
    add_entry(conf)
    stub = Stub(OPENAI)
    ctx = build_context(conf, env(stub, tmp_path))
    client = ctx.llm()
    assert client is ctx.llm()                                      # one client: one cap
    first = client.complete(req())
    assert not first.replayed and first.usage_source == "provider"
    assert first.cost == pytest.approx(0.18)
    again = client.complete(req())                                   # identical: from the store
    assert again.replayed and len(stub.seen) == 1
    # a different request is a second charge: 0.18 + 0.18 passes the 0.20 cap, so the next stops
    client.complete(req("another"))
    with pytest.raises(BudgetExceeded):
        client.complete(req("a third"))
    assert len(stub.seen) == 2
    total = store_usage(tmp_path / "replay.jsonl")
    assert total["calls"] == 2 and total["input_tokens"] == 240 and total["output_tokens"] == 60
    assert total["by_usage_source"] == {"provider": 2}
    assert total["by_model"] == {"cloud-openai/test-model": {"calls": 2, "input_tokens": 240,
                                                            "output_tokens": 60}}
    assert "sk-test-secret" not in repr(client) and "sk-test-secret" not in str(
        (tmp_path / "replay.jsonl").read_text())
    stub.stop()


def test_store_usage_of_a_missing_store_is_zero(tmp_path):
    assert store_usage(tmp_path / "none.jsonl")["calls"] == 0
