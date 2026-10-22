"""Build the running application from ``config/`` and the environment.

Nothing here is needed by the services themselves; it only assembles an :class:`AppContext`.
Inference is local by default (Ollama on the loopback address). A hosted model is an explicit
opt-in (``ATIDEP_LLM_PROVIDER=cloud``) and is refused unless the policy file enables it with a
positive daily cap, the key and endpoint are given, and the model's token prices come from a
*priced* entry of ``config/price_register.yaml`` (a price is never typed into the environment).
Every hosted call goes through the spend cap and is recorded, so a repeated identical request is
replayed and not paid twice. The Wazuh lab objects are created only when their environment
variables are set.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

import yaml

from app.api.main import AppContext
from app.config import AppConfig, load_config
from app.db.session import init_db, make_engine
from components.c1_ingest.evidence import EvidenceStore
from components.c1_ingest.ssrf import SafeFetcher
from components.c2_processing.attack import load_release
from components.c2_processing.indicators import load_benign_domains
from components.c4_validation.corpus import TestSet, load_baseline, load_test_set
from components.c4_validation.tier2 import LabError, LabManager
from components.c5_deployment.adapter import WazuhAdapter
from components.llm.client import (
    CloudChatClient,
    CostGuard,
    GuardedClient,
    LLMClient,
    OllamaClient,
    ReplayClient,
)
from components.llm.prompts import load_prompt_set
from schemas.cost_model import PriceRegister, UnitKind

ROOT = Path(__file__).resolve().parents[1]


def _path(cfg: AppConfig, key: str, default: str) -> Path:
    p = Path(cfg.settings.get("paths", {}).get(key, default))
    return p if p.is_absolute() else ROOT / p


@dataclass
class CloudSetup:
    client: LLMClient            # ReplayClient(record) around GuardedClient around the hosted model
    guard: CostGuard
    currency: str                # the currency of the price entry, and so of the daily cap
    price_entry: str
    store: Path


def build_cloud_setup(cfg: AppConfig, env: dict[str, str], config_dir: Path | str | None = None
                      ) -> CloudSetup:
    """Assemble a hosted-model client, or refuse with the first thing that is missing."""
    if not cfg.policies.llm.cloud_enabled:
        raise RuntimeError("cloud inference is off: set policies.llm.cloud_enabled with a "
                           "positive daily_cost_limit to opt in")
    need = ("ATIDEP_CLOUD_URL", "ATIDEP_CLOUD_MODEL", "ATIDEP_CLOUD_KEY",
            "ATIDEP_CLOUD_PRICE_ENTRY")
    missing = [k for k in need if not env.get(k)]
    if missing:
        raise RuntimeError(f"cloud inference needs {', '.join(missing)} (see .env.example)")
    cfg_dir = Path(config_dir) if config_dir else ROOT / "config"
    register = PriceRegister.model_validate(
        yaml.safe_load((cfg_dir / "price_register.yaml").read_text(encoding="utf-8")))
    entry = next((e for e in register.entries if e.id == env["ATIDEP_CLOUD_PRICE_ENTRY"]), None)
    if entry is None:
        raise RuntimeError(f"no price register entry {env['ATIDEP_CLOUD_PRICE_ENTRY']!r}")
    if entry.status != "priced":
        raise RuntimeError(f"price entry {entry.id!r} has no public price (status "
                           f"{entry.status}); the spend cap needs a priced entry")
    comps = {c.unit_kind: c for c in entry.components}
    if UnitKind.MTOK_IN not in comps or UnitKind.MTOK_OUT not in comps:
        raise RuntimeError(f"price entry {entry.id!r} must price both input and output tokens")
    limit = cfg.policies.llm.daily_cost_limit
    if not limit:                       # the config loader already refuses this; kept explicit
        raise RuntimeError("cloud inference needs a positive daily_cost_limit")
    # the guard charges every token at the list price and ignores any included monthly usage, so
    # it stops no later than the real bill would
    guard = CostGuard(limit,
                      price_in_per_mtok=comps[UnitKind.MTOK_IN].price,
                      price_out_per_mtok=comps[UnitKind.MTOK_OUT].price)
    inner = CloudChatClient(env.get("ATIDEP_CLOUD_API_STYLE", "openai"),  # type: ignore[arg-type]
                            env["ATIDEP_CLOUD_URL"], env["ATIDEP_CLOUD_MODEL"],
                            env["ATIDEP_CLOUD_KEY"], ca_file=env.get("ATIDEP_CLOUD_CA_BUNDLE")
                            or None)
    store = Path(env.get("ATIDEP_REPLAY_STORE") or (ROOT / "data" / "llm_replay.jsonl"))
    # replay outside, guard inside: a stored call is neither checked against nor charged to the cap
    client = ReplayClient(store, GuardedClient(inner, guard), "record")
    return CloudSetup(client, guard, entry.currency or "", entry.id, store)


def build_context(config_dir: Path | str | None = None, env: dict[str, str] | None = None
                  ) -> AppContext:
    env = dict(os.environ if env is None else env)
    config_dir = config_dir or env.get("ATIDEP_CONFIG_DIR")
    cfg = load_config(config_dir) if config_dir else load_config()
    api_key = env.get("ATIDEP_API_KEY", "")
    if not api_key or api_key == "change-me":
        raise RuntimeError("set ATIDEP_API_KEY (see .env.example) to a long random value")
    db_url = cfg.settings["database"]["url"]
    if db_url.startswith("sqlite:///") and not db_url.startswith("sqlite:////"):
        db_url = "sqlite:///" + str(ROOT / db_url.removeprefix("sqlite:///"))
    engine = make_engine(db_url)
    init_db(engine)

    model = env.get("ATIDEP_LLM_MODEL", "")
    base = env.get("ATIDEP_LLM_URL", "http://127.0.0.1:11434")

    provider = env.get("ATIDEP_LLM_PROVIDER", "ollama")
    if provider not in ("ollama", "cloud"):
        raise RuntimeError("ATIDEP_LLM_PROVIDER must be 'ollama' or 'cloud'")
    cloud = build_cloud_setup(cfg, env, config_dir) if provider == "cloud" else None

    def llm() -> LLMClient:
        if cloud is not None:
            return cloud.client                        # one client: the cap spans every call
        if not model:
            raise RuntimeError("set ATIDEP_LLM_MODEL to a model served by your local Ollama")
        return OllamaClient(model, base)

    sets_dir = _path(cfg, "test_sets_dir", "data/test_sets")

    def test_set_for(intel_id: str) -> TestSet | None:
        d = sets_dir / intel_id
        return load_test_set(d, intel_id) if d.is_dir() else None

    baseline_path = _path(cfg, "baseline", "tests/events/benign_baseline/baseline.jsonl")
    lab = adapter = None
    if env.get("WAZUH_API_USER") and env.get("WAZUH_API_PASSWORD"):
        ca = env.get("WAZUH_API_CA_BUNDLE", "")
        if ca:
            def adapter() -> WazuhAdapter:               # noqa: E306 - created per request
                return WazuhAdapter(env.get("WAZUH_API_URL", "https://127.0.0.1:55000"),
                                    env["WAZUH_API_USER"], env["WAZUH_API_PASSWORD"], ca_file=ca,
                                    allowlist=cfg.policies.deployment.wazuh_api_allowlist)
        try:
            candidate = LabManager(env.get("ATIDEP_LAB_CONTAINER", "wazuh"))
            lab = candidate if candidate.available() else None
        except LabError:
            lab = None

    def fetcher(domains: list[str]) -> SafeFetcher:
        return SafeFetcher(domains, max_bytes=cfg.policies.ingest.max_response_mb * 1024 * 1024,
                           max_redirects=cfg.policies.ingest.max_redirects)

    return AppContext(
        cfg=cfg, engine=engine, store=EvidenceStore(_path(cfg, "evidence_dir", "data/evidence")),
        attack=load_release(), prompts=load_prompt_set(), api_key=api_key,
        benign_domains=load_benign_domains(), llm=llm,
        packages_dir=_path(cfg, "deployment_dir", "deployment") / "packages",
        baseline=load_baseline(baseline_path) if baseline_path.exists() else [],
        test_set_for=test_set_for, fetcher=fetcher, adapter=adapter, lab=lab)
