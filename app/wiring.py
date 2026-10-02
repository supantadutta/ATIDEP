"""Build the running application from ``config/`` and the environment.

Nothing here is needed by the services themselves; it only assembles an :class:`AppContext`.
Inference is local (Ollama on the loopback address); cloud inference is not wired in and the
policy file keeps it off. The Wazuh lab objects are created only when their environment
variables are set.
"""

from __future__ import annotations

import os
from pathlib import Path

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
from components.llm.client import LLMClient, OllamaClient
from components.llm.prompts import load_prompt_set

ROOT = Path(__file__).resolve().parents[1]


def _path(cfg: AppConfig, key: str, default: str) -> Path:
    p = Path(cfg.settings.get("paths", {}).get(key, default))
    return p if p.is_absolute() else ROOT / p


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

    def llm() -> LLMClient:
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
