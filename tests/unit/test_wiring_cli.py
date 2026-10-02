import shutil
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from app.__main__ import main
from app.api.main import create_app
from app.wiring import build_context

ROOT = Path(__file__).resolve().parents[2]


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


def test_an_api_key_is_required_and_the_placeholder_is_refused(conf):
    for env in ({}, {"ATIDEP_API_KEY": ""}, {"ATIDEP_API_KEY": "change-me"}):
        with pytest.raises(RuntimeError, match="ATIDEP_API_KEY"):
            build_context(conf, env)


def test_the_context_assembles_and_serves(conf, tmp_path):
    ctx = build_context(conf, {"ATIDEP_API_KEY": "k" * 32})
    assert ctx.adapter is None and ctx.lab is None                    # no Wazuh variables set
    assert len(ctx.baseline) == 400 and ctx.attack.version
    client = TestClient(create_app(ctx))
    assert client.get("/health").json() == {"status": "ok"}
    assert client.get("/overview", headers={"Authorization": "Bearer " + "k" * 32}
                      ).json()["items"] == 0
    with pytest.raises(RuntimeError, match="ATIDEP_LLM_MODEL"):
        ctx.llm()                                                      # no model named yet
    assert ctx.test_set_for("TI-2026-0001") is None


def test_the_model_client_is_local_only(conf):
    ctx = build_context(conf, {"ATIDEP_API_KEY": "k" * 32, "ATIDEP_LLM_MODEL": "qwen-test"})
    assert ctx.llm().model == "qwen-test"
    remote = build_context(conf, {"ATIDEP_API_KEY": "k" * 32, "ATIDEP_LLM_MODEL": "m",
                                  "ATIDEP_LLM_URL": "http://203.0.113.9:11434"})
    with pytest.raises(Exception, match="non-local"):
        remote.llm()


def test_the_cli(conf, monkeypatch, capsys):
    monkeypatch.setenv("ATIDEP_CONFIG_DIR", str(conf))
    monkeypatch.setenv("ATIDEP_API_KEY", "k" * 32)
    assert main(["help"]) == 0 and main(["nonsense"]) == 2
    assert main(["init-db"]) == 0
    assert main(["verify-audit"]) == 0
    assert "intact: 0 events" in capsys.readouterr().out
    s = yaml.safe_load((conf / "settings.yaml").read_text())
    s["api"]["host"] = "0.0.0.0"                                       # noqa: S104 - the test case
    (conf / "settings.yaml").write_text(yaml.safe_dump(s))
    assert main(["serve"]) == 2
    assert "non-local" in capsys.readouterr().out
