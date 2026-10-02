import json
from datetime import timedelta

import pytest
from sqlalchemy import select

from app.db import models as m
from app.db.session import session_scope
from app.services.deployment import (
    IOC_RULE_FILE,
    DeploymentError,
    build_rule_package,
    compose_artifacts,
    deploy_lab,
    expiry_sweep,
    export_package,
    retire_rule,
    rollback,
    rule_file_name,
)
from app.services.governance import (
    ApprovalError,
    GovernanceError,
    decide,
    submit_for_approval,
    validate_rule,
)
from components.c5_deployment.adapter import NEUTRAL_RULES_XML, WazuhAdapter
from components.c5_deployment.package import (
    PackageError,
    build_package,
    load_package,
    verify_package,
    write_package,
)
from schemas.common import RuleState
from tests.unit.test_c4_governance import (  # noqa: F401  (fixtures and helpers)
    ATTACK,
    BASELINE,
    BENIGN,
    CFG,
    NOW,
    TEST_SET,
    make_ioc,
    make_sigma_rule,
)
from tests.unit.test_c5_adapter import Stub, make_cert


# ---- the package module ----------------------------------------------------------------------
def test_a_package_is_deterministic_and_checksummed():
    files = {"b.txt": "two", "a/x.json": b"{}"}
    one = build_package("p", files, {"k": 1})
    two = build_package("p", dict(reversed(list(files.items()))), {"k": 1})
    assert one.sha256 == two.sha256 and len(one.sha256) == 64
    assert build_package("p", {**files, "b.txt": "TWO"}, {"k": 1}).sha256 != one.sha256
    assert build_package("p", files, {"k": 2}).sha256 != one.sha256
    assert list(one.manifest["files"]) == ["a/x.json", "b.txt"]


@pytest.mark.parametrize("path", ["../x", "/abs", "a/../../b", "manifest.json", "a\\b", ""])
def test_unsafe_package_paths_are_refused(path):
    with pytest.raises(PackageError):
        build_package("p", {path: "x"}, {})
    with pytest.raises(PackageError):
        build_package("p", {}, {})


def test_verify_finds_changed_missing_and_unlisted_files_and_a_forged_manifest(tmp_path):
    pkg = build_package("pkg", {"a.txt": "alpha", "d/b.txt": "beta"}, {"rule": "R"})
    root = write_package(pkg, tmp_path)
    assert verify_package(root) == [] and load_package(root).sha256 == pkg.sha256
    with pytest.raises(PackageError, match="already exists"):
        write_package(pkg, tmp_path)
    (root / "a.txt").write_text("ALPHA")
    (root / "d" / "b.txt").unlink()
    (root / "extra.txt").write_text("x")
    problems = verify_package(root)
    assert "changed: a.txt" in problems and "missing: d/b.txt" in problems
    assert "unlisted: extra.txt" in problems
    manifest = json.loads((root / "manifest.json").read_text())
    manifest["meta"] = {"rule": "OTHER"}                          # forge the meta, keep the hash
    (root / "manifest.json").write_text(json.dumps(manifest))
    assert any("checksum" in p for p in verify_package(root))
    assert verify_package(tmp_path / "nowhere") == ["the manifest is missing or unreadable"]


# ---- composing and packaging -------------------------------------------------------------------
def approved(engine, kind_index, make):
    rid = make(engine)
    with session_scope(engine) as s:
        out = validate_rule(s, rid, cfg=CFG, attack=ATTACK, test_set=TEST_SET, baseline=BASELINE)
        assert out.outcome.value == "validated"
        submit_for_approval(s, rid)
        decide(s, rid, reviewer="Dr. Rahman", decision="approved")
    return rid


@pytest.fixture()
def sigma_rule(world):
    engine, _, ids = world
    return engine, approved(engine, 0, lambda e: make_sigma_rule(e, ids[0])[0])


@pytest.fixture()
def ioc_rule(world):
    engine, _, ids = world
    return engine, approved(engine, 1, lambda e: make_ioc(e, ids[1]))


def test_a_sigma_package_holds_everything_a_reviewer_needs(sigma_rule, tmp_path):
    engine, rid = sigma_rule
    with session_scope(engine) as s:
        pkg, art = build_rule_package(s, rid, CFG, now=NOW, test_set=TEST_SET,
                                      require_approval=True)
    names = set(pkg.files)
    assert {"README.md", "approval.json", "intel/reference.json", "rule/sigma.yml",
            "rule/use_case.json", "rule/assumptions.json", "telemetry.md", "tests/results.json",
            "wazuh/conversion_report.json", "wazuh/rule_ids.json",
            f"wazuh/{rule_file_name(rid)}", "rollback/rollback.json"} <= names
    assert sum(n.startswith("tests/events/positive/") for n in names) == 2
    ref = json.loads(pkg.files["intel/reference.json"])
    assert ref["opportunity"]["decision"] == "behavioral" and ref["evidence"][0]["verified"]
    approval = json.loads(pkg.files["approval.json"])
    assert approval["reviewer"] == "Dr. Rahman" and len(approval["content_sha256"]) == 64
    assert pkg.name.startswith(f"{rid}-v1-") and pkg.meta["wazuh_rule_ids"] == art.rule_ids
    with session_scope(engine) as s:                              # same inputs, same checksum
        again, _ = build_rule_package(s, rid, CFG, now=NOW, test_set=TEST_SET)
    assert again.sha256 == pkg.sha256 and again.name == pkg.name


def test_export_writes_an_intact_package_and_records_it(sigma_rule, tmp_path):
    engine, rid = sigma_rule
    with session_scope(engine) as s:
        dep = export_package(s, rid, CFG, out_dir=tmp_path, now=NOW, test_set=TEST_SET)
        assert dep.mode == "export" and dep.status == "ok" and verify_package(dep.package_path) == []
        assert dep.wazuh_rule_ids and len(dep.package_sha256) == 64
        with pytest.raises(Exception, match="already exists"):
            export_package(s, rid, CFG, out_dir=tmp_path, now=NOW, test_set=TEST_SET)


def test_only_rules_that_passed_every_gate_can_be_packaged(world, tmp_path):
    engine, _, ids = world
    rid, _ = make_sigma_rule(engine, ids[0])                      # a draft, never validated
    with session_scope(engine) as s, pytest.raises(DeploymentError, match="passed every gate"):
        build_rule_package(s, rid, CFG, now=NOW)
    with session_scope(engine) as s, pytest.raises(DeploymentError, match="unknown rule"):
        compose_artifacts(s, "RULE-0000-0000", CFG, now=NOW)


def test_an_ioc_package_carries_the_lists_and_the_synthesised_events(ioc_rule):
    engine, rid = ioc_rule
    with session_scope(engine) as s:
        pkg, art = build_rule_package(s, rid, CFG, now=NOW)
    assert "wazuh/lists/atidep-domains" in pkg.files and f"wazuh/{IOC_RULE_FILE}" in pkg.files
    assert b"stage.bad-host.net:" in pkg.files["wazuh/lists/atidep-domains"]
    assert any(n.startswith("tests/events/benign_lookalike/") for n in pkg.files)
    assert art.report["entries"] >= 3 and "rule/ioc_bundle.json" in pkg.files


def test_ioc_artifacts_are_rebuilt_from_active_bundles_and_drop_expired_entries(ioc_rule):
    engine, rid = ioc_rule
    with session_scope(engine) as s:
        now_art = compose_artifacts(s, rid, CFG, now=NOW)
        later = compose_artifacts(s, rid, CFG, now=NOW + timedelta(days=60))   # IPs expire first
        gone = compose_artifacts(s, rid, CFG, now=NOW + timedelta(days=400))
        without = compose_artifacts(s, rid, CFG, now=NOW, exclude=rid)
    assert "1.2.3.4:" in now_art.lists["atidep-ips"] and "1.2.3.4:" not in later.lists["atidep-ips"]
    assert later.lists["atidep-ips"] == "240.0.0.1:\n"                      # sentinel, never empty
    assert "stage.bad-host.net:" in later.lists["atidep-domains"]
    assert gone.rule_files[IOC_RULE_FILE] == NEUTRAL_RULES_XML
    assert without.rule_files[IOC_RULE_FILE] == NEUTRAL_RULES_XML and without.rule_ids == []


# ---- deployment against a stub API --------------------------------------------------------------
@pytest.fixture()
def api(tmp_path):
    cert, key = make_cert(tmp_path)
    stub = Stub(cert, key)
    stub.cert = cert
    yield stub, WazuhAdapter(stub.url, "atidep", "pw", ca_file=cert,
                             allowlist=CFG.policies.deployment.wazuh_api_allowlist,
                             sleep=lambda s: None)
    stub.stop()


def test_a_lab_deployment_snapshots_uploads_restarts_and_verifies(sigma_rule, api, tmp_path):
    engine, rid = sigma_rule
    stub, adapter = api
    stub.files["rules"][rule_file_name(rid)] = "<group name='old'></group>"      # a previous version
    with session_scope(engine) as s:
        dep = deploy_lab(s, rid, adapter, CFG, out_dir=tmp_path, now=NOW, test_set=TEST_SET,
                         verify=lambda: {"ok": True, "positives": "2/2"})
        assert dep.status == "ok" and dep.mode == "lab" and dep.approval_id
        assert dep.details["verification"]["positives"] == "2/2"
        assert dep.details["previous_files"] == {rule_file_name(rid): True}
        assert s.get(m.Rule, rid).state == RuleState.DEPLOYED.value
        assert verify_package(dep.package_path) == []
        pkg = load_package(dep.package_path)
        assert pkg.files[f"rollback/previous/{rule_file_name(rid)}"] == b"<group name='old'></group>"
        dep_id = dep.id
    assert stub.restarts == 1 and "<rule id=" in stub.files["rules"][rule_file_name(rid)]

    with session_scope(engine) as s:
        rb = rollback(s, dep_id, adapter)
        assert rb.status == "rolled_back" and s.get(m.Rule, rid).state == "approved"
    assert stub.files["rules"][rule_file_name(rid)] == "<group name='old'></group>"
    assert stub.restarts == 2
    with session_scope(engine) as s, pytest.raises(DeploymentError, match="successful lab"):
        rollback(s, dep_id, adapter)                                  # not twice


def test_a_failed_verification_restores_the_previous_state(sigma_rule, api, tmp_path):
    engine, rid = sigma_rule
    stub, adapter = api
    with session_scope(engine) as s:
        dep = deploy_lab(s, rid, adapter, CFG, out_dir=tmp_path, now=NOW,
                         verify=lambda: {"ok": False})
        assert dep.status == "failed" and dep.details["rolled_back"] is True
        assert s.get(m.Rule, rid).state == RuleState.APPROVED.value
    assert stub.files["rules"][rule_file_name(rid)] == NEUTRAL_RULES_XML       # no previous: placeholder


def test_an_upload_failure_is_rolled_back_and_reported(sigma_rule, api, tmp_path):
    engine, rid = sigma_rule
    stub, adapter = api
    stub.fail_uploads = True
    with session_scope(engine) as s:
        dep = deploy_lab(s, rid, adapter, CFG, out_dir=tmp_path, now=NOW)
        assert dep.status == "failed" and "XML syntax error" in dep.details["error"]
        assert dep.details["rolled_back"] is False and "rollback_error" in dep.details


def test_deployment_needs_a_current_approval(world, api, tmp_path):
    engine, _, ids = world
    stub, adapter = api
    rid, _ = make_sigma_rule(engine, ids[0])
    with session_scope(engine) as s, pytest.raises(ApprovalError, match="not approved"):
        deploy_lab(s, rid, adapter, CFG, out_dir=tmp_path, now=NOW)
    assert stub.calls == []                                           # nothing reached the API


def test_retiring_a_deployed_rule_neutralises_it(sigma_rule, api, tmp_path):
    engine, rid = sigma_rule
    stub, adapter = api
    with session_scope(engine) as s:
        with pytest.raises(GovernanceError, match="only a deployed rule"):
            retire_rule(s, rid, adapter, CFG, now=NOW)
        deploy_lab(s, rid, adapter, CFG, out_dir=tmp_path, now=NOW)
        dep = retire_rule(s, rid, adapter, CFG, now=NOW)
        assert dep.details["retired"] and s.get(m.Rule, rid).state == RuleState.RETIRED.value
    assert stub.files["rules"][rule_file_name(rid)] == NEUTRAL_RULES_XML


def test_indicator_bundles_deploy_to_shared_lists_and_retire_back_to_the_sentinel(ioc_rule, api,
                                                                                   tmp_path):
    engine, rid = ioc_rule
    stub, adapter = api
    with session_scope(engine) as s:
        dep = deploy_lab(s, rid, adapter, CFG, out_dir=tmp_path, now=NOW)
        assert dep.status == "ok"
    assert "stage.bad-host.net:" in stub.files["lists"]["atidep-domains"]
    assert "ioc" in stub.files["rules"][IOC_RULE_FILE] or "<rule" in stub.files["rules"][IOC_RULE_FILE]
    with session_scope(engine) as s:
        retire_rule(s, rid, adapter, CFG, now=NOW)
    assert stub.files["lists"]["atidep-domains"] == "placeholder.invalid:\n"
    assert stub.files["rules"][IOC_RULE_FILE] == NEUTRAL_RULES_XML


def test_the_expiry_sweep_creates_a_new_version_that_needs_approval_again(ioc_rule, api, tmp_path):
    engine, rid = ioc_rule
    stub, adapter = api
    with session_scope(engine) as s:
        deploy_lab(s, rid, adapter, CFG, out_dir=tmp_path, now=NOW)
    later = NOW + timedelta(days=60)
    with session_scope(engine) as s:
        res = expiry_sweep(s, CFG, now=later, benign_domains=BENIGN)
        assert [(r.rule_id, r.now_empty, r.new_version) for r in res] == [(rid, False, 2)]
        assert s.get(m.Rule, rid).state == RuleState.DRAFT.value
        v = s.scalars(select(m.RuleVersion).where(m.RuleVersion.rule_id == rid,
                                                  m.RuleVersion.version == 2)).one()
        doc = json.loads(v.content)["bundle"]
        assert "1.2.3.4" not in [e["value"] for e in doc["entries"]]          # expired: dropped
        assert {"value": "1.2.3.4", "reason": "expired"} in doc["excluded"]   # and says why
        assert "stage.bad-host.net" in [e["value"] for e in doc["entries"]] or any(
            "stage.bad-host.net" in e["value"] for e in doc["entries"])
    with session_scope(engine) as s:
        assert expiry_sweep(s, CFG, now=later, benign_domains=BENIGN) == []     # draft: not active
    with session_scope(engine) as s:                                  # everything expired: report it
        s.execute(m.Rule.__table__.update().where(m.Rule.rule_id == rid).values(state="approved"))
        res = expiry_sweep(s, CFG, now=NOW + timedelta(days=400), benign_domains=BENIGN)
        assert res and res[0].now_empty and res[0].new_version is None
