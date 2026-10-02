"""Deployment on the real manager through the least-privilege API user (blueprint §20.5)."""
import json
import urllib.error
import urllib.request
from datetime import timedelta

import pytest
from sqlalchemy import select, update

from app.db import models as m
from app.db.session import session_scope
from app.services.deployment import (
    IOC_RULE_FILE,
    SCRATCH_FILE,
    compose_artifacts,
    deploy_lab,
    dry_run,
    expiry_sweep,
    export_package,
    retire_rule,
    rollback,
    rule_file_name,
)
from app.services.governance import ApprovalError, decide, submit_for_approval, validate_rule
from components.c1_ingest.evidence import sha256_hex
from components.c4_validation.ioc_gates import synthesize_tests
from components.c5_deployment.adapter import (
    NEUTRAL_RULES_XML,
    REQUIRED_ACTIONS,
    NotAllowed,
    WazuhAdapter,
)
from components.c5_deployment.package import verify_package
from components.c5_deployment.verify import replay_verifier
from schemas.common import RuleState
from schemas.ioc_bundle import IocBundle
from tests.unit.test_c4_governance import (
    ATTACK,
    BASELINE,
    BENIGN,
    CFG,
    NOW,
    TEST_SET,
    make_ioc,
    make_sigma_rule,
)

USER, PASSWORD = "atidep", "Atidep#Lab2026x"
API_CERT = "/var/ossec/api/configuration/ssl/server.crt"
PROBE_RULE = ('<group name="atidep,probe,"><rule id="119998" level="0"><if_sid>61603</if_sid>'
              '<field name="win.eventdata.image" type="pcre2">(?!)</field>'
              "<description>probe</description></rule></group>")


@pytest.fixture(scope="module")
def adapter(lab, tmp_path_factory):
    lab.create_deploy_user(USER, PASSWORD, list(REQUIRED_ACTIONS))
    cert = tmp_path_factory.mktemp("pin") / "server.crt"
    lab.copy_out(API_CERT, cert)
    return WazuhAdapter(lab.api_url, USER, PASSWORD, ca_file=str(cert),
                        allowlist=CFG.policies.deployment.wazuh_api_allowlist)


def approved_sigma(engine, opp_id):
    rid, _ = make_sigma_rule(engine, opp_id)
    with session_scope(engine) as s:
        out = validate_rule(s, rid, cfg=CFG, attack=ATTACK, test_set=TEST_SET, baseline=BASELINE)
        assert out.outcome.value == "validated"
        submit_for_approval(s, rid)
        decide(s, rid, reviewer="Dr. Rahman", decision="approved")
    return rid


def approved_ioc(engine, opp_id):
    rid = make_ioc(engine, opp_id)
    with session_scope(engine) as s:
        out = validate_rule(s, rid, cfg=CFG, attack=ATTACK, test_set=None, baseline=BASELINE)
        assert out.outcome.value == "validated"
        submit_for_approval(s, rid)
        decide(s, rid, reviewer="Dr. Rahman", decision="approved")
    return rid


def bundle_entries(session, rule_id):
    v = session.scalars(select(m.RuleVersion).where(m.RuleVersion.rule_id == rule_id)).one()
    return IocBundle.model_validate(json.loads(v.content)["bundle"]).entries


def test_the_restricted_user_can_do_its_job_and_nothing_else(lab, adapter):
    adapter.put_rule_file(SCRATCH_FILE, PROBE_RULE)                  # overwrites an existing file
    assert "119998" in adapter.get_rule_file(SCRATCH_FILE)
    adapter.put_rule_file(SCRATCH_FILE, NEUTRAL_RULES_XML)
    with pytest.raises(NotAllowed):                                  # the adapter never deletes
        adapter._raw("DELETE", f"/rules/files/{SCRATCH_FILE}")
    with pytest.raises(NotAllowed):                                  # nor does it read config
        adapter._raw("GET", "/manager/configuration")

    def manager_answer(path):
        req = urllib.request.Request(adapter.api_url + path, method="GET",
                                     headers={"Authorization": f"Bearer {adapter._token_value()}"})
        try:
            with urllib.request.urlopen(req, context=adapter._ctx, timeout=30) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            return exc.code, {}

    # what the role was never granted is refused or empty at the manager (defence in depth)
    status, body = manager_answer("/security/users")
    assert status == 403 or body["data"]["total_affected_items"] == 0
    status, body = manager_answer("/agents")
    assert status == 403 or body["data"]["total_affected_items"] == 0
    # the known residual risk (F17): manager:read, needed for restart, exposes the configuration
    status, _ = manager_answer("/manager/configuration")
    assert status == 200


def test_export_dry_run_deploy_and_rollback_of_a_sigma_rule(world, lab, adapter, tmp_path):
    engine, _, ids = world
    rid = approved_sigma(engine, ids[0])
    with session_scope(engine) as s:
        exp = export_package(s, rid, CFG, out_dir=tmp_path / "exports", now=NOW,
                             test_set=TEST_SET)
        assert verify_package(exp.package_path) == []
        dry = dry_run(s, rid, adapter, CFG, now=NOW, test_set=TEST_SET)
        assert dry.status == "ok", dry.details
        assert dry.details["tier"] == "2a" and dry.details["events"] == 5
    assert "119999" in adapter.get_rule_file(SCRATCH_FILE)               # scratch file neutralised

    with session_scope(engine) as s:
        art = compose_artifacts(s, rid, CFG, now=NOW)
        dep = deploy_lab(s, rid, adapter, CFG, out_dir=tmp_path / "packages", now=NOW,
                         test_set=TEST_SET, verify=replay_verifier(lab, TEST_SET, art.rule_ids))
        assert dep.status == "ok", dep.details
        assert dep.details["verification"]["ok"]
        assert dep.details["verification"]["positives"] == "2/2"
        assert s.get(m.Rule, rid).state == RuleState.DEPLOYED.value
        assert verify_package(dep.package_path) == []
        dep_id = dep.id
    assert "<rule id=" in adapter.get_rule_file(rule_file_name(rid))

    with session_scope(engine) as s:
        rb = rollback(s, dep_id, adapter)
        assert rb.status == "rolled_back"
        assert s.get(m.Rule, rid).state == RuleState.APPROVED.value
    assert "119999" in adapter.get_rule_file(rule_file_name(rid))        # back to the placeholder
    replay = lab.replay([e.event for e in TEST_SET.positive])
    atidep = [f.rule_id for hits in replay.fired.values() for f in hits
              if 110000 <= f.rule_id < 120000]
    assert atidep == []                         # stock Wazuh rules may still alert; ATIDEP's do not


def test_a_failed_verification_rolls_the_deployment_back_automatically(world, lab, adapter,
                                                                       tmp_path):
    engine, _, ids = world
    rid = approved_sigma(engine, ids[0])
    with session_scope(engine) as s:
        dep = deploy_lab(s, rid, adapter, CFG, out_dir=tmp_path / "p", now=NOW,
                         test_set=TEST_SET, verify=lambda: {"ok": False, "why": "forced"})
        assert dep.status == "failed" and dep.details["rolled_back"] is True
        assert s.get(m.Rule, rid).state == RuleState.APPROVED.value
    assert "119999" in adapter.get_rule_file(rule_file_name(rid))


def test_an_unapproved_or_tampered_rule_is_never_deployed(world, adapter, tmp_path):
    engine, _, ids = world
    draft, _ = make_sigma_rule(engine, ids[0])
    with pytest.raises(ApprovalError, match="not approved"), session_scope(engine) as s:
        deploy_lab(s, draft, adapter, CFG, out_dir=tmp_path / "p", now=NOW)
    rid = approved_sigma(engine, ids[0])
    with session_scope(engine) as s:
        s.execute(update(m.RuleVersion).where(m.RuleVersion.rule_id == rid).values(
            content="title: tampered\n"))
    with pytest.raises(ApprovalError, match="hash mismatch"), session_scope(engine) as s:
        deploy_lab(s, rid, adapter, CFG, out_dir=tmp_path / "p", now=NOW)
    with session_scope(engine) as s:                         # even with the stored hash rewritten
        s.execute(update(m.RuleVersion).where(m.RuleVersion.rule_id == rid).values(
            content_sha256=sha256_hex("title: tampered\n")))
    with pytest.raises(ApprovalError, match="different content"), session_scope(engine) as s:
        deploy_lab(s, rid, adapter, CFG, out_dir=tmp_path / "p", now=NOW)
    assert adapter.get_rule_file(rule_file_name(rid)) is None        # nothing was written


def test_indicator_bundles_share_the_lists_and_retire_cleanly(world, lab, adapter, tmp_path):
    engine, _, ids = world
    rid = approved_ioc(engine, ids[1])
    with session_scope(engine) as s:
        tests = synthesize_tests(bundle_entries(s, rid))
        art = compose_artifacts(s, rid, CFG, now=NOW)
        dep = deploy_lab(s, rid, adapter, CFG, out_dir=tmp_path / "p", now=NOW,
                         verify=replay_verifier(lab, tests, art.rule_ids))
        assert dep.status == "ok", dep.details
        assert dep.details["verification"]["ok"], dep.details["verification"]
    domains = adapter.get_list("atidep-domains")
    assert "stage.bad-host.net:" in domains and "placeholder.invalid" not in domains
    assert "1.2.3.4:" in adapter.get_list("atidep-ips")
    assert "ioc" in adapter.get_rule_file(IOC_RULE_FILE)

    with session_scope(engine) as s:
        retire_rule(s, rid, adapter, CFG, now=NOW)
        assert s.get(m.Rule, rid).state == RuleState.RETIRED.value
    assert adapter.get_list("atidep-domains").strip() == "placeholder.invalid:"
    assert "119999" in adapter.get_rule_file(IOC_RULE_FILE)


def test_the_expiry_sweep_makes_a_new_version_that_must_be_approved_again(world):
    engine, _, ids = world
    rid = approved_ioc(engine, ids[1])
    later = NOW + timedelta(days=60)                  # IPs live 30 days, domains and URLs 90
    with session_scope(engine) as s:
        res = expiry_sweep(s, CFG, now=later, benign_domains=BENIGN)
        assert [(r.rule_id, r.now_empty) for r in res] == [(rid, False)]
        assert res[0].removed >= 2 and res[0].new_version == 2
        assert s.get(m.Rule, rid).state == RuleState.DRAFT.value
    with session_scope(engine) as s:
        assert expiry_sweep(s, CFG, now=later, benign_domains=BENIGN) == []
