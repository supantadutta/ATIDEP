import json

import pytest
import yaml
from sqlalchemy import select

from app.db import models as m
from app.db.audit import verify_audit_chain
from app.db.session import session_scope
from app.services.deployment import compose_artifacts, deploy_lab
from app.services.feedback import (
    improve_rule,
    ingest_alerts,
    rule_stats,
    set_disposition,
)
from app.services.governance import GovernanceError, validate_rule
from components.c4_validation.sigma_ir import parse_rule
from components.c4_validation.tier1 import rule_matches
from components.c5_deployment.feedback import (
    Cluster,
    RuleStats,
    alert_features,
    compute_stats,
    normalise,
)
from components.c5_deployment.improvement import (
    Recommendation,
    apply_recommendations,
    check_recommendation,
    user_message,
)
from components.llm.client import ScriptedClient
from components.llm.prompts import load_prompt
from schemas.common import RuleState
from tests.events import sysmon_factory as f
from tests.unit.test_c4_governance import (  # noqa: F401  (fixtures and helpers)
    ATTACK,
    BASELINE,
    CFG,
    NOW,
    TEST_SET,
    make_sigma_rule,
)

PROMPT = load_prompt("improvement_v1")
ACME = "C:\\Program Files\\Acme\\deploy.exe"
CMD_FP = "powershell -nop -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBi"
CMD_TP = "powershell -w hidden -enc JABzAD0AWwBTAHkAcwB0AGUAbQAuAFQAZQB4AHQAIQ"


def alert(rule_id, n, *, cmd=CMD_FP, parent=ACME, user="LAB\\alice", host="WIN10-A",
          image=f.PS, ts="2026-10-02T21:00:00.000+0000"):
    return {"id": f"1759{n:06d}", "timestamp": ts, "rule": {"id": str(rule_id), "level": 10},
            "agent": {"name": host},
            "data": {"win": {"system": {"computer": host}, "eventdata": {
                "commandLine": cmd, "parentImage": parent, "user": user, "image": image,
                "hashes": "SHA256=" + "a" * 64, "secret": "must not be kept"}}}}


def rows(spec):
    """spec: list of (disposition, overrides) -> feature rows as the statistics expect them."""
    out = []
    for i, (disp, over) in enumerate(spec):
        feats = alert_features(alert(110000, i, **over))
        out.append({**feats, "disposition": disp})
    return out


# ---- statistics ----------------------------------------------------------------------------------
def test_only_the_needed_features_are_kept_from_an_alert():
    feats = alert_features(alert(110000, 1))
    assert set(feats) == {"rule_id", "level", "timestamp", "alert_id", "host", "commandLine",
                          "image", "parentImage", "user"}
    assert "hashes" not in feats and "secret" not in json.dumps(feats)
    with pytest.raises(KeyError):
        alert_features({"rule": {}})


def test_normalisation_replaces_guids_blobs_and_numbers():
    assert normalise('Run  {3F2504E0-4F89-41D3-9A0C-0305E82C3301} -p 8080 ' + "A" * 30) == \
        "run <guid> -p <n> <blob>"


def test_clusters_are_exact_or_pattern_and_only_benign_ones_are_listed():
    spec = [("false_positive", {})] * 5 + [("false_positive", {"cmd": CMD_FP + " --x 7"})] + \
           [("true_positive", {"cmd": CMD_TP, "parent": "C:\\Windows\\explorer.exe"})] * 2 + \
           [("unknown", {"user": "LAB\\bob"})]
    stats = compute_stats(rows(spec))
    assert stats.alerts == 9 and stats.by_disposition == {
        "true_positive": 2, "false_positive": 6, "unknown": 1}
    assert stats.false_positive_rate == 0.75                      # 6 of 8 dispositioned
    assert stats.per_day == {"2026-10-02": 9}
    by = {(c.kind, c.feature): c for c in stats.clusters}
    parent = by[("exact", "parentImage")]
    assert parent.value == ACME.casefold() and parent.false_positives == 6 and parent.excludable
    assert parent.field == "ParentImage" and parent.true_positives == 0
    assert by[("exact", "host")].excludable is False and by[("exact", "host")].field is None
    assert by[("pattern", "commandLine")].excludable is False         # a shape, not a value
    assert "<blob>" in by[("pattern", "commandLine")].value
    assert [c.cluster_id for c in stats.clusters] == [f"c{i}" for i in range(1, len(stats.clusters) + 1)]
    assert not any(c.value == "c:\\windows\\explorer.exe" for c in stats.clusters)   # tp > fp


def test_small_groups_and_no_dispositions_give_no_clusters_and_no_rate():
    stats = compute_stats(rows([("false_positive", {})]))             # a single false positive
    assert stats.clusters == [] and stats.false_positive_rate == 1.0
    empty = compute_stats(rows([("unknown", {})] * 4))
    assert empty.false_positive_rate is None and empty.clusters == []
    assert compute_stats([]).alerts == 0


def test_statistics_are_deterministic():
    spec = [("false_positive", {"parent": ACME}), ("false_positive", {"parent": ACME}),
            ("false_positive", {"user": "LAB\\bob"}), ("false_positive", {"user": "LAB\\bob"})]
    a, b = compute_stats(rows(spec)), compute_stats(rows(list(reversed(spec))))
    assert [c.as_dict() for c in a.clusters] == [c.as_dict() for c in b.clusters]


# ---- checking and applying recommendations -------------------------------------------------------
def stats_with(*clusters):
    s = RuleStats(alerts=10)
    s.clusters = list(clusters)
    return s


def cl(cid="c1", field="ParentImage", value="c:\\program files\\acme\\deploy.exe", fp=6, tp=0,
       excludable=True, kind="exact"):
    return Cluster(cid, kind, "parentImage", field if excludable else None, value, fp + tp, fp,
                   tp, excludable)


def rec(**kw):
    base = dict(action="add_exclusion", cluster_id="c1", field="ParentImage", modifier="exact",
                value="C:\\Program Files\\Acme\\deploy.exe", reason="benign deployment tool")
    return Recommendation(**{**base, **kw})


FIELDS = {"Image", "CommandLine", "ParentImage", "User"}


@pytest.mark.parametrize("change,why", [
    ({}, None),
    ({"cluster_id": "c9"}, "no such cluster"),
    ({"value": "C:\\Windows\\System32\\cmd.exe"}, "unchanged"),
    ({"field": "Image"}, "unchanged"),
    ({"modifier": None}, "modifier is required"),
])
def test_exclusions_must_match_a_real_cluster_unchanged(change, why):
    got = check_recommendation(rec(**change), stats_with(cl()), FIELDS)
    assert (got is None) if why is None else (why in got)


def test_exclusions_refuse_shapes_true_positives_unknown_fields_and_tiny_values():
    assert "shape" in check_recommendation(rec(), stats_with(cl(excludable=False)), FIELDS)
    assert "true positives" in check_recommendation(rec(), stats_with(cl(tp=1)), FIELDS)
    assert "not a field" in check_recommendation(rec(), stats_with(cl()), {"Image"})
    tiny = cl(value="x.e")
    assert "too short" in check_recommendation(rec(value="x.e"), stats_with(tiny), FIELDS)


def test_a_level_change_needs_a_level():
    assert "required" in check_recommendation(Recommendation(
        action="change_level", reason="too loud"), stats_with(), FIELDS)
    assert check_recommendation(Recommendation(
        action="change_level", new_level="low", reason="too loud"), stats_with(), FIELDS) is None


RULE = yaml.safe_dump({
    "title": "Encoded PowerShell", "id": "55555555-5555-4555-8555-555555555555",
    "status": "experimental", "description": "d", "references": ["https://x.example"],
    "author": "ATIDEP", "date": "2026/10/02", "tags": ["attack.execution", "attack.t1059.001"],
    "logsource": {"category": "process_creation", "product": "windows"},
    "detection": {"selection": {"Image|endswith": "\\powershell.exe", "CommandLine|contains": "-enc"},
                  "condition": "selection"},
    "falsepositives": ["admin"], "level": "high"}, sort_keys=False)


def test_applying_an_exclusion_adds_a_selection_a_condition_and_a_covering_assumption():
    stats = stats_with(cl())
    change = apply_recommendations(RULE, [rec(), rec(action="change_level", new_level="medium",
                                                     cluster_id=None, field=None, modifier=None,
                                                     value=None)], stats, [])
    doc = yaml.safe_load(change.sigma_yaml)
    assert doc["level"] == "medium"
    det = doc["detection"]
    assert det["exclusion_atidep_1"] == {"ParentImage": "c:\\program files\\acme\\deploy.exe"}
    assert det["condition"] == "(selection) and not exclusion_atidep_1"
    assert len(change.assumptions) == 1 and change.assumptions[0].covers == [
        "c:\\program files\\acme\\deploy.exe"]
    assert "6 alerts" in change.assumptions[0].justification and len(change.descriptions) == 2
    # a second exclusion gets the next name and keeps the first
    second = apply_recommendations(change.sigma_yaml, [rec(cluster_id="c2")],
                                   stats_with(cl(), cl("c2")), change.assumptions)
    d2 = yaml.safe_load(second.sigma_yaml)["detection"]
    assert "exclusion_atidep_2" in d2 and d2["condition"].endswith("and not exclusion_atidep_2")
    ir = parse_rule(second.sigma_yaml)                     # still inside the supported subset
    assert ir.category == "process_creation"


def test_modifiers_are_written_into_the_field_key_and_list_conditions_are_refused():
    out = apply_recommendations(RULE, [rec(modifier="endswith")], stats_with(cl()), [])
    assert "ParentImage|endswith" in yaml.safe_load(out.sigma_yaml)["detection"]["exclusion_atidep_1"]
    listy = yaml.safe_load(RULE)
    listy["detection"]["condition"] = ["selection"]
    with pytest.raises(ValueError, match="single-string"):
        apply_recommendations(yaml.safe_dump(listy), [rec()], stats_with(cl()), [])


def test_the_agent_prompt_has_the_rule_and_aggregates_in_a_delimited_block():
    msg = user_message(RULE, stats_with(cl()), PROMPT, rule_age_days=12)
    marker = msg.split("<<<DATA ", 1)[1].split(">>>", 1)[0]
    assert msg.count(f"<<<END DATA {marker}>>>") == 1 and '"rule_age_days": 12' in msg
    assert "secret" not in msg and "must not be kept" not in msg


# ---- the whole loop ------------------------------------------------------------------------------
def deployed_with_alerts(engine, rid, adapter, tmp_path):
    with session_scope(engine) as s:
        dep = deploy_lab(s, rid, adapter, CFG, out_dir=tmp_path, now=NOW)
        assert dep.status == "ok"
        ids = compose_artifacts(s, rid, CFG, now=NOW).rule_ids
    return ids[0]


def test_alerts_are_ingested_once_dispositioned_and_summarised(sigma_rule, api, tmp_path):
    engine, rid = sigma_rule
    stub, adapter = api
    wid = deployed_with_alerts(engine, rid, adapter, tmp_path)
    batch = [alert(wid, i) for i in range(6)] + [alert(wid, 10, parent="C:\\Windows\\explorer.exe",
                                                       cmd=CMD_TP)] + [alert(999999, 20)]
    with session_scope(engine) as s:
        assert ingest_alerts(s, rid, batch) == 7                    # the foreign rule's is ignored
        assert s.get(m.Rule, rid).state == RuleState.MONITORED.value
        assert ingest_alerts(s, rid, batch) == 0                    # replaying adds nothing
        results = s.scalars(select(m.DetectionResult).order_by(m.DetectionResult.id)).all()
        assert len(results) == 7 and results[0].features["parentImage"] == ACME
        for r in results[:6]:
            set_disposition(s, r.id, "false_positive", "analyst1", "Acme deployment")
        set_disposition(s, results[6].id, "true_positive", "analyst1")
        stats = rule_stats(s, rid)
        assert stats.alerts == 7 and stats.false_positive_rate == round(6 / 7, 3)
        assert any(c.field == "ParentImage" and c.excludable and c.false_positives == 6
                   for c in stats.clusters)
        with pytest.raises(GovernanceError, match="disposition"):
            set_disposition(s, results[0].id, "maybe", "analyst1")
        with pytest.raises(GovernanceError, match="analyst"):
            set_disposition(s, results[0].id, "true_positive", " ")
        assert verify_audit_chain(s).ok


def test_ingesting_needs_a_deployment(sigma_rule):
    engine, rid = sigma_rule
    with session_scope(engine) as s, pytest.raises(GovernanceError, match="no successful lab"):
        ingest_alerts(s, rid, [])


def test_the_improvement_loop_removes_the_false_positive_and_keeps_the_true_positive(
        sigma_rule, api, tmp_path):
    engine, rid = sigma_rule
    stub, adapter = api
    wid = deployed_with_alerts(engine, rid, adapter, tmp_path)
    batch = [alert(wid, i) for i in range(6)] + [
        alert(wid, 10 + i, parent="C:\\Windows\\explorer.exe", cmd=CMD_TP) for i in range(2)]
    with session_scope(engine) as s:
        ingest_alerts(s, rid, batch)
        for r in s.scalars(select(m.DetectionResult).order_by(m.DetectionResult.id)):
            set_disposition(s, r.id, "false_positive" if r.features["parentImage"] == ACME
                            else "true_positive", "analyst1")
        stats = rule_stats(s, rid)
    parent = next(c for c in stats.clusters if c.field == "ParentImage" and c.excludable)
    image = next(c for c in stats.clusters if c.field == "Image")
    assert parent.true_positives == 0 and image.true_positives == 2
    answer = json.dumps({"recommendations": [
        {"action": "add_exclusion", "cluster_id": parent.cluster_id, "field": "ParentImage",
         "modifier": "exact", "value": parent.value, "reason": "Acme deployment tool"},
        {"action": "add_exclusion", "cluster_id": image.cluster_id, "field": "Image",
         "modifier": "exact", "value": image.value, "reason": "all powershell"},   # has true positives
        {"action": "add_exclusion", "cluster_id": "c99", "field": "User", "modifier": "exact",
         "value": "x", "reason": "invented"},
        {"action": "request_telemetry", "reason": "script block text would help"}]})
    client = ScriptedClient([answer])
    with session_scope(engine) as s:
        rep = improve_rule(s, rid, client, PROMPT, CFG, now=NOW, seed=3)
        assert [r.action for r in rep.accepted] == ["add_exclusion", "request_telemetry"]
        assert len(rep.rejected) == 2 and "true positives" in rep.rejected[0][1]
        assert [r.action for r in rep.applied] == ["add_exclusion"] and rep.new_version == 2
        rule = s.get(m.Rule, rid)
        assert rule.state == RuleState.DRAFT.value                    # approval voided
        v2 = s.scalars(select(m.RuleVersion).where(m.RuleVersion.rule_id == rid,
                                                   m.RuleVersion.version == 2)).one()
        assert v2.origin == "improvement" and "exclusion_atidep_1" in v2.content
        assert any(a["covers"] == [parent.value] for a in v2.assumptions)
        run = s.scalars(select(m.ModelRun).where(m.ModelRun.agent == "improvement")).one()
        assert run.schema_valid and run.seed == 3
        assert any(e.action == "improvement.applied" for e in s.scalars(select(m.AuditEvent)))
    assert "secret" not in client.requests[0].user                    # raw fields never reached it

    with session_scope(engine) as s:                                  # back through every gate
        out = validate_rule(s, rid, cfg=CFG, attack=ATTACK, test_set=TEST_SET, baseline=BASELINE)
        assert out.outcome.value == "validated", [(r.gate.value, r.message) for r in out.results
                                                  if r.status.value != "passed"]
        content = s.scalars(select(m.RuleVersion).where(
            m.RuleVersion.rule_id == rid, m.RuleVersion.version == 2)).one().content
    ir = parse_rule(content)
    fp_event = f.process_create(7001, f.PS, CMD_FP, ACME)
    tp_event = f.process_create(7002, f.PS, CMD_TP, "C:\\Windows\\explorer.exe")
    assert not rule_matches(ir, fp_event, CFG.wazuh_mapping)          # the false positive is gone
    assert rule_matches(ir, tp_event, CFG.wazuh_mapping)              # the true positive remains


def test_nothing_is_asked_without_alerts_and_only_live_rules_are_improved(sigma_rule, api,
                                                                         tmp_path):
    engine, rid = sigma_rule
    stub, adapter = api
    client = ScriptedClient([])
    with session_scope(engine) as s, pytest.raises(GovernanceError, match="only a live rule"):
        improve_rule(s, rid, client, PROMPT, CFG, now=NOW)            # approved, not deployed
    deployed_with_alerts(engine, rid, adapter, tmp_path)
    with session_scope(engine) as s:
        rep = improve_rule(s, rid, client, PROMPT, CFG, now=NOW)
        assert rep.skipped and "no alerts" in rep.skipped
    assert client.requests == []                                      # no tokens spent


def test_indicator_bundles_are_not_tuned(ioc_rule, api, tmp_path):
    engine, rid = ioc_rule
    stub, adapter = api
    with session_scope(engine) as s:
        assert deploy_lab(s, rid, adapter, CFG, out_dir=tmp_path, now=NOW).status == "ok"
    client = ScriptedClient([])
    with session_scope(engine) as s:
        rep = improve_rule(s, rid, client, PROMPT, CFG, now=NOW)
        assert rep.skipped and "expiry sweep" in rep.skipped and client.requests == []


def test_a_model_that_returns_nothing_valid_changes_nothing(sigma_rule, api, tmp_path):
    engine, rid = sigma_rule
    stub, adapter = api
    wid = deployed_with_alerts(engine, rid, adapter, tmp_path)
    with session_scope(engine) as s:
        ingest_alerts(s, rid, [alert(wid, i) for i in range(3)])
        rep = improve_rule(s, rid, ScriptedClient(["nonsense"] * 3), PROMPT, CFG, now=NOW)
        assert rep.error and rep.applied == [] and rep.new_version is None
        assert s.get(m.Rule, rid).state == RuleState.MONITORED.value
