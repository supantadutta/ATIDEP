import json

import pytest
import yaml

from research.adversarial.authored import import_journal
from research.adversarial.cases import load_case_set
from research.adversarial.review import apply, batches, decide, main, prepare, reviewer_view
from tests.unit.test_adversarial_authored import CASE, INJ, journal


def test_decide_follows_the_pre_declared_rule():
    assert decide(["present", "present"], issues=[]) == (False, "", False)
    assert decide(["present", "unclear"], issues=[]) == (False, "", False)         # doubt keeps it
    assert decide(["unclear", "unclear"], issues=[]) == (False, "", False)
    assert decide(["absent", "absent"], issues=[])[:1] == (True,)
    assert decide(["absent", "present"], issues=[]) == (False, "", True)           # adjudicate
    assert decide(["absent", "present", "present"], issues=[]) == (False, "", False)
    assert decide(["absent", "present", "absent"], issues=[])[0] is True
    out = decide(["present", "present"], issues=["an evidence quotation is not verbatim"])
    assert out[0] is True and out[1].startswith("mechanical integrity")
    with pytest.raises(ValueError):
        decide(["maybe", "present"], issues=[])


@pytest.fixture
def cases(tmp_path):
    ctrl = dict(CASE, id="CTL1-01", role="control", defect_class="NONE", expected_gate="none")
    j = journal(tmp_path, [{"type": "result", "key": "a", "result": {"cases": [CASE, ctrl]}},
                           {"type": "result", "key": "b", "result": {"reports": [INJ]}}])
    import_journal(j, tmp_path / "raw", tmp_path / "cases")
    return tmp_path / "cases"


def test_reviewers_do_not_see_the_authors_opinion(cases, tmp_path):
    cs = load_case_set(cases)
    view = reviewer_view(cs.defects[0])
    assert not {"why", "evasive", "review", "excluded"} & set(view)
    assert "defect_class" in view and "sigma_yaml" in view
    assert "expected_defence" not in reviewer_view(cs.injections[0])
    plan = prepare(cases, tmp_path / "rin")
    assert plan == {"D1": ["D1-01"], "CTL1a": ["CTL1-01"], "INJA": ["INJA-01"]}
    assert "why" not in yaml.safe_load((tmp_path / "rin" / "D1-01.yaml").read_text())


def test_batches_split_a_control_set_in_halves(cases):
    cs = load_case_set(cases)
    cs.controls = [cs.controls[0].model_copy(update={"id": f"CTL1-{i:02d}"}) for i in range(1, 13)]
    plan = batches(cs)
    assert plan["CTL1a"] == [f"CTL1-{i:02d}" for i in range(1, 7)]
    assert plan["CTL1b"] == [f"CTL1-{i:02d}" for i in range(7, 13)]


def write_review(d, name, reviewer, role, items):
    (d / name).write_text(json.dumps({"reviewer": reviewer, "role": role, "reviews": [
        {"id": i, "verdict": v, "confidence": 4, "reasoning": "r", "events_ok": True,
         "incidental_issues": notes} for i, v, notes in items]}))


def test_apply_excludes_only_by_the_rule_and_keeps_split_votes_for_a_third(cases, tmp_path):
    rd = tmp_path / "reviews"
    rd.mkdir()
    write_review(rd, "1.json", "R1", "primary",
                 [("D1-01", "absent", ["x"]), ("CTL1-01", "present", []),
                  ("INJA-01", "present", [])])
    write_review(rd, "2.json", "R2", "primary",
                 [("D1-01", "present", []), ("CTL1-01", "present", []),
                  ("INJA-01", "unclear", [])])
    s = apply(cases, rd)
    assert s["needs_adjudication"] == ["D1-01"] and s["excluded"] == []     # one "absent" only
    assert s["split_votes"] == [{"id": "INJA-01", "verdicts": ["present", "unclear"]}]
    write_review(rd, "3.json", "R3", "adjudicator", [("D1-01", "absent", [])])
    s = apply(cases, rd)
    assert [e["id"] for e in s["excluded"]] == ["D1-01"]
    assert "2 of 3" in s["excluded"][0]["reason"]
    cs = load_case_set(cases)
    d1 = cs.defects[0]
    assert d1.excluded and len(d1.review["verdicts"]) == 3
    assert cs.active_defects() == [] and len(cs.active_controls()) == 1
    assert s["incidental"]["D1-01"] == ["x"]


def test_cases_without_two_reviewers_are_reported_and_the_cli_exits_non_zero(cases, tmp_path):
    rd = tmp_path / "reviews"
    rd.mkdir()
    write_review(rd, "1.json", "R1", "primary", [("D1-01", "present", [])])
    assert apply(cases, rd)["unreviewed"] == ["D1-01", "CTL1-01", "INJA-01"]
    assert main(["apply", str(rd), "--cases", str(cases)]) == 1


def test_blind_inputs_hide_class_gate_role_and_order_and_keep_a_key(cases, tmp_path):
    from research.adversarial.review import blind_agreement, prepare_blind
    cs = load_case_set(cases)
    plan = prepare_blind(cases, tmp_path / "blind", seed=1)
    key = json.loads((tmp_path / "blind" / "key.json").read_text())
    assert sorted(key.values()) == ["CTL1-01", "D1-01"] and sorted(key) == ["B001", "B002"]
    assert plan == {"BL1": ["B001", "B002"]}
    for label in key:
        view = yaml.safe_load((tmp_path / "blind" / f"{label}.yaml").read_text())
        assert set(view) == {"id", "report_text", "evidence", "logsource", "techniques",
                             "sigma_yaml", "assumptions", "events"}
    rd = tmp_path / "blind_reviews"
    rd.mkdir()
    inv = {v: k for k, v in key.items()}
    (rd / "1.json").write_text(json.dumps({"reviews": [
        {"label": inv["D1-01"], "gates_that_should_stop": ["G1"]},
        {"label": inv["CTL1-01"], "gates_that_should_stop": []}]}))
    (rd / "2.json").write_text(json.dumps({"reviews": [
        {"label": inv["D1-01"], "gates_that_should_stop": []},
        {"label": inv["CTL1-01"], "gates_that_should_stop": []}]}))
    out = blind_agreement(key, cs, rd)
    assert out["per_class"]["D1"]["claimed_gate_named_by_one"] == 1
    assert out["per_class"]["NONE"]["no_gate_named_by_both"] == 1
    assert out["defective_with_no_gate_named_by_both_blind_reviewers"] == []
