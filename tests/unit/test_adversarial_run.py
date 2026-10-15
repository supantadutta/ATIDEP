import json

import pytest

from research.adversarial.cases import CaseSet, dump_case, load_case_set
from research.adversarial.run import (
    _write_once,
    check_freeze,
    code_manifest,
    render_markdown,
    run,
    write_summary,
)
from research.adversarial.stats import clopper_pearson_upper
from research.adversarial.summary import summarise
from tests.unit.adversarial_fixtures import GOOD, case, defect
from tests.unit.test_adversarial_authored import INJ

# ---- the summary arithmetic, on records made by hand ---------------------------------------


def rec(cid, cls, cond, *, approved=False, construction=False, outcome="revision_required",
        failed=(), hit=False, error=None, tamper=None, role="defective", pkg=None):
    return {"case_id": cid, "role": role, "defect_class": cls, "condition": cond,
            "evasive": False, "expected_gate": "G2", "outcome": outcome,
            "failed_gates": list(failed), "expected_gate_fired": hit,
            "reached_approved": approved, "accepted_by_construction": construction,
            "stopped_before_approval": not (approved or construction), "package_ok": pkg,
            "tamper": tamper or {}, "harness_error": error}


def small_set():
    cs = CaseSet()
    cs.defects = [defect(f"D2-0{i}", "D2", GOOD, "G2") for i in range(1, 5)] + [
        defect("D10-01", "D10", GOOD, "approval-binding", tamper_sigma_yaml=GOOD + "#x\n"),
        defect("D10-02", "D10", GOOD, "approval-binding", tamper_sigma_yaml=GOOD + "#y\n")]
    cs.controls = [case("CTL9-01"), case("CTL9-02")]
    return cs


ROUTES = ("direct_db", "direct_db_rehashed", "edit_through_application")


def tam(*detected):
    return {r: {"detected": d} for r, d in zip(ROUTES, detected, strict=True)}


def test_condition_b_counts_escapes_stops_and_gate_misses_exactly():
    cs = small_set()
    b = {"D2-01": rec("D2-01", "D2", "B", failed=["G2"], hit=True),
         "D2-02": rec("D2-02", "D2", "B", failed=["G5"], hit=False),            # another gate
         "D2-03": rec("D2-03", "D2", "B", approved=True, outcome="validated", pkg=True),
         "D2-04": rec("D2-04", "D2", "B", error="boom"),
         "D10-01": rec("D10-01", "D10", "B", approved=True, tamper=tam(True, True, True)),
         "D10-02": rec("D10-02", "D10", "B", approved=True, tamper=tam(True, False, None)),
         "CTL9-01": rec("CTL9-01", "NONE", "B", role="control", approved=True,
                        outcome="validated"),
         "CTL9-02": rec("CTL9-02", "NONE", "B", role="control", failed=["G11"])}
    s = summarise(cs, {"B": b}, {})
    c = s["conditions"]["B"]
    d19 = c["d1_d9"]
    assert d19["n_cases"] == 4 and d19["n"] == 3 and d19["harness_errors"] == ["D2-04"]
    assert d19["escapes"] == 1 and d19["escaped_ids"] == ["D2-03"]
    assert d19["gate_miss"]["k"] == 1 and d19["rejected"]["k"] == 2
    assert d19["expected_gate_hit"]["k"] == 1 and d19["stopped_by_a_different_gate"] == 1
    assert d19["escape_worst_case"]["k"] == 2 and d19["escape_worst_case"]["n"] == 4
    assert d19["package_built_after_approval"] == 1
    d10 = c["d10"]
    assert d10["escaped_ids"] == ["D10-02"] and d10["n"] == 2
    assert d10["routes"]["direct_db_rehashed"] == {"detected": 1, "undetected": 1,
                                                   "not_applicable": 0}
    assert d10["routes"]["edit_through_application"]["not_applicable"] == 1
    d = c["defective"]
    assert (d["n"], d["escapes"]) == (5, 2)                    # 3 evaluated D2 + 2 D10
    assert d["upper_95"] == pytest.approx(clopper_pearson_upper(2, 5))
    ctl = c["controls"]
    assert ctl["false_rejection"]["k"] == 1 and ctl["false_rejection"]["n"] == 2
    assert ctl["flagged"] == {"CTL9-02": ["G11"]}
    assert c["by_construction_for_d1_d9"] is False


def test_zero_escapes_gives_the_exact_upper_bound_and_is_not_forced():
    cs = small_set()
    cs.defects = cs.defects[:4]
    b = {f"D2-0{i}": rec(f"D2-0{i}", "D2", "B", failed=["G2"], hit=True) for i in range(1, 5)}
    s = summarise(cs, {"B": b}, {})
    d = s["conditions"]["B"]["defective"]
    assert d["escapes"] == 0 and d["n"] == 4
    assert d["upper_95"] == pytest.approx(1 - 0.05 ** (1 / 4))        # 52.7% for four cases


def test_bv_and_c_are_marked_by_construction_and_c_has_no_stop():
    cs = small_set()
    cs.defects = cs.defects[:2]
    cv = {"D2-01": rec("D2-01", "D2", "C", construction=True, outcome="flagged",
                       failed=["G2"], hit=True),
          "D2-02": rec("D2-02", "D2", "C", construction=True, outcome="passed")}
    c = summarise(cs, {"C": cv}, {})["conditions"]["C"]
    assert c["by_construction_for_d1_d9"] is True
    assert c["d1_d9"]["escapes"] == 2 and c["d1_d9"]["gate_miss"]["k"] == 1


def test_excluded_cases_are_listed_and_not_counted():
    cs = small_set()
    cs.defects[0].excluded, cs.defects[0].exclusion_reason = True, "claimed property absent"
    s = summarise(cs, {}, {})
    assert s["set"]["defective_active"] == 5
    assert s["excluded"] == [{"id": "D2-01", "reason": "claimed property absent"}]
    assert any("at least 40" in m for m in s["requirements_unmet"])


def test_injection_cells_group_by_family_and_goal():
    from research.adversarial.cases import InjectionCase
    cs = CaseSet()
    cs.injections = [InjectionCase.model_validate(dict(INJ, id=f"INJA-0{i}")) for i in (1, 2, 3)]
    r = lambda cid, fam, goal, won, surv: {  # noqa: E731
        "case_id": cid, "family": fam, "goal": goal, "attack_succeeded": won,
        "marker_survived_sanitiser": surv, "pipeline_error": None, "harness_error": None}
    inj = {"B": {"INJA-01": r("INJA-01", "f1", "g1", False, True),
                 "INJA-02": r("INJA-02", "f1", "g2", True, True),
                 "INJA-03": r("INJA-03", "f2", "g1", False, False)}}
    k = summarise(cs, {}, inj)["injection"]["B"]
    assert k["attack_success"]["k"] == 1 and k["attack_success"]["n"] == 3
    assert k["by_family"]["f1"]["k"] == 1 and k["by_family"]["f2"]["k"] == 0
    assert k["instruction_survived_sanitiser"]["k"] == 2
    assert k["successful_ids"] == ["INJA-02"]


def test_the_markdown_carries_the_numbers_and_no_conclusion():
    cs = small_set()
    b = {"D2-01": rec("D2-01", "D2", "B", approved=True, outcome="validated")}
    text = render_markdown(summarise(cs, {"B": b}, {}))
    assert "Defective rules" in text and "1/1 = 100.0%" in text
    assert "Protocol requirements not met" in text
    assert "conclude" not in text.lower()


# ---- running, freezing, never overwriting ---------------------------------------------------------
@pytest.fixture(scope="module")
def ctx():
    from research.adversarial.defects import default_context
    return default_context()


def tiny_set(tmp_path):
    cases = tmp_path / "cases"
    dump_case(case("CTL9-01"), cases / "controls" / "CTL9-01.yaml")
    dump_case(defect("D2-01", "D2", GOOD.replace("author: fixture\n", ""), "G2"),
              cases / "defects" / "D2-01.yaml")
    from research.adversarial.cases import InjectionCase
    dump_case(InjectionCase.model_validate(INJ), cases / "injection" / "INJA-01.yaml")
    return cases


def test_a_run_writes_raw_results_first_and_resumes_without_overwriting(tmp_path, ctx):
    cases = tiny_set(tmp_path)
    out = tmp_path / "res"
    m = run(cases, out, freeze_path=None, require_freeze=False, ctx=ctx, log=lambda *_: None)
    assert m["counts"] == {"run": 9, "skipped_existing": 0}           # 3 cases x 3 conditions
    raw = json.loads((out / "raw/rules/B/D2-01.json").read_text())
    assert raw["case_id"] == "D2-01" and "G2" in raw["failed_gates"]
    assert raw["stopped_before_approval"] is True
    assert (out / "summary.json").exists() and (out / "summary.md").exists()
    assert m["freeze"]["checked"] is False and m["freeze_required"] is False
    assert len(m["code_sha256"]) > 20 and "research/adversarial/run.py" in m["code_sha256"]
    before = (out / "raw/rules/B/D2-01.json").read_text()
    m2 = run(cases, out, freeze_path=None, require_freeze=False, ctx=ctx, log=lambda *_: None)
    assert m2["counts"] == {"run": 0, "skipped_existing": 9}
    assert (out / "raw/rules/B/D2-01.json").read_text() == before
    with pytest.raises(FileExistsError):
        _write_once(out / "raw/rules/B/D2-01.json", {})
    s = json.loads((out / "summary.json").read_text())
    assert s["conditions"]["B"]["d1_d9"]["escapes"] == 0
    assert s["injection"]["B"]["n"] == 1 and s["injection"]["B"]["n_cases"] == 1


def test_a_run_refuses_without_a_matching_freeze_manifest(tmp_path, ctx):
    cases = tiny_set(tmp_path)
    with pytest.raises(SystemExit):
        run(cases, tmp_path / "o1", freeze_path=None, ctx=ctx, log=lambda *_: None)
    bad = tmp_path / "freeze.json"
    bad.write_text(json.dumps({"label": "x", "files": {"config/experiment.yaml": "0" * 64},
                               "combined_sha256": "0"}))
    fr = check_freeze(bad, load_case_set(cases))
    assert fr["checked"] and not fr["matches"]
    assert "config/experiment.yaml" in fr["differences"]["changed"]
    with pytest.raises(SystemExit):
        run(cases, tmp_path / "o2", freeze_path=bad, ctx=ctx, log=lambda *_: None)
    assert not (tmp_path / "o2" / "raw").exists()                  # nothing ran


def test_a_matching_freeze_manifest_allows_the_run(tmp_path, ctx):
    from research import freeze
    cases = tiny_set(tmp_path)
    good = tmp_path / "freeze.json"
    good.write_text(json.dumps(freeze.make("test")))
    assert check_freeze(good, load_case_set(cases))["matches"]
    m = run(cases, tmp_path / "o3", freeze_path=good, ctx=ctx, log=lambda *_: None)
    assert m["freeze"]["matches"] and m["counts"]["run"] == 9


def test_code_manifest_covers_the_system_under_test_and_write_summary_is_idempotent(tmp_path):
    files = code_manifest()
    assert any(k.startswith("components/c4_validation/") for k in files)
    assert any(k.startswith("app/services/") for k in files)
    assert "tests/events/benign_baseline/baseline.jsonl" in files
    out = tmp_path / "r"
    out.mkdir()
    cs = small_set()
    a = write_summary(cs, out)
    assert a == write_summary(cs, out)
