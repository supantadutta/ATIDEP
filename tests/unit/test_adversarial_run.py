import json

import pytest

from research.adversarial.cases import CaseSet, InjectionCase, dump_case, load_case_set
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
    m = run(cases, out, freeze_path=None, require_freeze=False, allow_unreviewed=True, ctx=ctx,
            log=lambda *_: None)
    assert m["counts"] == {"run": 9, "skipped_existing": 0}           # 3 cases x 3 conditions
    raw = json.loads((out / "raw/rules/B/D2-01.json").read_text())
    assert raw["case_id"] == "D2-01" and "G2" in raw["failed_gates"]
    assert raw["stopped_before_approval"] is True
    assert set(raw["_stamp"]) == {"freeze_combined_sha256", "code_combined_sha256", "case_sha256"}
    assert (out / "summary.json").exists() and (out / "summary.md").exists()
    assert m["freeze"]["checked"] is False and m["freeze_required"] is False
    assert m["preregistered"] is False and m["review_gaps"]["unreviewed"]
    assert len(m["code_sha256"]) > 20 and "research/adversarial/run.py" in m["code_sha256"]
    before = (out / "raw/rules/B/D2-01.json").read_text()
    m2 = run(cases, out, freeze_path=None, require_freeze=False, allow_unreviewed=True, ctx=ctx,
             log=lambda *_: None)
    assert m2["counts"] == {"run": 0, "skipped_existing": 9}
    assert (out / "raw/rules/B/D2-01.json").read_text() == before
    manifest = json.loads((out / "run_manifest.json").read_text())
    assert len(manifest["invocations"]) == 2 and manifest["preregistered"] is False
    with pytest.raises(FileExistsError):
        _write_once(out / "raw/rules/B/D2-01.json", {})
    s = json.loads((out / "summary.json").read_text())
    assert s["conditions"]["B"]["d1_d9"]["escapes"] == 0
    assert s["completeness"]["complete"] is True
    inj = s["injection"]["B"]
    assert inj["n"] == 1 and inj["n_cases"] == 1 and not inj["harness_errors"]
    raw_inj = json.loads((out / "raw/injection/B/INJA-01.json").read_text())
    assert raw_inj["null_run"] and raw_inj["succeeded_without_compliance"] is not None


def test_a_resumed_run_refuses_records_from_another_case_version(tmp_path, ctx):
    cases = tiny_set(tmp_path)
    out = tmp_path / "res"
    run(cases, out, freeze_path=None, require_freeze=False, allow_unreviewed=True, ctx=ctx,
        conditions=("C",), log=lambda *_: None)
    p = cases / "controls" / "CTL9-01.yaml"
    p.write_text(p.read_text().replace("why: fixture", "why: fixture, edited"))
    with pytest.raises(SystemExit, match="different"):
        run(cases, out, freeze_path=None, require_freeze=False, allow_unreviewed=True, ctx=ctx,
            conditions=("C",), log=lambda *_: None)


def test_a_run_refuses_while_cases_are_unreviewed(tmp_path, ctx):
    cases = tiny_set(tmp_path)
    with pytest.raises(SystemExit, match="review"):
        run(cases, tmp_path / "o", freeze_path=None, require_freeze=False, ctx=ctx,
            log=lambda *_: None)
    assert not (tmp_path / "o" / "raw").exists()


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


def test_a_matching_freeze_manifest_allows_the_run_only_on_the_frozen_cases(tmp_path, ctx,
                                                                          monkeypatch):
    from research import freeze
    from research.adversarial import run as run_mod
    cases = tiny_set(tmp_path)
    good = tmp_path / "freeze.json"
    good.write_text(json.dumps(freeze.make("test")))
    other = check_freeze(good, load_case_set(cases), cases)
    assert not other["matches"] and other["differences"]["cases_dir"]
    monkeypatch.setattr(run_mod, "FROZEN_CASES", cases)
    assert check_freeze(good, load_case_set(cases), cases)["matches"]
    m = run(cases, tmp_path / "o3", freeze_path=good, allow_unreviewed=True, ctx=ctx,
            log=lambda *_: None)
    assert m["freeze"]["matches"] and m["counts"]["run"] == 9
    assert m["preregistered"] is False                         # the tiny set has no reviews


def test_a_freeze_manifest_without_code_does_not_match(tmp_path):
    from research import freeze
    man = freeze.make("test")
    assert any(k.startswith("components/c4_validation/") for k in man["files"])
    assert "research/adversarial/injection.py" in man["files"]
    man["files"] = {k: v for k, v in man["files"].items() if not k.endswith(".py")}
    p = tmp_path / "f.json"
    p.write_text(json.dumps(man))
    fr = check_freeze(p, small_set())
    assert not fr["matches"] and fr["differences"]["code_not_frozen"]


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


# ---- completeness, by-construction cells, D10 denominators, injection columns -------------------
def test_a_result_set_missing_a_case_is_flagged_incomplete():
    cs = small_set()
    b = {"D2-01": rec("D2-01", "D2", "B", failed=["G2"], hit=True)}
    s = summarise(cs, {"B": b}, {})
    assert s["completeness"]["complete"] is False
    assert "D2-02" in s["completeness"]["missing"]["B"] and "C" in s["completeness"]["missing"]
    assert "INCOMPLETE RESULT SET" in render_markdown(s)


def test_by_construction_rates_carry_no_confidence_bound_and_no_other_gate_column():
    cs = small_set()
    cv = {"D2-01": rec("D2-01", "D2", "C", construction=True, outcome="flagged", failed=["G2"]),
          "CTL9-01": rec("CTL9-01", "NONE", "C", role="control", construction=True,
                         outcome="passed")}
    c = summarise(cs, {"C": cv}, {})["conditions"]["C"]
    assert c["d1_d9"]["escape"]["by_construction"] and c["d1_d9"]["escape"]["upper_95"] is None
    assert c["d1_d9"]["stopped_by_a_different_gate"] is None
    fr = c["controls"]["false_rejection"]
    assert fr["k"] == 0 and fr["by_construction"] and fr["upper_95"] is None
    assert c["d1_d9"]["gate_miss"]["upper_95"] is not None          # measured post hoc
    text = render_markdown(summarise(cs, {"C": cv}, {}))
    assert "(by construction)" in text and "| n/a |" in text


def test_a_d10_case_whose_base_rule_was_not_approved_stays_in_the_denominator():
    cs = small_set()
    b = {"D10-01": rec("D10-01", "D10", "B", approved=True, tamper=tam(True, True, True)),
         "D10-02": rec("D10-02", "D10", "B", tamper=tam(None, None, None))}
    d10 = summarise(cs, {"B": b}, {})["conditions"]["B"]["d10"]
    assert d10["n"] == 2 and d10["n_applicable"] == 1
    assert d10["base_rule_not_approved_ids"] == ["D10-02"] and d10["escaped_ids"] == []


def test_injection_reports_success_with_and_without_compliance_and_leaves_out_the_inexpressible():
    cs = CaseSet()
    cs.injections = [InjectionCase.model_validate(dict(INJ, id=f"INJA-0{i}")) for i in (1, 2, 3, 4)]

    def r(cid, won, alone, expressible=True, error=None):
        return {"case_id": cid, "family": "f", "goal": "g", "attack_succeeded": won,
                "succeeded_without_compliance": alone,
                "attributable_to_compliance": won and not alone, "expressible": expressible,
                "marker_survived_sanitiser": True, "pipeline_error": None,
                "harness_error": error, "stopped_by_schema": [], "intermediate_only": [],
                "stage_errors": []}
    k = summarise(cs, {}, {"C": {"INJA-01": r("INJA-01", True, False),
                                 "INJA-02": r("INJA-02", True, True),
                                 "INJA-03": r("INJA-03", False, False, expressible=False),
                                 "INJA-04": r("INJA-04", False, False, error="boom")}})
    c = k["injection"]["C"]
    assert c["n"] == 2 and c["n_cases"] == 4
    assert (c["attack_success"]["k"], c["success_without_compliance"]["k"],
            c["attributable_to_compliance"]["k"]) == (2, 1, 1)
    assert c["not_expressible_in_condition"] == ["INJA-03"]
    assert c["harness_errors"] == {"INJA-04": "boom"}
    assert c["attack_success_worst_case"]["k"] == 3 and c["by_construction"] is True
    text = render_markdown(k)
    assert "without compliance" in text and "INJA-04" in text and "Not expressible" in text


def test_review_gaps_and_set_aside_reviewers(tmp_path):
    from research.adversarial.review import apply, review_gaps
    cases = tiny_set(tmp_path)
    assert review_gaps(load_case_set(cases))["unreviewed"] == ["D2-01", "CTL9-01", "INJA-01"]
    revs = tmp_path / "reviews"
    revs.mkdir()

    def doc(name, reviewer, verdicts, read_other=False):
        (revs / name).write_text(json.dumps({"reviewer": reviewer, "role": "primary",
                                             "read_other_files": read_other, "reviews": [
                                                 {"id": i, "verdict": v} for i, v in verdicts]}))
    ids = ("D2-01", "CTL9-01", "INJA-01")
    doc("a.json", "R1", [(i, "present") for i in ids])
    doc("b.json", "R2", [(i, "present") for i in ids[:2]] + [("INJA-01", "absent")])
    doc("c.json", "R9", [(i, "absent") for i in ids], read_other=True)     # set aside
    summary = apply(cases, revs)
    assert summary["set_aside"] == ["c.json"] and summary["excluded"] == []
    assert summary["needs_adjudication"] == ["INJA-01"]
    gaps = review_gaps(load_case_set(cases))
    assert gaps["unreviewed"] == ["INJA-01"] and not gaps["integrity"]
