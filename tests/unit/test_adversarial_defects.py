import pytest

from research.adversarial.defects import default_context, evaluate_case
from tests.unit.adversarial_fixtures import GOOD, case, defect, events


@pytest.fixture(scope="module")
def ctx():
    return default_context()


def run(c, cond, ctx):
    return evaluate_case(c, cond, ctx)


# ---- a clean control passes everything in B and is only flagged by what it should be -----------------
def test_a_clean_control_is_approved_and_packaged_under_b(ctx):
    r = run(case(), "B", ctx)
    assert r.harness_error is None and r.outcome == "validated" and r.failed_gates == []
    assert r.reached_validated and r.reached_approved and r.package_ok is True
    assert r.state_final == "approved" and not r.stopped_before_approval


def test_the_same_control_under_b_v_is_approved_with_a_clean_log(ctx):
    r = run(case(), "B-V", ctx)
    assert r.harness_error is None and r.failed_gates == [] and r.reached_approved


# ---- seeded defects are stopped in B, pass through B-V (with the log showing why), accepted in C ----------
BAD_FIELD = GOOD.replace("CommandLine|contains: -enc", "ScriptBlockText|contains: -enc")
UNSUPPORTED_CONSTRUCT = GOOD.replace("condition: selection and not flt",
                                     "condition: selection | count() > 3")


@pytest.mark.parametrize("sigma,cls,gate", [
    (BAD_FIELD, "D3", "G5"),
    (GOOD.replace("title: Encoded PowerShell command line\n", ""), "D2", "G2"),
    ("title: [unterminated\n  level: high", "D1", "G1"),
])
def test_a_defective_rule_is_stopped_before_approval_under_b(ctx, sigma, cls, gate):
    c = defect(f"{cls}-99", cls, sigma, gate)
    b = run(c, "B", ctx)
    assert b.harness_error is None
    assert gate in b.failed_gates and b.expected_gate_fired
    assert b.stopped_before_approval and not b.reached_approved and b.package_ok is None
    assert b.state_final in ("draft", "blocked")
    bv = run(c, "B-V", ctx)
    assert bv.harness_error is None and gate in bv.failed_gates      # the advisory log shows it
    assert bv.reached_approved and bv.state_final == "approved"      # but nothing stops it
    cc = run(c, "C", ctx)
    assert cc.accepted_by_construction and not cc.stopped_before_approval


def test_a_rule_that_matches_a_benign_lookalike_is_stopped_by_g10(ctx):
    sigma = GOOD.replace("  flt:\n    ParentImage|endswith: \\ccmexec.exe\n", "").replace(
        "selection and not flt", "selection")
    c = defect("D9-99", "D9", sigma, "G10", assumptions=[])
    b = run(c, "B", ctx)
    assert "G10" in b.failed_gates and b.stopped_before_approval


def test_unavailable_telemetry_blocks_a_rule(ctx):
    c = defect("D5-99", "D5", GOOD, "G6", logsource="windows_powershell_script_block")
    b = run(c, "B", ctx)
    assert "G6" in b.failed_gates and b.state_final == "blocked" and b.stopped_before_approval
    assert b.opportunity_decision != "behavioral"     # the opportunity override already objected


# ---- D10: tampering after approval -----------------------------------------------------------------------
TAMPERED = GOOD.replace("CommandLine|contains: -enc", "CommandLine|contains: x")
COSMETIC = GOOD + "# a comment\n"


@pytest.mark.parametrize("tamper", [TAMPERED, COSMETIC])
def test_every_route_of_tampering_with_an_approved_rule_is_detected(ctx, tamper):
    c = defect("D10-99", "D10", GOOD, "approval-binding", tamper_sigma_yaml=tamper)
    for cond in ("B", "B-V"):
        r = run(c, cond, ctx)
        assert r.harness_error is None and r.reached_approved
        assert set(r.tamper) == {"direct_db", "direct_db_rehashed", "edit_through_application"}
        assert all(t["detected"] is True for t in r.tamper.values()), r.tamper
    c_ = run(c, "C", ctx)
    assert all(t["detected"] is False for t in c_.tamper.values())      # no approval exists in C


def test_a_tamper_that_is_not_a_change_is_neither_detected_nor_an_escape(ctx):
    """If the 'tampered' text were identical to the approved rule, the route would test nothing:
    the harness reports it as not applicable, and the integrity check rejects such a case."""
    c = defect("D10-98", "D10", GOOD, "approval-binding", tamper_sigma_yaml=GOOD)
    assert any("identical" in i for i in c.integrity_issues())
    r = run(c, "B", ctx)
    assert r.tamper["direct_db"]["detected"] is None
    assert r.tamper["direct_db"]["content_changed"] is False


# ---- integrity of case files ------------------------------------------------------------------------------
def test_integrity_checks_catch_a_misquoted_citation_and_mismatched_events():
    assert case().integrity_issues() == []
    bad = case(evidence=["this quotation is not in the report at all"])
    assert any("verbatim" in i for i in bad.integrity_issues())
    wrong = case(logsource="windows_dns_query")
    assert any("does not fit" in i for i in wrong.integrity_issues())
    ev = events()
    ev["lookalike"] = []
    assert any("look-alike" in i for i in case(events=ev).integrity_issues())


def test_case_shapes_are_enforced():
    with pytest.raises(ValueError):
        case(cls="D99", role="defective")
    with pytest.raises(ValueError):
        defect("D10-97", "D10", GOOD, "approval-binding")                # no tamper text
    with pytest.raises(ValueError):
        case(cls="D3")                                                    # a control has no class
