"""End to end on the real manager: Sigma rules and IOC bundles produced by the pipeline are
deployed alone, replayed, and judged by gates G8-G11 at tier 2."""

from app.db.session import session_scope
from app.services.governance import validate_rule
from schemas.validation_result import GateId, GateStatus, Outcome
from tests.unit.test_c4_governance import (  # noqa: F401  (fixtures and helpers)
    ATTACK,
    BASELINE,
    CFG,
    TEST_SET,
    make_ioc,
    make_sigma_rule,
    world,
)


def test_a_sigma_rule_is_judged_at_tier_2_and_the_tiers_agree(world, lab):  # noqa: F811
    engine, _, ids = world
    rid, _ = make_sigma_rule(engine, ids[0])
    with session_scope(engine) as s:
        out = validate_rule(s, rid, cfg=CFG, attack=ATTACK, test_set=TEST_SET,
                            baseline=BASELINE, lab=lab)
    assert out.outcome is Outcome.VALIDATED, [(r.gate.value, r.message) for r in out.results
                                              if r.status is not GateStatus.PASSED]
    assert {r.tier for r in out.results if r.gate in (GateId.G8, GateId.G9, GateId.G10,
                                                      GateId.G11)} == {2}
    ev = out.details["events"]
    assert ev["tiers_run"] == [1, 2] and ev["fidelity_disagreements"] == []
    assert ev["baseline_matches"] == 0


def test_a_generated_rule_that_is_too_loose_is_caught_by_the_real_pipeline(world, lab):  # noqa: F811
    from tests.unit.test_c4_governance import sigma
    engine, _, ids = world
    loose = sigma(detection={"selection": {"Image|endswith": "\\powershell.exe",
                                           "CommandLine|contains": "-enc"},
                             "condition": "selection"}, assumptions=[])
    rid, _ = make_sigma_rule(engine, ids[0], loose)
    with session_scope(engine) as s:
        out = validate_rule(s, rid, cfg=CFG, attack=ATTACK, test_set=TEST_SET,
                            baseline=BASELINE, lab=lab)
    assert out.outcome is Outcome.REVISION_REQUIRED and out.failed == [GateId.G10]
    assert out.details["events"]["fidelity_disagreements"] == []


def test_an_ioc_bundle_built_by_the_pipeline_behaves_on_the_real_manager(world, lab):  # noqa: F811
    engine, _, ids = world
    rid = make_ioc(engine, ids[1])
    with session_scope(engine) as s:
        out = validate_rule(s, rid, cfg=CFG, attack=ATTACK, test_set=None, baseline=BASELINE,
                            lab=lab)
    assert out.outcome is Outcome.VALIDATED, [(r.gate.value, r.message) for r in out.results
                                              if r.status is not GateStatus.PASSED]
    ev = out.details["events"]
    assert ev["tiers_run"] == [1, 2] and ev["fidelity_disagreements"] == []
    assert ev["counts"]["positive"] >= 4 and ev["counts"]["lookalike"] >= 4
