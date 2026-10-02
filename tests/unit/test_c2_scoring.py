from datetime import UTC, datetime, timedelta

import pytest

from app.config import load_config
from components.c2_processing.attack import load_release
from components.c2_processing.scoring import ScoreInputs, score_priority
from schemas.common import Band

CFG = load_config()
NOW = datetime(2026, 10, 2, tzinfo=UTC)
ATTACK = load_release()


def run(**kw):
    base = dict(reliability_rating="B", credibility_rating=2, evidence_support_pct=100,
                retrieved_at=NOW, published_at=NOW)
    return score_priority(ScoreInputs(**{**base, **kw}), CFG.scoring, CFG.org_profile,
                          CFG.telemetry_catalog, ATTACK)


def comp(result, name):
    return next(c for c in result.components if c.name == name)


def test_the_example_item_is_scored_component_by_component():
    r = run(primary_type="behavior", independent_sources=2, technique_ids=["T1059.001"],
            products=["PowerShell"], platforms=["windows"], sectors=["financial_services"],
            candidate_logsources=["windows_process_creation"])
    assert comp(r, "source_reliability").value == 80
    assert comp(r, "intelligence_confidence").value == 80          # credibility 2, all verified
    # product "PowerShell" is not in the profile, the platform "windows" is -> tech 50;
    # telemetry available -> 100; sector targeted -> 100: 0.5*50 + 0.3*100 + 0.2*100
    assert comp(r, "environmental_relevance").value == pytest.approx(75)
    assert comp(r, "recency").value == 100
    assert comp(r, "cross_source_correlation").value == 50
    assert comp(r, "potential_impact").value == 70                  # execution tactic
    expected = 0.25 * 80 + 0.20 * 80 + 0.20 * 75 + 0.15 * 100 + 0.10 * 50 + 0.10 * 70   # 78.0
    assert r.score == pytest.approx(round(expected, 1), abs=0.05)
    assert r.priority.band is Band.HIGH


def test_weights_sum_and_contributions_add_up_to_the_score():
    r = run(technique_ids=["T1059.001"])
    assert sum(c.weight for c in r.components) == pytest.approx(1.0)
    assert sum(c.weighted for c in r.components) == pytest.approx(r.score, abs=0.05)
    assert all(e["reason"] for e in r.explanation())


def test_source_reliability_and_credibility_mapping_incl_cannot_be_judged():
    assert comp(run(reliability_rating="A"), "source_reliability").value == 100
    f = run(reliability_rating="F", credibility_rating=6)
    assert comp(f, "source_reliability").value == 50 and "neutral" in comp(f, "source_reliability").reason
    assert comp(f, "intelligence_confidence").value == 50
    with pytest.raises(ValueError):
        run(reliability_rating="Z")


def test_unverified_claims_reduce_confidence_proportionally():
    assert comp(run(credibility_rating=1, evidence_support_pct=50), "intelligence_confidence").value == 50
    assert comp(run(credibility_rating=1, evidence_support_pct=0), "intelligence_confidence").value == 0


def test_environmental_relevance_cases():
    full = run(products=["Active Directory"], candidate_logsources=["windows_process_creation"],
               sectors=["financial services"])
    assert comp(full, "environmental_relevance").value == 100
    platform_only = run(platforms=["windows"], candidate_logsources=[], sectors=["energy"])
    assert comp(platform_only, "environmental_relevance").value == pytest.approx(0.5 * 50 + 0 + 0)
    unavailable = run(products=["Active Directory"], candidate_logsources=["windows_powershell_script_block"])
    assert comp(unavailable, "environmental_relevance").value == pytest.approx(0.5 * 100 + 0 + 0.2 * 50)
    nothing = run(sectors=["energy"])
    assert comp(nothing, "environmental_relevance").value == 0


def test_recency_halves_every_half_life():
    for kind, half in [("ip", 14), ("domain", 30), ("hash", 180), ("behavior", 365)]:
        r = run(primary_type=kind, published_at=NOW - timedelta(days=half))
        assert comp(r, "recency").value == pytest.approx(50.0), kind
    assert comp(run(published_at=None), "recency").value == 100
    assert comp(run(published_at=NOW + timedelta(days=3)), "recency").value == 100   # future dates clamp
    with pytest.raises(ValueError):
        run(primary_type="unknown")


def test_cross_source_steps():
    assert [comp(run(independent_sources=n), "cross_source_correlation").value
            for n in (0, 1, 2, 3, 9)] == [0, 0, 50, 100, 100]


def test_potential_impact_takes_the_highest_source():
    assert comp(run(technique_ids=["T1059.001"]), "potential_impact").value == 70
    assert comp(run(technique_ids=["T1059.001", "T1486"]), "potential_impact").value == 90   # impact
    assert comp(run(cvss=9.8), "potential_impact").value == pytest.approx(98)
    assert comp(run(), "potential_impact").value == 50                                     # default
    assert comp(run(technique_ids=["T9999"]), "potential_impact").value == 50              # unknown id


def test_bands_follow_half_open_intervals():
    low = run(reliability_rating="E", credibility_rating=5, evidence_support_pct=0,
              primary_type="ip", published_at=NOW - timedelta(days=400), independent_sources=1)
    assert low.priority.band is Band.LOW and low.score < 40
    hi = run(reliability_rating="A", credibility_rating=1, independent_sources=3,
             technique_ids=["T1486"], products=["Active Directory"], sectors=["financial_services"],
             candidate_logsources=["windows_process_creation"])
    assert hi.priority.band is Band.CRITICAL and hi.score >= 80
