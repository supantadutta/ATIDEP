from pathlib import Path

import pytest
import yaml

from app.config import load_config
from components.c4_validation.corpus import (
    CorpusError,
    TestEvent,
    TestSet,
    corpus_sha256,
    load_baseline,
    load_test_set,
)
from components.c4_validation.event_gates import (
    Tier1Runner,
    discriminating_defects,
    run_event_gates,
)
from components.c4_validation.sigma_ir import parse_rule
from schemas.validation_result import GateId, GateStatus
from tests.events import sysmon_factory as f

CFG = load_config()
EVENTS = Path(__file__).resolve().parents[1] / "events"
TEST_SET = load_test_set(EVENTS)
BASELINE = load_baseline(EVENTS / "benign_baseline" / "baseline.jsonl")


def rule(detection, category="process_creation"):
    return yaml.safe_dump({
        "title": "t", "id": "44444444-4444-4444-8444-444444444444", "status": "experimental",
        "description": "d", "references": ["https://x.example"], "author": "a", "date": "2026/10/02",
        "tags": ["attack.execution", "attack.t1059.001"],
        "logsource": {"category": category, "product": "windows"}, "detection": detection,
        "falsepositives": ["x"], "level": "high"}, sort_keys=False)


GOOD = {"sel": {"Image|endswith": "\\powershell.exe", "CommandLine|contains": "-enc"},
        "flt": {"ParentImage|endswith": "\\ccmexec.exe"}, "condition": "sel and not flt"}
NO_FILTER = {"sel": {"Image|endswith": "\\powershell.exe", "CommandLine|contains": "-enc"},
             "condition": "sel"}
GENERIC = {"sel": {"Image|endswith": "\\powershell.exe"}, "condition": "sel"}


def gates(detection, test_set=TEST_SET, baseline=BASELINE, runners=None):
    ir = parse_rule(rule(detection))
    return run_event_gates(ir, test_set, baseline, runners or [Tier1Runner(ir, CFG.wazuh_mapping)],
                           CFG.policies)


def status(rep):
    return {r.gate: r.status for r in rep.results}


# ---- corpora ---------------------------------------------------------------------------------
def test_the_shipped_sets_and_baseline_load_with_unique_record_ids():
    assert len(TEST_SET.positive) == 2 and len(TEST_SET.negative) == 2
    assert len(TEST_SET.lookalike) == 1 and len(BASELINE) == 400
    assert corpus_sha256(BASELINE) == corpus_sha256(list(reversed(BASELINE)))     # order-free
    assert corpus_sha256(BASELINE) != corpus_sha256(BASELINE[:-1])


def test_the_baseline_is_free_of_encoded_commands_and_deterministic():
    cmds = [e.event["win"]["eventdata"].get("commandLine", "").lower() for e in BASELINE]
    assert not any("-enc" in c for c in cmds)
    from tests.events.make_benign_baseline import build
    assert build() == [e.event for e in BASELINE]


def test_duplicate_record_ids_and_malformed_events_are_refused(tmp_path):
    ev = f.process_create(1, f.PS, "x", "y")
    ts = TestSet("dup", positive=[TestEvent("a", ev)], negative=[TestEvent("b", ev)])
    with pytest.raises(CorpusError, match="used by both"):
        run_event_gates(parse_rule(rule(GOOD)), ts, BASELINE, [Tier1Runner(
            parse_rule(rule(GOOD)), CFG.wazuh_mapping)], CFG.policies)
    (tmp_path / "positive").mkdir()
    (tmp_path / "positive" / "bad.json").write_text('{"not": "an event"}')
    with pytest.raises(CorpusError, match="not a structured"):
        load_test_set(tmp_path)


# ---- G8 - G11 ----------------------------------------------------------------------------------
def test_a_precise_rule_passes_all_four_event_gates_on_tier_1():
    rep = gates(GOOD)
    assert rep.passed and rep.tier == 1 and not rep.defects
    assert all(r.tier == 1 for r in rep.results)
    assert [r.gate for r in rep.results] == [GateId.G8, GateId.G9, GateId.G10, GateId.G11]
    assert rep.details["baseline_matches"] == 0 and rep.details["counts"]["positive"] == 2


def test_g10_catches_a_rule_that_fires_on_the_sccm_look_alike():
    rep = gates(NO_FILTER)
    st = status(rep)
    assert st[GateId.G10] is GateStatus.FAILED and st[GateId.G8] is GateStatus.PASSED
    assert st[GateId.G9] is GateStatus.PASSED and st[GateId.G11] is GateStatus.PASSED
    d = next(d for d in rep.defects if d.gate is GateId.G10)
    assert d.code == "G10_MATCHED_LOOKALIKE" and d.path == "sysmon1_sccm_encoded.json"


def test_g8_names_the_positive_events_a_rule_misses():
    det = {"sel": {"Image|endswith": "\\powershell.exe", "CommandLine|contains": "-enc AAAAAAAA"},
           "condition": "sel"}
    rep = gates(det)
    assert status(rep)[GateId.G8] is GateStatus.FAILED
    assert {d.code for d in rep.defects if d.gate is GateId.G8} == {"G8_MISSED_POSITIVE"}


def test_a_generic_rule_fails_g9_and_g11_for_both_reasons():
    rep = gates(GENERIC)
    codes = {d.code for d in rep.defects}
    assert status(rep)[GateId.G9] is GateStatus.FAILED
    assert {"G11_NOT_DISCRIMINATING", "G11_TOO_BROAD"} <= codes
    assert rep.details["baseline_match_pct"] > 0.5
    too_broad = next(d for d in rep.defects if d.code == "G11_TOO_BROAD")
    assert "limit is 0.5%" in too_broad.message


def test_missing_event_kinds_fail_instead_of_passing_vacuously():
    empty = TestSet("empty")
    rep = gates(GOOD, test_set=empty)
    for g in (GateId.G8, GateId.G9, GateId.G10):
        assert status(rep)[g] is GateStatus.FAILED
    assert {d.code for d in rep.defects} >= {"G8_NO_EVENTS", "G9_NO_EVENTS", "G10_NO_EVENTS"}


def test_a_baseline_that_is_too_small_cannot_certify_breadth():
    rep = gates(GOOD, baseline=BASELINE[:20])
    assert status(rep)[GateId.G11] is GateStatus.FAILED
    assert any(d.code == "G11_BASELINE_TOO_SMALL" for d in rep.defects)


def _baseline_with_marker(n):
    """The baseline with the marker text planted in the command line of n events."""
    import copy
    events = copy.deepcopy([e.event for e in BASELINE])
    planted = 0
    for ev in events:
        data = ev["win"]["eventdata"]
        if planted < n and "commandLine" in data:
            data["commandLine"] += " zzmarker"
            planted += 1
    return [TestEvent(f"b{i}", ev) for i, ev in enumerate(events)]


@pytest.mark.parametrize("planted,ok", [(0, True), (2, True), (3, False)])
def test_the_baseline_limit_is_inclusive_at_the_configured_rate(planted, ok):
    # 2 of 400 events is exactly 0.5%, which is allowed; 3 of 400 is 0.75%, which is not
    ir = parse_rule(rule({"sel": {"CommandLine|contains": "zzmarker"}, "condition": "sel"}))
    rep = run_event_gates(ir, TestSet("x"), _baseline_with_marker(planted),
                          [Tier1Runner(ir, CFG.wazuh_mapping)], CFG.policies)
    assert (status(rep)[GateId.G11] is GateStatus.PASSED) is ok
    assert rep.details["baseline_matches"] == planted


# ---- tiers -------------------------------------------------------------------------------------
class FakeTier2:
    tier = 2

    def __init__(self, flip=()):
        self.flip = set(flip)

    def run(self, events):
        ir = parse_rule(rule(GOOD))
        out = Tier1Runner(ir, CFG.wazuh_mapping).run(events)
        return {k: (not v if k in self.flip else v) for k, v in out.items()}


def test_tier_2_decides_the_gates_and_disagreements_are_reported_as_fidelity_findings():
    ir = parse_rule(rule(GOOD))
    positive_id = TEST_SET.positive[0].record_id
    rep = run_event_gates(ir, TEST_SET, BASELINE,
                          [FakeTier2(flip={positive_id}), Tier1Runner(ir, CFG.wazuh_mapping)],
                          CFG.policies)
    assert rep.tier == 2 and all(r.tier == 2 for r in rep.results)
    assert status(rep)[GateId.G8] is GateStatus.FAILED                      # Tier 2 said "missed"
    assert rep.details["fidelity_disagreements"] == [positive_id]
    assert rep.details["tiers_run"] == [1, 2]


def test_agreeing_tiers_report_no_disagreement():
    ir = parse_rule(rule(GOOD))
    rep = run_event_gates(ir, TEST_SET, BASELINE, [Tier1Runner(ir, CFG.wazuh_mapping), FakeTier2()],
                          CFG.policies)
    assert rep.passed and rep.details["fidelity_disagreements"] == []


def test_at_least_one_runner_is_required():
    with pytest.raises(ValueError):
        run_event_gates(parse_rule(rule(GOOD)), TEST_SET, BASELINE, [], CFG.policies)


# ---- discriminating conditions -------------------------------------------------------------------
@pytest.mark.parametrize("det,ok", [
    ({"s": {"Image|endswith": "\\powershell.exe"}, "condition": "s"}, False),
    ({"s": {"Image|endswith": "\\a.exe", "ParentImage|endswith": "\\b.exe"}, "condition": "s"}, True),
    ({"s": {"Image|endswith": "\\a.exe", "CommandLine|contains": "-enc"}, "condition": "s"}, True),
    ({"s": {"CommandLine|contains": "ab"}, "condition": "s"}, False),
    ({"s": {"CommandLine|contains": "*"}, "condition": "s"}, False),
    ({"s": {"CommandLine|contains": "mimikatz"}, "condition": "s"}, True),
    ({"a": {"Image|endswith": "\\a.exe"}, "b": {"CommandLine|contains": "-enc"},
      "condition": "a or b"}, False),                    # one alternative is generic
    ({"a": {"Image|endswith": "\\a.exe"}, "f": {"User|contains": "svc"},
      "condition": "a and not f"}, False),
])
def test_discriminating_condition_rule(det, ok):
    assert (not discriminating_defects(parse_rule(rule(det)))) is ok
