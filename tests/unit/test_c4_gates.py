import copy
from itertools import count

import pytest
import yaml

from app.config import load_config
from components.c2_processing.attack import load_release
from components.c3_detection.rule_agent import RuleContext
from components.c4_validation.gates import (
    GateInputs,
    gate_g1,
    gate_g2,
    make_loop_validator,
    run_static_gates,
)
from schemas.detection_opportunity import Decision, DetectionOpportunity
from schemas.sigma_subset import Assumption
from schemas.validation_result import GateId, GateStatus

CFG = load_config()
ATTACK = load_release()
QUOTE = ("The actor ran powershell.exe -enc JABzAD0A to download a second stage; the loader is "
         "started by the installer")
OPP = DetectionOpportunity(
    detectable=True, decision=Decision.BEHAVIORAL, detection_concept="Encoded PowerShell",
    required_log_source="windows_process_creation", required_fields=["Image", "CommandLine"],
    attack_techniques=["T1059.001"], false_positive_hypotheses=["admin scripts"],
    evidence_ids=["EV-1"], decision_reason="Observable in process events")
GOOD = {
    "title": "Encoded PowerShell command line", "id": "33333333-3333-4333-8333-333333333333",
    "status": "experimental", "description": "Detects PowerShell with an encoded command.",
    "references": ["https://vendor.example/report"], "author": "ATIDEP", "date": "2026/10/02",
    "tags": ["attack.execution", "attack.t1059.001"],
    "logsource": {"category": "process_creation", "product": "windows"},
    "detection": {"selection": {"Image|endswith": "\\powershell.exe",
                                "CommandLine|contains": "-enc"}, "condition": "selection"},
    "falsepositives": ["Administrative automation"], "level": "high"}


def inputs(opp=OPP, quotes=None, catalog=None):
    n = count(110000)
    ids = {}
    return GateInputs(opp, {"EV-1": QUOTE} if quotes is None else quotes,
                      catalog or CFG.telemetry_catalog, CFG.wazuh_mapping, ATTACK, CFG.policies,
                      lambda k: ids.setdefault(k, next(n)))


def run(doc=None, assumptions=(), inp=None, text=None):
    text = text if text is not None else yaml.safe_dump(doc or GOOD, sort_keys=False)
    return run_static_gates(text, list(assumptions), inp or inputs())


def codes(rep):
    return sorted({d.code for d in rep.defects})


def mutate(**changes):
    doc = copy.deepcopy(GOOD)
    for k, v in changes.items():
        if v is None:
            doc.pop(k, None)
        else:
            doc[k] = v
    return doc


# ---- a good rule ---------------------------------------------------------------------------
def test_a_well_formed_supported_rule_passes_every_static_gate():
    rep = run()
    assert rep.passed and not rep.defects and not rep.blocked
    assert [r.gate for r in rep.results] == [GateId.G1, GateId.G2, GateId.G3, GateId.G4,
                                             GateId.G5, GateId.G6, GateId.G7]
    assert all(r.status is GateStatus.PASSED for r in rep.results)
    assert rep.conversion.rule_ids == [110000] and rep.ir is not None
    assert rep.stats["evidence"] == {"values": 2, "quoted": 2, "assumed": 0, "unsupported": 0}


# ---- G1 --------------------------------------------------------------------------------------
def test_g1_rejects_yaml_that_does_not_parse_and_non_mappings():
    d, doc = gate_g1("title: [unclosed")
    assert doc is None and d[0].code == "G1_YAML"
    d, doc = gate_g1("- just\n- a list")
    assert d[0].code == "G1_NOT_A_MAPPING"
    assert gate_g1("x: " + "y" * 60000)[0][0].code == "G1_TOO_LARGE"


def test_g1_uses_pysigma_so_unknown_modifiers_and_broken_conditions_fail():
    bad_mod = mutate(detection={"s": {"CommandLine|bogus": "x"}, "condition": "s"})
    d, _ = gate_g1(yaml.safe_dump(bad_mod))
    assert d and d[0].code == "G1_SIGMA" and "bogus" in d[0].message
    bad_cond = mutate(detection={"s": {"CommandLine": "x"}, "condition": "nosuchselection"})
    d, _ = gate_g1(yaml.safe_dump(bad_cond))
    assert d and d[0].code == "G1_SIGMA"
    assert gate_g1(yaml.safe_dump(GOOD))[0] == []


def test_a_rule_that_fails_g1_leaves_the_dependent_gates_unrun_but_still_checks_g6():
    rep = run(text="detection: [")
    by = {r.gate: r.status for r in rep.results}
    assert by[GateId.G1] is GateStatus.FAILED and by[GateId.G6] is GateStatus.PASSED
    assert all(by[g] is GateStatus.NOT_RUN for g in
               (GateId.G2, GateId.G3, GateId.G4, GateId.G5, GateId.G7))
    assert not rep.passed


# ---- G2 --------------------------------------------------------------------------------------
@pytest.mark.parametrize("change,code", [
    ({"id": "not-a-uuid"}, "G2_INVALID"), ({"id": None}, "G2_MISSING"),
    ({"status": "stable"}, "G2_INVALID"), ({"author": " "}, "G2_INVALID"),
    ({"date": "02-10-2026"}, "G2_INVALID"), ({"date": None}, "G2_MISSING"),
    ({"references": []}, "G2_INVALID"), ({"falsepositives": None}, "G2_MISSING"),
    ({"level": "severe"}, "G2_INVALID"), ({"tags": ["execution"]}, "G2_INVALID"),
    ({"title": None}, "G2_MISSING"), ({"description": ""}, "G2_INVALID"),
])
def test_g2_names_the_missing_or_invalid_metadata(change, code):
    defects = gate_g2(mutate(**change))
    assert [d.code for d in defects] == [code] and defects[0].path == next(iter(change))


def test_g2_accepts_both_date_styles_and_yaml_dates():
    import datetime
    assert not gate_g2(mutate(date="2026-10-02"))
    assert not gate_g2(mutate(date=datetime.date(2026, 10, 2)))


# ---- G3 --------------------------------------------------------------------------------------
def test_g3_reports_the_stable_reason_code_and_the_gate_stays_in_the_loop():
    rep = run(mutate(detection={"s": {"CommandLine|contains|base64": "x"}, "condition": "s"}))
    g3 = rep.result(GateId.G3)
    assert g3.status is GateStatus.FAILED and "G3_UNSUPPORTED_MODIFIER" in g3.reason_codes
    assert rep.result(GateId.G4).status is GateStatus.NOT_RUN and rep.ir is None


def test_an_invented_field_is_reported_once_by_g5_not_also_by_g3():
    doc = mutate(detection={"s": {"ScriptBlockText|contains": "-enc"}, "condition": "s"})
    rep = run(doc)
    assert codes(rep) == ["G5_UNKNOWN_FIELD"] and rep.ir is not None and rep.conversion is None
    assert rep.result(GateId.G3).status is GateStatus.PASSED


def test_an_invalid_level_is_reported_by_g1_and_g2_only():
    rep = run(mutate(level="severe"))
    assert {d.gate for d in rep.defects} == {GateId.G1, GateId.G2}


def test_g3_refuses_log_sources_outside_the_subset():
    doc = mutate(logsource={"category": "registry_set", "product": "windows"})
    rep = run(doc)
    assert "G3_UNSUPPORTED_LOGSOURCE" in codes(rep)


# ---- G4 --------------------------------------------------------------------------------------
def test_g4_flags_values_that_the_report_never_stated():
    doc = mutate(detection={"s": {"Image|endswith": "\\powershell.exe",
                                  "CommandLine|contains": ["-enc", "mimikatz"]},
                            "condition": "s"})
    rep = run(doc)
    assert codes(rep) == ["G4_UNSUPPORTED_VALUE"] and "mimikatz" in rep.defects[0].message
    assert rep.result(GateId.G4).status is GateStatus.FAILED


def test_g4_accepts_a_declared_assumption_that_covers_the_value():
    doc = mutate(detection={"s": {"Image|endswith": "\\powershell.exe",
                                  "CommandLine|contains": "-enc"},
                            "f": {"ParentImage|endswith": "\\ccmexec.exe"},
                            "condition": "s and not f"})
    assert "G4_UNSUPPORTED_VALUE" in codes(run(doc))
    covered = Assumption(statement="Exclude SCCM", justification="common admin tool",
                         covers=["ccmexec.exe"])
    rep = run(doc, [covered])
    assert rep.passed and rep.stats["evidence"]["assumed"] == 1
    # an assumption for something else does not help
    other = Assumption(statement="x", justification="y", covers=["unrelated.exe"])
    assert "G4_UNSUPPORTED_VALUE" in codes(run(doc, [other]))


def test_g4_is_not_fooled_by_case_wildcards_or_doubled_backslashes():
    doc = mutate(detection={"s": {"Image|endswith": "\\POWERSHELL.EXE",
                                  "CommandLine|contains": "-E*"}, "condition": "s"})
    assert run(doc).passed
    quotes = {"EV-1": "started C:\\\\Windows\\\\System32\\\\powershell.exe now"}
    doc2 = mutate(detection={"s": {"Image|endswith": "\\System32\\powershell.exe"},
                             "condition": "s"})
    assert run(doc2, inp=inputs(quotes=quotes)).passed


def test_g4_checks_literal_runs_inside_regular_expressions():
    ok = mutate(detection={"s": {"CommandLine|re": "powershell\\s+-enc"}, "condition": "s"})
    assert run(ok).passed
    bad = mutate(detection={"s": {"CommandLine|re": "powershell\\s+(invoke-mimikatz)"},
                            "condition": "s"})
    assert "G4_UNSUPPORTED_VALUE" in codes(run(bad))


def test_g4_exempts_boolean_fields_only():
    net_opp = OPP.model_copy(update={"required_log_source": "windows_network_connection"})
    doc = mutate(logsource={"category": "network_connection", "product": "windows"},
                 detection={"s": {"DestinationIp": "203.0.113.5", "Initiated": True},
                            "condition": "s"})
    q = {"EV-1": "beacons to 203.0.113.5 over https"}
    assert run(doc, inp=inputs(net_opp, q)).passed
    assert "G4_UNSUPPORTED_VALUE" in codes(run(doc, inp=inputs(net_opp, {"EV-1": "nothing"})))


# ---- G5 --------------------------------------------------------------------------------------
def test_g5_catches_invented_fields_with_the_allowed_list():
    doc = mutate(detection={"s": {"Image|endswith": "\\powershell.exe", "ScriptBlockText|contains":
                                  "-enc"}, "condition": "s"})
    rep = run(doc)
    assert "G5_UNKNOWN_FIELD" in codes(rep)
    d = next(d for d in rep.defects if d.code == "G5_UNKNOWN_FIELD")
    assert d.path == "detection.ScriptBlockText" and "CommandLine" in d.message


def test_g5_catches_a_rule_for_a_different_log_source_than_the_opportunity():
    doc = mutate(logsource={"category": "dns_query", "product": "windows"},
                 detection={"s": {"QueryName|endswith": "powershell.exe"}, "condition": "s"})
    assert "G5_LOGSOURCE_MISMATCH" in codes(run(doc))


# ---- G6 --------------------------------------------------------------------------------------
def test_g6_blocks_when_the_required_telemetry_is_not_available():
    ps = OPP.model_copy(update={"required_log_source": "windows_powershell_script_block"})
    rep = run(inp=inputs(ps))
    assert rep.blocked and rep.result(GateId.G6).status is GateStatus.FAILED
    d = next(d for d in rep.defects if d.gate is GateId.G6)
    assert "Script Block Logging" in d.message


def test_g6_blocks_when_the_rules_own_log_source_is_switched_off():
    catalog = copy.deepcopy(CFG.telemetry_catalog)
    catalog["logsources"]["windows_process_creation"]["available"] = False
    rep = run(inp=inputs(catalog=catalog))
    assert rep.blocked and codes(rep).count("G6_TELEMETRY_UNAVAILABLE") == 1


# ---- G7 --------------------------------------------------------------------------------------
def test_g7_rejects_unknown_deprecated_and_unsupported_techniques():
    assert "G7_UNKNOWN_TECHNIQUE" in codes(run(mutate(tags=["attack.execution", "attack.t9999"])))
    assert "G7_UNKNOWN_TECHNIQUE" in codes(run(mutate(tags=["attack.collection", "attack.t1002"])))
    rep = run(mutate(tags=["attack.stealth", "attack.t1027"]))
    assert codes(rep) == ["G7_UNSUPPORTED_MAPPING"]            # exists, but no quote supports it
    assumed = Assumption(statement="obfuscation", justification="seen", covers=["T1027"])
    assert run(mutate(tags=["attack.stealth", "attack.t1027"]), [assumed]).passed


def test_g7_requires_a_technique_and_consistent_tactics():
    assert "G7_NO_TECHNIQUE" in codes(run(mutate(tags=["attack.execution"])))
    rep = run(mutate(tags=["attack.persistence", "attack.t1059.001"]))
    assert "G7_INCONSISTENT_TACTIC" in codes(rep)


def test_g7_names_the_valid_tactics_when_an_old_tactic_name_is_used():
    rep = run(mutate(tags=["attack.defense_evasion", "attack.t1059.001"]))
    d = next(d for d in rep.defects if d.code == "G7_UNKNOWN_TACTIC")
    assert "stealth" in d.message and ATTACK.version in d.message


# ---- the loop adapter --------------------------------------------------------------------------
def rule_ctx(opp=OPP, quotes=None):
    return RuleContext(intel_id="TI-2026-0001", opportunity_id=1, opportunity=opp,
                       quotes={"EV-1": QUOTE} if quotes is None else quotes,
                       allowed_fields=["Image", "CommandLine"], sigma_category="process_creation")


def test_the_loop_validator_returns_repairable_defects_and_blocks_on_g6():
    i = inputs()
    validate = make_loop_validator(catalog=i.catalog, wazuh_mapping=i.wazuh_mapping,
                                   attack=i.attack, policy=i.policy, allocate=i.allocate)
    ok = validate(yaml.safe_dump(GOOD, sort_keys=False), [], rule_ctx())
    assert ok.passed
    bad = validate(yaml.safe_dump(mutate(author=" "), sort_keys=False), [], rule_ctx())
    assert not bad.passed and not bad.blocked and bad.defects[0].gate is GateId.G2
    ps = OPP.model_copy(update={"required_log_source": "windows_powershell_script_block"})
    blocked = validate(yaml.safe_dump(GOOD, sort_keys=False), [], rule_ctx(ps))
    assert blocked.blocked and "not available" in blocked.blocked_reason
