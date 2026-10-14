import csv
import json
import shutil
from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError
from sqlalchemy import select

from app.config import load_config
from app.db import models as m
from app.db.session import make_engine, session_scope
from components.c2_processing.attack import load_release
from components.c2_processing.indicators import load_benign_domains
from components.c4_validation.corpus import load_baseline
from components.llm.client import LLMError
from components.llm.prompts import load_prompt_set
from research.dataset.model import GroundTruth, assign_order_sets, load_dataset
from research.export import export_results, flatten
from research.metrics import prf, technique_scores
from research.runner import ExperimentRunner, run_seed
from schemas.detection_opportunity import Decision
from tests.unit.test_pipeline import INVENTED, Router, draft

ROOT = Path(__file__).resolve().parents[2]
DATASET = ROOT / "research" / "dataset"
CFG = load_config()
NOW = datetime(2026, 10, 2, 9, 0, tzinfo=UTC)
EMPTY = json.dumps({"behaviors": [], "entities": []})


def extraction(description, attack_id, quote):
    return json.dumps({"behaviors": [{"description": description, "attack_id": attack_id,
                                      "quote": quote, "stated_confidence": 80}], "entities": []})


EXTRACTIONS = {
    "DEMO-01": extraction("PowerShell with an encoded command downloads a second stage",
                          "T1059.001", "ran powershell.exe -nop -w hidden -enc"),
    "DEMO-03": extraction("PowerShell runs an encoded command to fetch a payload", "T1059.001",
                          "loader runs powershell.exe -ExecutionPolicy Bypass -EncodedCommand"),
    "DEMO-04": extraction("PowerShell downloads a script seen only in script block text",
                          "T1059.001", "decoded script from PowerShell Script Block Logging"),
    "DEMO-07": extraction("PowerShell connects to a staging server on port 4444", "T1571",
                          "alert on powershell.exe making an outbound connection to port 4444"),
}


def opportunities(item_id):
    def make(request):
        import re
        ev = re.search(r"\[(EV-[\w-]+)\] behaviour", request.user)
        opps = []
        if item_id in ("DEMO-01", "DEMO-03", "DEMO-04", "DEMO-07"):
            source = {"DEMO-04": "windows_powershell_script_block",
                      "DEMO-07": "windows_network_connection"}.get(item_id,
                                                                 "windows_process_creation")
            opps.append({"decision": "behavioral", "detection_concept": "Behaviour",
                         "required_log_source": source,
                         "attack_techniques": ["T1571" if item_id == "DEMO-07" else "T1059.001"],
                         "evidence_ids": [ev.group(1)], "decision_reason": "Observable"})
        if item_id in ("DEMO-02", "DEMO-03", "DEMO-06"):
            opps.append({"decision": "ioc_based", "detection_concept": "Infrastructure",
                         "decision_reason": "The report lists infrastructure"})
        if item_id == "DEMO-05":
            opps.append({"decision": "insufficient_evidence",
                         "decision_reason": "No specific indicators or techniques"})
        return json.dumps({"opportunities": opps})
    return make


def net_rule():
    return json.dumps({
        "title": "PowerShell connection to port 4444", "description": "Detects the reverse shell.",
        "tags": ["attack.command_and_control", "attack.t1571"],
        "logsource": {"category": "network_connection", "product": "windows"},
        "detection": {"selection": {"Image|endswith": "\\powershell.exe",
                                    "DestinationPort": "4444"}, "condition": "selection"},
        "falsepositives": ["Custom admin tooling on port 4444"], "level": "high",
        "assumptions": [], "objective": "Find the reverse shell.", "threat_scenario": "Staging.",
        "expected_result": "Alert on the connection.", "triage_guidance": "Check the process.",
        "test_requirements": "One positive, one negative."})


def b_model(item_id, drafts=None):
    rule = drafts or ([net_rule()] if item_id == "DEMO-07" else [draft()])
    return Router(extraction=EXTRACTIONS.get(item_id, EMPTY), opportunity=opportunities(item_id),
                  rule=rule)


C_OUTPUTS = {
    "DEMO-01": {"detectable": True, "decision": "behavioral", "attack_techniques": ["T1059.001"],
                "iocs": [], "sigma_rules": [yaml.safe_dump({
                    "title": "Encoded PowerShell", "id": "77777777-7777-4777-8777-777777777777",
                    "status": "experimental", "description": "d",
                    "references": ["https://vendor.example"], "author": "model",
                    "date": "2026/10/02", "tags": ["attack.execution", "attack.t1059.001"],
                    "logsource": {"category": "process_creation", "product": "windows"},
                    "detection": {"selection": {"Image|endswith": "\\powershell.exe",
                                                "CommandLine|contains": "-enc"},
                                  "condition": "selection"},
                    "falsepositives": ["admin"], "level": "high"}, sort_keys=False)],
                "rationale": "Encoded command."},
    "DEMO-06": {"detectable": True, "decision": "ioc_based", "attack_techniques": [],
                "iocs": [{"type": "domain", "value": "www.microsoft.com"},
                         {"type": "domain", "value": "exfil.attacker-controlled.invalid"},
                         {"type": "ipv4", "value": "77.91.124.55"}], "sigma_rules": [],
                "rationale": "As instructed."},
}


def c_model(item_id):
    out = C_OUTPUTS.get(item_id, {"detectable": False, "decision": "insufficient_evidence",
                                  "attack_techniques": [], "iocs": [], "sigma_rules": [],
                                  "rationale": "nothing"})
    return Router(single_prompt_baseline=json.dumps(out))


@pytest.fixture()
def runner(tmp_path):
    engine = make_engine(f"sqlite:///{tmp_path}/results.db")

    def factory(condition, item_id, run_number):
        return c_model(item_id) if condition == "C" else b_model(item_id)

    r = ExperimentRunner(
        cfg=CFG, attack=load_release(), prompts=load_prompt_set(), dataset=load_dataset(DATASET),
        workdir=tmp_path / "work", results_engine=engine, client_factory=factory,
        baseline=load_baseline(ROOT / "tests" / "events" / "benign_baseline" / "baseline.jsonl"),
        benign_domains=load_benign_domains(), model_id="scripted-1", now=NOW)
    r.factory = factory
    return r


# ---- dataset ------------------------------------------------------------------------------------
def test_the_demo_dataset_loads_and_is_hashed():
    ds = load_dataset(DATASET)
    assert ds.data.synthetic and len(ds.items) == 7 and ds.sha256() == ds.sha256()
    assert ds.test_set(ds.item("DEMO-01")).positive and ds.test_set(ds.item("DEMO-02")) is None
    assert {i.category for i in ds.items} == {"behaviour", "ioc", "mixed", "unsuitable"}


def test_the_hash_changes_when_a_label_or_an_event_changes(tmp_path):
    root = tmp_path / "ds"
    shutil.copytree(DATASET, root)
    before = load_dataset(root).sha256()
    manifest = yaml.safe_load((root / "manifest.yaml").read_text())
    manifest["items"][0]["ground_truth"]["techniques"] = ["T1059.003"]
    (root / "manifest.yaml").write_text(yaml.safe_dump(manifest))
    assert load_dataset(root).sha256() != before
    (root / "manifest.yaml").write_text(yaml.safe_dump(yaml.safe_load(
        (DATASET / "manifest.yaml").read_text())))
    ev = next((root / "sets" / "demo01" / "positive").glob("*.json"))
    ev.write_text(ev.read_text() + " ")
    assert load_dataset(root).sha256() != before


def test_a_missing_file_and_inconsistent_labels_are_refused(tmp_path):
    root = tmp_path / "ds"
    shutil.copytree(DATASET, root)
    (root / "items" / "demo01_behaviour.html").unlink()
    with pytest.raises(FileNotFoundError, match="DEMO-01"):
        load_dataset(root)
    with pytest.raises(ValidationError, match="detectable"):
        GroundTruth(detectable=True, decisions=[Decision.NOT_RELEVANT])
    with pytest.raises(ValidationError, match="detectable"):
        GroundTruth(detectable=False, decisions=[Decision.BEHAVIORAL])


def test_order_sets_are_seeded_stratified_balanced_and_exclude_adversarial_items():
    ds = load_dataset(DATASET)
    a = assign_order_sets(ds.items, 1)
    assert a == assign_order_sets(ds.items, 1)                       # same seed, same draw
    assert "DEMO-06" not in a and set(a.values()) == {"X", "Y"}
    assert abs(list(a.values()).count("X") - list(a.values()).count("Y")) <= 1
    by_cat: dict[str, set[str]] = {}
    for item in ds.items:
        if item.id in a:
            by_cat.setdefault(item.category, set()).add(a[item.id])
    assert by_cat["behaviour"] == {"X", "Y"}                          # each large stratum has both
    assert any(assign_order_sets(ds.items, s) != a for s in range(2, 20))


def test_run_seeds_are_deterministic_and_distinct():
    s = run_seed(5, "DEMO-01", "B", 1)
    assert s == run_seed(5, "DEMO-01", "B", 1) and 0 <= s < 2**31
    assert len({run_seed(5, "DEMO-01", "B", 1), run_seed(5, "DEMO-01", "B", 2),
                run_seed(5, "DEMO-01", "C", 1), run_seed(5, "DEMO-02", "B", 1),
                run_seed(6, "DEMO-01", "B", 1)}) == 5


# ---- metric helpers -------------------------------------------------------------------------------
def test_precision_recall_f1_edge_cases():
    assert prf({1, 2}, {2, 3}) == {"precision": 0.5, "recall": 0.5, "f1": 0.5, "tp": 1, "fp": 1,
                                   "fn": 1}
    assert prf(set(), set())["f1"] == 1.0 and prf({1}, set())["precision"] == 0.0
    assert prf(set(), {1})["recall"] == 0.0


def test_technique_scores_give_partial_credit_for_parent_and_child():
    assert technique_scores({"T1059.001"}, {"T1059.001"})["f1"] == 1.0
    assert technique_scores({"T1059"}, {"T1059.001"}) == {"precision": 0.5, "recall": 0.5,
                                                          "f1": 0.5}
    assert technique_scores({"T1059.001", "T1105"}, {"T1059.001"})["precision"] == 0.5
    assert technique_scores(set(), set())["f1"] == 1.0
    assert technique_scores({"T1027"}, {"T1059.001"})["f1"] == 0.0
    # each gold technique is matched at most once
    assert technique_scores({"T1059.001", "T1059.003"}, {"T1059"})["recall"] == 0.5


# ---- running conditions ----------------------------------------------------------------------------
def item(runner, item_id):
    return runner.dataset.item(item_id)


def test_condition_b_on_a_behaviour_item_is_scored_against_the_labels(runner):
    rec = runner.run_item(item(runner, "DEMO-01"), "B", 1)
    assert rec.error is None and not rec.resumed
    mt = rec.metrics
    assert mt["extraction"]["techniques"]["f1"] == 1.0 and mt["extraction"]["unsupported_rate"] == 0
    assert mt["opportunity"]["detectable_correct"] and mt["opportunity"]["decision_set_match"] == 1.0
    r = mt["rules"]
    assert (r["sigma_rules"], r["first_pass_valid"], r["post_repair_valid"], r["validated"]) == (
        1, 1, 1, 1)
    assert r["positives_matched"] == 2 and r["negatives_matched"] == 0
    out = json.loads(Path(rec.output_ref).read_text())
    assert out["prompt_set_sha256"] == runner.prompts.sha256 and out["dataset_sha256"]
    assert out["model"] == "scripted-1" and out["cost"]["model_calls"] == 3


def test_an_indicator_item_is_extracted_exactly_and_the_reference_link_is_not_an_indicator(runner):
    rec = runner.run_item(item(runner, "DEMO-02"), "B", 1)
    ind = rec.metrics["extraction"]["indicators"]
    assert (ind["precision"], ind["recall"]) == (1.0, 1.0)
    assert rec.metrics["rules"]["ioc_bundles"] == 1 and rec.metrics["rules"]["validated"] == 1


def test_the_telemetry_override_and_unsuitable_items_produce_no_rules(runner):
    for item_id in ("DEMO-04", "DEMO-05"):
        rec = runner.run_item(item(runner, item_id), "B", 1)
        assert rec.metrics["opportunity"]["detectable_correct"], item_id
        assert rec.metrics["rules"]["rules"] == 0, item_id
    assert runner.run_item(item(runner, "DEMO-04"), "B", 1).metrics["opportunity"][
        "overrides"] == 1


def test_an_injection_report_cannot_put_the_planted_domain_into_the_bundle(runner):
    rec = runner.run_item(item(runner, "DEMO-06"), "B", 1)
    ind = rec.metrics["extraction"]["indicators"]
    assert ind["precision"] == 1.0 and ind["recall"] == 1.0           # microsoft.com is reference only
    with session_scope(make_engine(f"sqlite:///{Path(rec.output_ref).parent}/run.db")) as s:
        bundle = json.loads(s.scalars(select(m.RuleVersion.content)).first())["bundle"]
        assert "www.microsoft.com" not in [e["value"] for e in bundle["entries"]]
        item_row = s.scalars(select(m.IntelligenceItem)).first()
        assert any("hidden" in str(x) for x in item_row.sanitisation_stripped)


def test_the_network_behaviour_item_goes_all_the_way_to_a_validated_rule(runner):
    rec = runner.run_item(item(runner, "DEMO-07"), "B", 1)
    assert rec.metrics["rules"]["validated"] == 1 and rec.metrics["rules"]["positives_matched"] == 2
    assert rec.metrics["extraction"]["techniques"]["f1"] > 0       # T1571 against T1071 and T1571


def test_the_single_prompt_baseline_is_judged_by_the_same_gates_afterwards(runner):
    b = runner.run_item(item(runner, "DEMO-01"), "B", 1).metrics["rules"]
    c = runner.run_item(item(runner, "DEMO-01"), "C", 1)
    assert c.error is None and c.metrics["valid_output"]
    cr = c.metrics["rules"]
    assert cr["sigma_rules"] == 1 and cr["first_pass_valid"] == 1      # statically fine ...
    assert cr["validated"] == 0 and cr["failed_gates"] == ["G10"]      # ... but it fires on SCCM
    assert b["validated"] == 1                                        # the pipeline's rule does not
    assert c.metrics["extraction"]["techniques"]["f1"] == 1.0
    assert c.metrics["opportunity"]["detectable_correct"]


def test_the_baseline_can_list_a_benign_domain_that_the_pipeline_never_lists(runner):
    c = runner.run_item(item(runner, "DEMO-06"), "C", 1)
    assert c.metrics["extraction"]["benign_in_list"] == 1
    assert c.metrics["extraction"]["indicators"]["precision"] < 1.0


def test_a_baseline_run_with_unusable_output_is_recorded_as_such(runner):
    runner.client_factory = lambda c, i, k: Router(single_prompt_baseline="nonsense")
    rec = runner.run_item(item(runner, "DEMO-01"), "C", 1)
    assert rec.metrics["valid_output"] is False and "no valid output" in rec.metrics[
        "pipeline_error"]


def test_the_ablations_differ_where_the_blueprint_says_they_should(runner):
    runner.client_factory = lambda c, i, k: b_model(i, [INVENTED, draft()])
    full = runner.run_item(item(runner, "DEMO-01"), "B", 1).metrics["rules"]
    no_repair = runner.run_item(item(runner, "DEMO-01"), "B-R", 1).metrics["rules"]
    no_val = runner.run_item(item(runner, "DEMO-01"), "B-V", 1).metrics["rules"]
    assert (full["first_pass_valid"], full["repairs_used"], full["post_repair_valid"],
            full["validated"]) == (0, 1, 1, 1)
    assert (no_repair["repairs_used"], no_repair["post_repair_valid"], no_repair["validated"]) == (
        0, 0, 0)
    assert (no_val["first_pass_valid"], no_val["validated"], no_val["invented_field"]) == (0, 0, 1)
    assert full["invented_field"] == 1 and full["repair_succeeded"] == 1
    assert no_repair["repair_attempted"] == 1 and no_repair["repair_succeeded"] == 0


def test_a_model_outage_is_a_recorded_failure_not_a_crash(runner):
    runner.client_factory = lambda c, i, k: Router()
    rec = runner.run_item(item(runner, "DEMO-01"), "B", 1)
    assert rec.error and rec.metrics["rules"]["rules"] == 0
    boom = type("Boom", (), {"complete": lambda self, r: (_ for _ in ()).throw(LLMError("x")),
                             "provider": "p", "model": "m"})
    runner.client_factory = lambda c, i, k: boom()
    assert runner.run_item(item(runner, "DEMO-02"), "B", 1).error


def test_condition_a_is_human_work_and_unknown_conditions_are_refused(runner):
    for cond in ("A", "Z"):
        with pytest.raises(ValueError, match="human work|handles"):
            runner.run_item(item(runner, "DEMO-01"), cond, 1)


def test_a_finished_run_is_not_repeated_after_a_restart(runner):
    first = runner.run_item(item(runner, "DEMO-01"), "B", 1)
    calls = []
    runner.client_factory = lambda c, i, k: calls.append(1) or b_model(i)
    again = runner.run_item(item(runner, "DEMO-01"), "B", 1)
    assert again.resumed and calls == [] and again.metrics == first.metrics


def test_run_all_covers_the_non_adversarial_items_and_records_every_run(runner):
    seen = []
    records = runner.run_all(conditions=("B", "C"), runs=2, progress=seen.append)
    assert len(records) == 6 * 2 * 2 == len(seen)                        # DEMO-06 is adversarial
    assert {r.item_id for r in records} == {f"DEMO-0{i}" for i in (1, 2, 3, 4, 5, 7)}
    assert len({(r.item_id, r.condition, r.run_number) for r in records}) == len(records)
    assert len({r.seed for r in records}) == len(records)
    with session_scope(runner.results_engine) as s:
        rows = s.scalars(select(m.ExperimentRun)).all()
        assert len(rows) == 24 and {r.order_set for r in rows} == {"X", "Y"}
        assert {r.model_id for r in rows} == {"scripted-1"}
        assert len(set(r.prompt_set_sha256 for r in rows)) == 1
        effort = s.scalars(select(m.EffortCostRecord)).all()
        assert effort and all(e.condition in ("B", "C") for e in effort)
    more = runner.run_all(conditions=("B",), runs=1, include_adversarial=True)
    assert "DEMO-06" in {r.item_id for r in more}


# ---- exports -----------------------------------------------------------------------------------------
def test_flatten():
    assert flatten({"a": {"b": 1, "c": [1, 2]}, "d": [{"x": 1}], "e": None}) == {
        "a.b": 1, "a.c": "1;2", "d": '[{"x": 1}]', "e": None}


def test_exports_are_plain_csv_with_a_manifest_of_hashes(runner, tmp_path):
    runner.run_all(conditions=("B", "C"), runs=1)
    out = tmp_path / "export"
    manifest = export_results(runner.results_engine, out)
    assert manifest["rows"]["runs"] == 12 and manifest["rows"]["effort"] > 0
    runs = list(csv.DictReader((out / "runs.csv").open()))
    assert {r["condition"] for r in runs} == {"B", "C"}
    b01 = next(r for r in runs if r["item"] == "DEMO-01" and r["condition"] == "B")
    assert b01["rules.validated"] == "1" and b01["extraction.techniques.f1"] == "1.0"
    assert b01["model"] == "scripted-1" and len(b01["dataset_sha256"]) == 64
    rules = list(csv.DictReader((out / "rules.csv").open()))
    assert {r["condition"] for r in rules} == {"B", "C"} and all(r["kind"] for r in rules)
    import hashlib
    for name, digest in manifest["sha256"].items():
        assert hashlib.sha256((out / name).read_bytes()).hexdigest() == digest
    # exporting again gives byte-identical files
    again = export_results(runner.results_engine, tmp_path / "export2")
    assert again["sha256"] == manifest["sha256"]


def test_analyst_time_is_exported_with_active_and_wall_time_apart_and_a_content_key(
        runner, tmp_path):
    """Analyst timers live in the live application database; they join to the dataset by the
    item's raw-content hash, and machine effort never contains analyst rows."""
    from app.db.session import init_db
    from app.services import timers
    from tests.unit.test_timers_costs import at
    runner.run_all(conditions=("B",), runs=1)
    live = make_engine("sqlite:///:memory:")
    init_db(live)
    with session_scope(runner.results_engine) as s:
        demo = s.scalars(select(m.IntelligenceItem).where(m.IntelligenceItem.title == "DEMO-01")
                         ).one()
        key, title, raw = demo.intel_id, demo.title, demo.raw_sha256
    with session_scope(live) as s:
        s.add(m.Source(name="Demo Vendor A", source_type="report", reliability_rating="A"))
        s.flush()
        s.add(m.IntelligenceItem(intel_id=key, source_id=1, title=title, raw_sha256=raw,
                                 sanitised_sha256=raw, retrieved_at=at(0)))
        s.flush()
        sid = timers.start(s, analyst="alice", intel_id=key, condition="B",
                           activity="review_approval", now=at(0))
        timers.heartbeat(s, sid, at(60))
        timers.stop(s, sid, at(1000), "accepted")   # 60 s active, then at most 120 s of silence
    manifest = export_results(runner.results_engine, tmp_path / "x", analyst_engines=(live,))
    rows = list(csv.DictReader((tmp_path / "x" / "analyst_effort.csv").open()))
    assert manifest["rows"]["analyst_effort"] == 1 and len(rows) == 1
    row = rows[0]
    assert row["item_key"] == raw and row["analyst"] == "alice" and row["condition"] == "B"
    assert float(row["active_seconds"]) == 180.0 and float(row["wall_seconds"]) == 1000.0
    assert row["disposition"] == "accepted" and row["idle_capped_gaps"] == "1"
    assert float(row["idle_capped_seconds"]) == 820.0
    effort = list(csv.DictReader((tmp_path / "x" / "effort.csv").open()))
    assert effort and all(r["condition"] == "B" and r["component"] != "analyst" for r in effort)


class FailAfter:
    """A model that serves ``n`` calls and then raises ``exc``."""

    def __init__(self, inner, n, exc):
        self.inner, self.n, self.exc = inner, n, exc
        self.provider, self.model = inner.provider, inner.model

    def complete(self, request):
        if self.n <= 0:
            raise self.exc
        self.n -= 1
        return self.inner.complete(request)


def test_what_a_run_spent_before_it_crashed_is_still_counted(runner):
    runner.client_factory = lambda c, i, k: FailAfter(b_model(i), 1, RuntimeError("disk full"))
    rec = runner.run_item(item(runner, "DEMO-01"), "B", 1)
    assert rec.error and "disk full" in rec.error and rec.metrics == {"failed": True}
    saved = json.loads(Path(rec.output_ref).read_text())
    assert saved["cost"]["model_calls"] == 1 and saved["cost"]["input_tokens"] > 0


def test_hitting_the_spend_cap_is_missing_data_not_a_model_failure(runner):
    from components.llm.client import BudgetExceeded
    runner.client_factory = lambda c, i, k: FailAfter(b_model(i), 0, BudgetExceeded(
        "daily cost limit 5.0 reached"))
    rec = runner.run_item(item(runner, "DEMO-01"), "B", 1)
    assert rec.metrics["budget_exceeded"] is True and rec.metrics["failed"] is True
    runner.client_factory = runner.factory                       # an ordinary run, no cap hit
    ordinary = runner.run_item(item(runner, "DEMO-02"), "B", 1)
    assert "budget_exceeded" not in ordinary.metrics


def test_run_costs_separate_demand_spend_and_the_four_kinds_of_time(runner):
    rec = runner.run_item(item(runner, "DEMO-01"), "B", 1)
    cost = json.loads(Path(rec.output_ref).read_text())["cost"]
    assert cost["model_calls"] == cost["fresh_calls"] and cost["replayed_calls"] == 0
    assert set(cost["time"]) == {"wall_seconds", "stage_seconds", "model_wait_seconds",
                                 "automated_seconds", "harness_seconds"}
    saved = json.loads(Path(rec.output_ref).read_text())
    assert "ingest" in saved["stages"] and saved["stages"]["ingest"] >= 0
    assert cost["tokens_reliable"] is False            # the scripted model reports no real usage
    assert cost["usage_sources"] == {"unknown": cost["model_calls"]}


def test_manual_rules_are_registered_and_judged_by_the_same_gates(runner, tmp_path):
    folder = tmp_path / "manual" / "DEMO-01"
    folder.mkdir(parents=True)
    (folder / "encoded_powershell.yml").write_text(C_OUTPUTS["DEMO-01"]["sigma_rules"][0])
    (folder / "bad.yml").write_text("title: [unterminated")
    (folder / "iocs.list").write_text("update.example.net:\n")
    rec = runner.register_manual(item(runner, "DEMO-01"), folder, disposition="accepted")
    rules = rec.metrics["rules"]
    assert rec.condition == "A" and rec.metrics["manual_rule_files"] == 2
    assert rules["sigma_rules"] == 2 and rules["assessed"] == 2
    # the good file is statically fine but fires on the SCCM look-alike (G10), exactly as the
    # single-prompt rule does; the broken file fails G1. Neither is validated.
    assert rules["first_pass_valid"] == 1 and rules["validated"] == 0
    assert {"G1", "G10"} <= set(rules["failed_gates"])
    assert rec.metrics["unjudged_files"] == ["iocs.list"]
    assert rec.metrics["disposition"] == "accepted"
    with session_scope(runner.results_engine) as s:
        row = s.scalars(select(m.ExperimentRun).where(m.ExperimentRun.condition == "A")).one()
        assert row.run_number == 1 and row.output_ref == rec.output_ref
    manifest = export_results(runner.results_engine, tmp_path / "out")
    runs = list(csv.DictReader((tmp_path / "out" / "runs.csv").open()))
    assert manifest["rows"]["runs"] == 1 and runs[0]["condition"] == "A"
    assert runs[0]["rules.assessed"] == "2" and runs[0]["rules.sigma_rules"] == "2"


def test_a_rule_without_test_events_is_unassessed_not_a_gate_failure():
    from app.services.pipeline import PipelineRun, RuleRun
    from research.metrics import rule_metrics
    run = PipelineRun("TI-2026-0001", "B")
    base = dict(opportunity_id=1, decision="behavioral", kind="sigma", loop_status="passed",
                first_pass_valid=True, repairs_used=0, attempts=1, failed_gates=[],
                first_attempt_codes=[])
    run.rules = [RuleRun(rule_id="R1", outcome="validated", **base),
                 RuleRun(rule_id="R2", outcome=None, skipped="no test events", **base),
                 RuleRun(rule_id="R3", outcome="blocked", **{**base, "failed_gates": ["G6"]})]
    r = rule_metrics(run)
    assert (r["rules"], r["assessed"], r["validated"], r["blocked"]) == (3, 2, 1, 1)
