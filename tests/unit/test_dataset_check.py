"""The readiness check for the real dataset. The fixtures here are throwaway test data built in a
temporary folder; they are not a dataset and carry no research meaning."""

import json
import shutil
from datetime import date
from pathlib import Path

import pytest
import yaml

from research.dataset.check import EXPECTED, check_dataset, main

ROOT = Path(__file__).resolve().parents[2]
DEMO = ROOT / "research" / "dataset"
CUTOFF = date(2026, 1, 1)


def build(root: Path, *, published="2026-06-01", synthetic=False, tag="T") -> Path:
    """A well-formed 30-item dataset with the required composition."""
    (root / "items").mkdir(parents=True)
    shutil.copytree(DEMO / "sets" / "demo01", root / "sets" / "ev")
    items = []
    n = 0
    for category, count in EXPECTED.items():
        for k in range(count):
            n += 1
            iid = f"{tag}{n:02d}"
            (root / "items" / f"{iid}.txt").write_text(f"report {tag} {iid} {category} {k}\n")
            if category == "ioc":
                gt = {"detectable": True, "decisions": ["ioc_based"],
                      "indicators": [{"type": "domain", "value": f"bad{n}.example.net"}],
                      "required_log_source": "windows_dns_query"}
            elif category in ("behaviour", "mixed"):
                gt = {"detectable": True, "decisions": ["behavioral"],
                      "techniques": ["T1059.001"],
                      "required_log_source": "windows_process_creation"}
            else:
                gt = {"detectable": False, "decisions": ["not_relevant"]}
            item = {"id": iid, "file": f"items/{iid}.txt", "category": category,
                    "source": {"name": "fixture"}, "published": published, "ground_truth": gt}
            if category in ("behaviour", "mixed"):
                item["test_events"] = "sets/ev"
            items.append(item)
    (root / "manifest.yaml").write_text(yaml.safe_dump(
        {"dataset_id": "fixture", "synthetic": synthetic, "seed": 7, "items": items}))
    return root


def second(root: Path, ids, flip=(), techniques=None) -> Path:
    data = yaml.safe_load((root / "manifest.yaml").read_text())
    gts = {i["id"]: i["ground_truth"] for i in data["items"]}
    out = {}
    for iid in ids:
        det = gts[iid]["detectable"] != (iid in flip)
        out[iid] = {"detectable": det,
                    "techniques": (techniques or {}).get(iid, gts[iid].get("techniques", []))}
    p = root / "second.yaml"
    p.write_text(yaml.safe_dump(out))
    return p


def codes(rep, level="blocker"):
    return {f.code for f in rep.findings if f.level == level}


def spread(root: Path, per_category=3):
    """Items covering every category, to give the second labeller a stratified third."""
    data = yaml.safe_load((root / "manifest.yaml").read_text())
    out, seen = [], {}
    for i in data["items"]:
        seen[i["category"]] = seen.get(i["category"], 0) + 1
        if seen[i["category"]] <= per_category:
            out.append(i["id"])
    return out


def test_the_synthetic_demo_dataset_is_never_ready():
    rep = check_dataset(DEMO)
    assert not rep.ready
    assert {"synthetic", "composition", "cutoff_unknown", "second_labels_missing"} <= codes(rep)


def test_a_complete_dataset_with_agreeing_second_labels_has_no_blockers(tmp_path):
    root = build(tmp_path / "d")
    ids = spread(root, 4)                                    # 4+4+4+4 = 16 >= a third of 30
    rep = check_dataset(root, model_cutoff=CUTOFF, second_labels=second(root, ids))
    assert rep.ready, [vars(f) for f in rep.blockers]
    assert rep.facts["composition"] == EXPECTED
    assert rep.facts["agreement"]["detectable_kappa"] == 1.0
    assert rep.facts["agreement"]["technique_jaccard_mean"] == 1.0
    assert rep.facts["second_labeller_items"] == 16 and rep.facts["second_labeller_required"] == 10
    assert sum(sum(v.values()) for v in rep.facts["order_sets"].values()) == 30


def test_agreement_is_computed_from_the_two_label_files(tmp_path):
    root = build(tmp_path / "d")
    ids = spread(root, 4)
    flip = {ids[0], ids[5]}                                   # two detectable disagreements
    tech = {ids[8]: ["T1059.001", "T1105"]}                   # one technique set differs: 1/2
    rep = check_dataset(root, model_cutoff=CUTOFF,
                        second_labels=second(root, ids, flip=flip, techniques=tech))
    a = rep.facts["agreement"]
    assert a["disagreements"] == sorted(flip)
    assert a["detectable_raw_agreement"] == pytest.approx(14 / 16)
    assert 0 < a["detectable_kappa"] < 1
    assert a["technique_jaccard_mean"] < 1.0


def test_too_few_or_unstratified_second_labels_block(tmp_path):
    root = build(tmp_path / "d")
    few = check_dataset(root, model_cutoff=CUTOFF, second_labels=second(root, spread(root, 1)))
    assert "second_labels_too_few" in codes(few)              # 4 items < 10
    ioc_only = [i["id"] for i in yaml.safe_load((root / "manifest.yaml").read_text())["items"]
                if i["category"] == "ioc"]
    rep = check_dataset(root, model_cutoff=CUTOFF, second_labels=second(root, ioc_only))
    assert "second_labels_not_stratified" in codes(rep)
    assert "second_labels_too_few" not in codes(rep)          # 10 items, but only one category


def test_reports_not_after_the_cutoff_or_without_a_date_block(tmp_path):
    old = build(tmp_path / "old", published="2025-12-31")
    assert "before_cutoff" in codes(check_dataset(old, model_cutoff=CUTOFF))
    same = build(tmp_path / "same", published="2026-01-01")
    assert "before_cutoff" in codes(check_dataset(same, model_cutoff=CUTOFF))   # strictly after
    data = yaml.safe_load((old / "manifest.yaml").read_text())
    data["items"][0]["published"] = None
    (old / "manifest.yaml").write_text(yaml.safe_dump(data))
    assert "no_publication_date" in codes(check_dataset(old, model_cutoff=CUTOFF))


def test_wrong_composition_missing_labels_and_incomplete_events_block(tmp_path):
    root = build(tmp_path / "d")
    data = yaml.safe_load((root / "manifest.yaml").read_text())
    data["items"] = data["items"][1:]                          # drop one ioc item
    beh = next(i for i in data["items"] if i["category"] == "behaviour")
    beh.pop("test_events")
    beh2 = [i for i in data["items"] if i["category"] == "behaviour"][1]
    beh2["ground_truth"] = None
    (root / "manifest.yaml").write_text(yaml.safe_dump(data))
    rep = check_dataset(root, model_cutoff=CUTOFF)
    assert {"composition", "no_events", "no_ground_truth"} <= codes(rep)
    shutil.rmtree(root / "sets" / "ev" / "benign_lookalike")
    (root / "sets" / "ev" / "benign_lookalike").mkdir()
    assert "event_set_incomplete" in codes(check_dataset(root, model_cutoff=CUTOFF))


def test_duplicate_reports_and_pilot_overlap_block(tmp_path):
    root = build(tmp_path / "test", tag="T")
    (root / "items" / "T02.txt").write_text((root / "items" / "T01.txt").read_text())
    assert "duplicate_content" in codes(check_dataset(root, model_cutoff=CUTOFF))
    clean = build(tmp_path / "test2", tag="U")
    pilot = build(tmp_path / "pilot", tag="P")
    assert "pilot_overlap" not in codes(check_dataset(clean, model_cutoff=CUTOFF, pilot_root=pilot))
    (pilot / "items" / "P03.txt").write_text((clean / "items" / "U05.txt").read_text())
    assert "pilot_overlap" in codes(check_dataset(clean, model_cutoff=CUTOFF, pilot_root=pilot))
    assert "pilot_not_checked" in codes(check_dataset(clean, model_cutoff=CUTOFF), "note")


def test_adversarial_items_are_outside_the_composition_and_a_bad_manifest_is_reported(tmp_path):
    root = build(tmp_path / "d")
    data = yaml.safe_load((root / "manifest.yaml").read_text())
    adv = dict(data["items"][0], id="ADV01", adversarial=True)
    (root / "items" / "ADV01.txt").write_text("hostile text")
    adv["file"] = "items/ADV01.txt"
    data["items"].append(adv)
    (root / "manifest.yaml").write_text(yaml.safe_dump(data))
    assert "composition" not in codes(check_dataset(root, model_cutoff=CUTOFF))
    (root / "manifest.yaml").write_text("dataset_id: x\nitems: not-a-list\n")
    assert codes(check_dataset(root)) == {"manifest_invalid"}


def test_the_cli_exit_status_and_json_output(tmp_path, capsys):
    root = build(tmp_path / "d")
    ids = spread(root, 4)
    ok = main(["check", str(root), "--cutoff", "2026-01-01", "--second-labels",
               str(second(root, ids)), "--json"])
    out = json.loads(capsys.readouterr().out)
    assert ok == 0 and out["ready_for_main_run"] is True
    assert main(["check", str(DEMO)]) == 1
    assert "NOT READY" in capsys.readouterr().out
