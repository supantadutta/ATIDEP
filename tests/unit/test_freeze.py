import json

from research import freeze


def tree(tmp_path):
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "a.yaml").write_text("x: 1\n")
    (tmp_path / "requirements.txt").write_text("numpy==2.0\n")
    return tmp_path


def test_a_manifest_changes_when_any_frozen_file_changes_and_verify_names_it(tmp_path):
    root = tree(tmp_path)
    man = freeze.make("t", root)
    assert set(man["files"]) == {"config/a.yaml", "requirements.txt"}
    assert freeze.verify(man, root) == {"changed": [], "missing": [], "added": []}
    (root / "config" / "a.yaml").write_text("x: 2\n")
    (root / "config" / "b.yaml").write_text("y: 1\n")
    (root / "requirements.txt").unlink()
    assert freeze.verify(man, root) == {"changed": ["config/a.yaml"],
                                        "missing": ["requirements.txt"],
                                        "added": ["config/b.yaml"]}
    assert freeze.make("t", root)["combined_sha256"] != man["combined_sha256"]


def test_the_manifest_records_whether_the_tree_was_clean_and_makes_no_tag(tmp_path):
    man = freeze.make("t", tree(tmp_path))
    assert man["working_tree_clean"] in (True, False) and "tag is created by a person" in man["note"]


def test_the_command_line_round_trips(tmp_path, capsys):
    out = tmp_path / "m.json"
    assert freeze.main(["make", "--label", "prereg-v1", "--out", str(out)]) == 0
    man = json.loads(out.read_text())
    assert man["label"] == "prereg-v1" and "config/cost_rates.yaml" in man["files"]
    assert "config/price_register.yaml" in man["files"] and "requirements.txt" in man["files"]
    assert freeze.main(["verify", str(out)]) == 0
