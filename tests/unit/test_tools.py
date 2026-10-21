"""Reproducibility tooling: the lock generator and the licence audit."""

import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))

import licence_audit  # noqa: E402
import make_lock  # noqa: E402


def test_the_lock_pins_every_direct_dependency_and_matches_the_committed_file():
    names = make_lock.direct(ROOT / "requirements.in")
    pins, missing = make_lock.closure(names)
    assert not missing
    for n in names:
        assert make_lock.norm(n.split()[0]) in pins                   # each direct dep is pinned
    # the committed requirements.txt is exactly what the generator produces here
    assert (ROOT / "requirements.txt").read_text() == make_lock.render(pins, names)
    assert all("==" in line for line in (ROOT / "requirements.txt").read_text().splitlines()
               if line and not line.startswith("#"))


def test_the_direct_dependencies_are_declared_in_pyproject_too():
    text = (ROOT / "pyproject.toml").read_text().lower()
    for n in make_lock.direct(ROOT / "requirements.in"):
        assert make_lock.norm(n.split()[0]).replace("-", "") in text.replace("-", ""), n


@pytest.mark.parametrize("expr,ok", [
    ("MIT", True), ("MIT License", True), ("BSD-3-Clause", True),
    ("Apache-2.0 OR BSD-2-Clause", True), ("MIT AND PSF-2.0", True),
    ("BSD-3-Clause AND CC0-1.0", False),               # CC0 is not an OSI-approved licence
    ("MIT-CMU", False), ("Proprietary", False), ("", False),
    ("LGPL-2.1-only", True),
])
def test_osi_recognition(expr, ok):
    assert licence_audit.recognised(expr) is ok


def test_every_package_states_a_licence_and_unknown_ones_are_listed_not_hidden():
    rows = licence_audit.audit()
    assert len(rows) > 40 and all(r["licence"] for r in rows)
    flagged = {r["package"] for r in rows if r["osi_status"] != "recognised"}
    assert flagged <= {"numpy", "pillow"}                  # the ones this tool cannot confirm
    ext = {c["name"]: c for c in licence_audit.externals()}
    assert not any(c["verified"] for c in ext.values())     # nothing is claimed as verified
    assert ext["Language model weights"]["licence_as_stated"] is None


def test_the_audit_writes_a_bill_of_materials(tmp_path):
    assert licence_audit.main(["--out", str(tmp_path)]) == 0
    md = (tmp_path / "bill_of_materials.md").read_text()
    assert "## Python packages" in md and "Language model weights" in md and "NOT SET" in md
    assert (tmp_path / "python_packages.csv").exists()


def test_the_reference_checklist_covers_every_entry_and_marks_no_paper_full_text_verified():
    import reference_checklist as rc
    bib = (ROOT / "paper" / "references.bib").read_text()
    entries = rc.parse(bib)
    records = rc.load_records(ROOT / "paper" / "verification_records.yaml")
    assert len(entries) == len(re.findall(r"^@\w+\{", bib, flags=re.M))
    assert {e["key"] for e in entries} == set(records)          # one record per entry
    text = rc.render(entries, records)
    assert all(f"`{e['key']}`" in text for e in entries)
    papers = [e for e in entries if rc.level(e.get("annote", "")) != "P"]
    assert text.count(f"[ ] {rc.FULL_TEXT_PENDING}") == len(papers)
    assert "do not cite" in text.lower() and "Drummond" in text
    assert {rc.level(e.get("annote", "")) for e in entries} <= {"P", "E-A", "E-M"}
    # a source read directly is software or documentation, never a paper
    for e in entries:
        if rc.level(e.get("annote", "")) == "P":
            assert e["type"] in ("online", "misc") and records[e["key"]]["peer_reviewed"].startswith("no")
    assert (ROOT / "paper" / "verification_checklist.md").read_text() == text


def test_a_flagged_sentence_is_shown_unresolved_until_a_rewording_is_recorded():
    import reference_checklist as rc
    entry = {"key": "k", "type": "article", "title": "T", "annote": "E-A: extract"}
    check = {"status": "partly_supported", "excerpt": "an overstated sentence"}
    rec = {"k": {"key": "k", "claim_checks": [check]}}
    assert "an overstated sentence **Unresolved.**" in rc.render([entry], rec)
    check["resolution"] = "reworded"
    text = rc.render([entry], rec)
    assert "**Resolution:** reworded" in text and "Unresolved" not in text
    assert f"[ ] {rc.FULL_TEXT_PENDING}" in text          # a rewording is not a full-text check


# ---- model probe (evidence for spike S3; it selects nothing) -----------------------------
def _ollama_stub(reply_text):
    """A loopback server speaking the two Ollama routes the probe uses."""
    import json as _json
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    class H(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802 - http.server API
            self.rfile.read(int(self.headers["Content-Length"]))
            if self.path == "/api/show":
                body = {"details": {"family": "stubfam", "parameter_size": "1B",
                                    "quantization_level": "Q4"},
                        "license": "Example licence text", "model_info": {"a.b": 1}}
            else:
                body = {"model": "stub:1", "message": {"content": reply_text},
                        "prompt_eval_count": 120, "eval_count": 30, "total_duration": 2_000_000}
            out = _json.dumps(body).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)

        def log_message(self, *a):
            pass

    server = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def test_model_probe_records_identity_and_rates_but_never_selects(tmp_path, capsys):
    import json as _json

    import model_probe
    server = _ollama_stub('{"behaviors": [], "entities": []}')
    try:
        out = tmp_path / "probe.json"
        rc = model_probe.main(["--provider", "ollama", "--model", "stub:1", "--smoke",
                               "--url", f"http://127.0.0.1:{server.server_port}",
                               "--out", str(out)])
    finally:
        server.shutdown()
    report = _json.loads(out.read_text())
    assert rc == 0 and report["smoke_only"] is True
    assert report["decision"].startswith("pending") and report["model_pinned"] is False
    assert report["training_cutoff"] is None                    # the tool cannot know it
    assert report["identity"]["family"] == "stubfam"
    assert report["identity"]["licence_text_present"] is True
    assert report["usage_probe"]["stable"] is True
    pilot = report["pilot"]
    assert pilot["chunks"] >= 7 and pilot["post_retry_schema_valid"] == 1.0
    assert pilot["first_attempt_schema_valid"] == 1.0 and pilot["meets_s3_schema_criterion"]
    assert pilot["quote_verbatim_rate"] is None                 # nothing was quoted
    assert pilot["usage_sources"] == {"provider": pilot["chunks"]}


def test_model_probe_counts_unparseable_output_against_the_criterion(tmp_path):
    import json as _json

    import model_probe
    server = _ollama_stub("not json at all")
    try:
        out = tmp_path / "probe.json"
        model_probe.main(["--provider", "ollama", "--model", "stub:1", "--smoke",
                          "--url", f"http://127.0.0.1:{server.server_port}", "--out", str(out)])
    finally:
        server.shutdown()
    pilot = _json.loads(out.read_text())["pilot"]
    assert pilot["post_retry_schema_valid"] == 0.0
    assert pilot["first_attempt_schema_valid"] == 0.0
    assert pilot["meets_s3_schema_criterion"] is False


def test_model_probe_requires_items_or_smoke():
    import model_probe
    with pytest.raises(SystemExit):
        model_probe.main(["--provider", "ollama", "--model", "x"])


# ---- related-work matrix: no capability marked without evidence --------------------------
def _row(**over):
    import related_work_matrix as rw
    cells = {c: {"value": "Not reported"} for c, _ in rw.COLUMNS}
    row = {"key": "k1", "year": "2026", "name": "System", "level": "abstract_via_search_extract",
           "relevance": "close", "limitation": "no deployment reported", "cells": cells}
    row.update(over)
    return row


def test_the_matrix_refuses_a_marked_cell_without_evidence_or_source():
    import related_work_matrix as rw
    r = _row()
    r["cells"]["rule_generation"] = {"value": "Yes"}
    with pytest.raises(rw.MatrixError, match="needs evidence"):
        rw.validate([r])
    r["cells"]["rule_generation"] = {"value": "Yes", "evidence": "generates Sigma rules",
                                     "source": "https://example.invalid/x"}
    rw.validate([r])
    r["cells"]["human_approval"] = {"value": "No"}                    # absence also needs a source
    with pytest.raises(rw.MatrixError):
        rw.validate([r])


def test_the_matrix_refuses_unknown_values_levels_keys_and_duplicates():
    import related_work_matrix as rw
    bad = _row()
    bad["cells"]["open_source"] = {"value": "Probably"}
    with pytest.raises(rw.MatrixError, match="value must be"):
        rw.validate([bad])
    with pytest.raises(rw.MatrixError, match="level"):
        rw.validate([_row(level="skimmed")])
    with pytest.raises(rw.MatrixError, match="bibliography"):
        rw.validate([_row()], bib_keys={"other"})
    with pytest.raises(rw.MatrixError, match="duplicate"):
        rw.validate([_row(), _row()])


def test_the_matrix_renders_evidence_and_says_full_text_is_pending():
    import related_work_matrix as rw
    r = _row()
    r["cells"]["rule_generation"] = {"value": "Partial", "evidence": "drafts rules",
                                     "source": "https://example.invalid/x"}
    text = rw.render({"rows": [r], "preamble": "P"})
    assert "| System [@k1] | 2026 |" in text and "| A |" in text
    assert "drafts rules" in text and "full-text verification is pending" in text.lower()
    assert "every cell is Not reported" not in text


def test_the_committed_matrix_is_valid_and_matches_its_data():
    import related_work_matrix as rw
    data_path = ROOT / "paper" / "related_work.yaml"
    if not data_path.exists():
        pytest.skip("matrix data not written yet")
    data = rw.load(data_path, ROOT / "paper" / "references.bib")
    assert (ROOT / "paper" / "related_work_matrix.md").read_text() == rw.render(data)
    chapter = (ROOT / "paper" / "chapters" / "02_literature_review.md").read_text()
    a, b = chapter.index(rw.BEGIN) + len(rw.BEGIN), chapter.index(rw.END)
    assert chapter[a:b].strip() == rw.render_table(data, rw.CHAPTER_CAPTION).strip()
    brief = (ROOT / "docs" / "supervisor_brief.md").read_text()
    a, b = brief.index(rw.BEGIN) + len(rw.BEGIN), brief.index(rw.END)
    assert brief[a:b].strip() == rw.render_table(data, rw.BRIEF_CAPTION, rw.BRIEF_KEYS).strip()


def test_sync_chapter_replaces_only_the_marked_block(tmp_path):
    import related_work_matrix as rw
    r = _row()
    p = tmp_path / "ch.md"
    p.write_text(f"before\n{rw.BEGIN}\nold\n{rw.END}\nafter\n")
    assert rw.sync_chapter(p, {"rows": [r]}, "Cap") is True
    text = p.read_text()
    assert text.startswith("before\n") and text.endswith("after\n") and "old" not in text
    assert "| System [@k1] | 2026 |" in text and ": Cap" in text
    assert rw.sync_chapter(p, {"rows": [r]}, "Cap") is False          # idempotent
    unmarked = tmp_path / "unmarked.md"
    unmarked.write_text("no markers here\n")
    with pytest.raises(rw.MatrixError, match="markers"):
        rw.sync_chapter(unmarked, {"rows": [r]}, "Cap")


def test_a_matrix_subset_keeps_only_the_named_rows_and_refuses_unknown_keys():
    import related_work_matrix as rw
    data = {"rows": [_row(), _row(key="k2", name="Other")]}
    text = rw.render_table(data, "Cap", ["k2"])
    assert "[@k2]" in text and "[@k1]" not in text and "| M1 |" in text
    with pytest.raises(rw.MatrixError, match="not in the matrix"):
        rw.render_table(data, "Cap", ["missing"])
