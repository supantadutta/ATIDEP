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


def test_the_reference_checklist_covers_every_entry_and_marks_none_verified(tmp_path):
    import reference_checklist as rc
    bib = (ROOT / "paper" / "references.bib").read_text()
    entries = rc.parse(bib)
    assert len(entries) == len(re.findall(r"^@\w+\{", bib, flags=re.M))
    text = rc.render(entries)
    assert all(f"`{e['key']}`" in text for e in entries)
    assert text.count("[ ] pending") >= len(entries)
    assert "[x]" not in text and "verified" in text.lower()
    assert "do not cite" in text.lower() and "Drummond" in text
    assert {rc.level(e.get("annote", "")) for e in entries} <= {"V1", "V2", "V3"}


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
