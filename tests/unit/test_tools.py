"""Reproducibility tooling: the lock generator and the licence audit."""

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
