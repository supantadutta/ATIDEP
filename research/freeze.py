"""Freeze manifest for pre-registration and reproducibility (blueprint §29 item 14).

    python -m research.freeze make --label prereg-v1 --out research/preregistration/prereg-v1.json
    python -m research.freeze verify research/preregistration/prereg-v1.json

The manifest lists the SHA-256 of everything that fixes the study's rules: the configuration
(including the economic inputs and the price register), the prompts, the knowledge files, the
datasets' manifests and labels, the adversarial protocol and case set, and the pinned
requirements. ``verify`` reports every file that has changed, appeared or vanished since. It
records the git commit and whether the working tree was clean, because a manifest made from
uncommitted files is a weaker promise. It does not create the git tag; that is a human act.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PATTERNS = ("config/*.yaml", "prompts/*.md", "knowledge/*.json", "knowledge/*/*.json",
            "research/dataset/*/manifest.yaml", "research/dataset/manifest.yaml",
            "research/adversarial/PROTOCOL.md", "research/adversarial/cases/**/*.yaml",
            "research/preregistration/*.md", "requirements.in", "requirements.txt",
            "pyproject.toml", "docs/ATIDEP_Blueprint_v3.md")


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def collect(root: Path = ROOT) -> dict[str, str]:
    files: dict[str, str] = {}
    for pattern in PATTERNS:
        for p in sorted(root.glob(pattern)):
            if p.is_file():
                files[str(p.relative_to(root))] = _sha(p)
    return files


def _git(*args: str, root: Path = ROOT) -> str | None:
    try:
        return subprocess.run(["git", *args], cwd=root, capture_output=True, text=True,
                              check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def make(label: str, root: Path = ROOT) -> dict[str, object]:
    files = collect(root)
    dirty = _git("status", "--porcelain", root=root)
    combined = hashlib.sha256("\n".join(f"{k} {v}" for k, v in sorted(files.items()))
                              .encode()).hexdigest()
    return {"label": label, "created": datetime.now(UTC).isoformat(timespec="seconds"),
            "git_head": _git("rev-parse", "HEAD", root=root), "working_tree_clean": dirty == "",
            "files": files, "combined_sha256": combined,
            "note": "The git tag is created by a person after committing this file."}


def verify(manifest: dict[str, object], root: Path = ROOT) -> dict[str, list[str]]:
    old = dict(manifest["files"])  # type: ignore[arg-type]
    new = collect(root)
    return {"changed": sorted(k for k in old if k in new and old[k] != new[k]),
            "missing": sorted(k for k in old if k not in new),
            "added": sorted(k for k in new if k not in old)}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m research.freeze")
    sub = ap.add_subparsers(dest="cmd", required=True)
    m = sub.add_parser("make")
    m.add_argument("--label", required=True)
    m.add_argument("--out", required=True)
    v = sub.add_parser("verify")
    v.add_argument("manifest")
    a = ap.parse_args(argv)
    if a.cmd == "make":
        man = make(a.label)
        Path(a.out).parent.mkdir(parents=True, exist_ok=True)
        Path(a.out).write_text(json.dumps(man, indent=1, sort_keys=True))
        print(f"{len(man['files'])} files hashed; working tree clean: {man['working_tree_clean']}")  # type: ignore[arg-type]
        return 0
    diff = verify(json.loads(Path(a.manifest).read_text()))
    for k, names in diff.items():
        for n in names:
            print(f"{k}: {n}")
    return 1 if any(diff.values()) else 0


if __name__ == "__main__":
    sys.exit(main())
