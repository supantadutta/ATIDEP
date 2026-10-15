"""Run the frozen case set under B, B-V and C and write raw per-case results and a summary.

    python -m research.adversarial run --out research/adversarial/results/v0 \
        --freeze research/adversarial/FREEZE.json
    python -m research.adversarial summarise --out research/adversarial/results/v0

Rules, from ``PROTOCOL.md``:

* the run refuses to start unless the freeze manifest matches the files on disk (the cases, the
  protocol, the configuration, the prompts); ``--no-freeze-check`` exists for development and is
  written into the run manifest;
* excluded cases are never run;
* every (case, condition) result is written to its own file before anything is aggregated, and an
  existing raw file is never overwritten (an interrupted run is resumed; a changed system gets a
  new ``--out`` directory, so the v0 results stay as they were);
* the run manifest records the git commit, whether the tree was clean, the case-set hash and a
  hash of every file of the code under test.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from research import freeze
from research.adversarial.cases import CaseSet, load_case_set
from research.adversarial.defects import CONDITIONS, Context, default_context, evaluate_case
from research.adversarial.injection import run_injection
from research.adversarial.summary import summarise

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
CODE_GLOBS = ("components/**/*.py", "app/**/*.py", "schemas/**/*.py", "research/adversarial/*.py",
              "tests/events/*.py", "tests/events/benign_baseline/*.jsonl")


def code_manifest(root: Path = ROOT) -> dict[str, str]:
    files: dict[str, str] = {}
    for pattern in CODE_GLOBS:
        for p in sorted(root.glob(pattern)):
            if p.is_file() and "__pycache__" not in p.parts:
                files[str(p.relative_to(root))] = hashlib.sha256(p.read_bytes()).hexdigest()
    return files


def _git(*args: str) -> str | None:
    try:
        return subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True,
                              check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def check_freeze(path: Path | None, cs: CaseSet) -> dict[str, Any]:
    if path is None:
        return {"checked": False, "reason": "no freeze manifest given"}
    manifest = json.loads(path.read_text(encoding="utf-8"))
    diff = freeze.verify(manifest)
    return {"checked": True, "label": manifest.get("label"),
            "frozen_combined_sha256": manifest.get("combined_sha256"),
            "git_head_at_freeze": manifest.get("git_head"),
            "tree_clean_at_freeze": manifest.get("working_tree_clean"),
            "case_set_sha256": cs.sha256(), "differences": diff,
            "matches": not any(diff.values())}


def _raw_path(out: Path, kind: str, condition: str, case_id: str) -> Path:
    return out / "raw" / kind / condition / f"{case_id}.json"


def _write_once(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        raise FileExistsError(f"{path} already exists; raw results are never overwritten")
    path.write_text(json.dumps(data, indent=1, sort_keys=True, default=str), encoding="utf-8")


def load_raw(out: Path) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    rules: dict[str, dict[str, Any]] = {}
    inj: dict[str, dict[str, Any]] = {}
    for kind, bucket in (("rules", rules), ("injection", inj)):
        base = out / "raw" / kind
        for cond_dir in sorted(base.glob("*")) if base.exists() else []:
            for p in sorted(cond_dir.glob("*.json")):
                bucket.setdefault(cond_dir.name, {})[p.stem] = json.loads(
                    p.read_text(encoding="utf-8"))
    return rules, inj


def run(cases_dir: Path | str, out_dir: Path | str, *, freeze_path: Path | str | None,
        require_freeze: bool = True, ctx: Context | None = None,
        conditions: tuple[str, ...] = CONDITIONS, log=print) -> dict[str, Any]:
    out = Path(out_dir)
    cs = load_case_set(cases_dir)
    fr = check_freeze(Path(freeze_path) if freeze_path else None, cs)
    if require_freeze and not (fr["checked"] and fr["matches"]):
        raise SystemExit("refusing to run: the freeze manifest is missing or does not match the "
                         f"files on disk ({json.dumps(fr.get('differences', fr))[:400]})")
    ctx = ctx or default_context()
    started = datetime.now(UTC).isoformat(timespec="seconds")
    t0 = time.monotonic()
    counts = {"run": 0, "skipped_existing": 0}
    for cond in conditions:
        for case in (*cs.active_defects(), *cs.active_controls()):
            path = _raw_path(out, "rules", cond, case.id)
            if path.exists():
                counts["skipped_existing"] += 1
                continue
            _write_once(path, evaluate_case(case, cond, ctx).as_dict())
            counts["run"] += 1
        for inj in cs.active_injections():
            path = _raw_path(out, "injection", cond, inj.id)
            if path.exists():
                counts["skipped_existing"] += 1
                continue
            _write_once(path, run_injection(inj, cond, ctx).as_dict())
            counts["run"] += 1
        log(f"condition {cond} done")
    manifest = {"started": started, "seconds": round(time.monotonic() - t0, 1),
                "git_head": _git("rev-parse", "HEAD"),
                "working_tree_clean": _git("status", "--porcelain") == "",
                "python": sys.version.split()[0], "platform": platform.platform(),
                "freeze": fr, "freeze_required": require_freeze, "counts": counts,
                "conditions": list(conditions), "code_sha256": code_manifest(),
                "code_combined_sha256": hashlib.sha256(
                    json.dumps(code_manifest(), sort_keys=True).encode()).hexdigest()}
    (out / "run_manifest.json").write_text(json.dumps(manifest, indent=1, sort_keys=True))
    write_summary(cs, out)
    return manifest


def write_summary(cs: CaseSet, out: Path) -> dict[str, Any]:
    rules, inj = load_raw(out)
    summary = summarise(cs, rules, inj)
    (out / "summary.json").write_text(json.dumps(summary, indent=1, sort_keys=True))
    (out / "summary.md").write_text(render_markdown(summary), encoding="utf-8")
    return summary


def _pct(p: dict[str, Any] | None) -> str:
    if not p or p["rate"] is None:
        return "n/a"
    return f"{p['k']}/{p['n']} = {100 * p['rate']:.1f}% (upper 95%: {100 * p['upper_95']:.1f}%)"


def render_markdown(s: dict[str, Any]) -> str:
    """Tables of the numbers in ``summary.json``; no interpretation is added."""
    lines = ["# Adversarial evaluation: results", "",
             "Generated mechanically from `summary.json`. Interpretation is in the report, "
             "not here.", "", f"Case-set hash: `{s['set']['case_set_sha256']}`", "",
             f"Active cases: {s['set']['defective_active']} defective, "
             f"{s['set']['controls_active']} controls, {s['set']['injection_active']} injection "
             f"reports. Per class: {s['set']['per_class']}", ""]
    if s["requirements_unmet"]:
        lines += ["**Protocol requirements not met by the active set:** "
                  + "; ".join(s["requirements_unmet"]), ""]
    if s["excluded"]:
        lines += ["## Excluded cases", "", "| case | reason |", "|---|---|"]
        lines += [f"| {e['id']} | {e['reason']} |" for e in s["excluded"]] + [""]
    lines += ["## Defective rules", "",
              "| condition | escape (D1-D9 reached Approved; D10 undetected tamper) | gate miss "
              "(D1-D9, every gate passed) | rejected before approval (D1-D9) | expected gate hit |",
              "|---|---|---|---|---|"]
    for cond, c in s["conditions"].items():
        d = c["defective"]
        d19 = c["d1_d9"] or {}
        tag = " (by construction for D1-D9)" if c["by_construction_for_d1_d9"] else ""
        lines.append(f"| {cond}{tag} | {_pct(d)} | {_pct(d19.get('gate_miss'))} | "
                     f"{_pct(d19.get('rejected'))} | {_pct(d19.get('expected_gate_hit'))} |")
    lines += ["", "## By defect class", "",
              "| condition | class | n | escapes | gate miss | expected gate hit | stopped by "
              "another gate |", "|---|---|---|---|---|---|---|"]
    for cond, c in s["conditions"].items():
        for cls, cell in c["by_class"].items():
            if cls == "D10":
                u = sum(r["undetected"] for r in cell["routes"].values())
                lines.append(f"| {cond} | D10 | {cell['n']} | {_pct(cell['escape'])} "
                             f"(undetected routes: {u}) | n/a | n/a | n/a |")
            else:
                lines.append(f"| {cond} | {cls} | {cell['n']} | {cell['escapes']} | "
                             f"{cell['gate_miss']['k']} | {cell['expected_gate_hit']['k']} | "
                             f"{cell['stopped_by_a_different_gate']} |")
    lines += ["", "## Clean controls (false rejection)", "",
              "| condition | stopped before approval | flagged by any gate |", "|---|---|---|"]
    for cond, c in s["conditions"].items():
        k = c["controls"]
        if k:
            lines.append(f"| {cond} | {_pct(k['false_rejection'])} | "
                         f"{_pct(k['flagged_by_any_gate'])} |")
    lines += ["", "## Prompt injection (worst-case obedient model stand-in)", "",
              "| condition | attack success | instruction survived the sanitiser |",
              "|---|---|---|"]
    for cond, k in s["injection"].items():
        lines.append(f"| {cond} | {_pct(k['attack_success'])} | "
                     f"{_pct(k['instruction_survived_sanitiser'])} |")
    for cond, k in s["injection"].items():
        lines += ["", f"### Condition {cond}: by family", "", "| family | success |", "|---|---|"]
        lines += [f"| {f} | {_pct(p)} |" for f, p in k["by_family"].items()]
        if k["successful_ids"]:
            lines += ["", f"Successful attacks: {', '.join(k['successful_ids'])}"]
    errs = {cond: c["defective"]["harness_errors"] for cond, c in s["conditions"].items()
            if c["defective"]["harness_errors"]}
    if errs:
        lines += ["", "## Harness errors (not counted as stopped or escaped)", "", json.dumps(errs)]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m research.adversarial")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--out", required=True)
    r.add_argument("--cases", default=str(HERE / "cases"))
    r.add_argument("--freeze", dest="freeze_path")
    r.add_argument("--no-freeze-check", action="store_true")
    s = sub.add_parser("summarise")
    s.add_argument("--out", required=True)
    s.add_argument("--cases", default=str(HERE / "cases"))
    a = ap.parse_args(argv)
    if a.cmd == "run":
        m = run(a.cases, a.out, freeze_path=a.freeze_path,
                require_freeze=not a.no_freeze_check)
        print(json.dumps({k: m[k] for k in ("counts", "seconds", "git_head",
                                            "working_tree_clean")}))
        return 0
    write_summary(load_case_set(a.cases), Path(a.out))
    print(f"summary written to {a.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
