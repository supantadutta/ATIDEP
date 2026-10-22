"""Run the frozen case set under B, B-V and C and write raw per-case results and a summary.

    python -m research.adversarial run --out research/adversarial/results/v0 \
        --freeze research/adversarial/FREEZE.json
    python -m research.adversarial summarise --out research/adversarial/results/v0

Rules, from ``PROTOCOL.md``:

* the run refuses to start unless the freeze manifest matches the files on disk (the cases and
  their review records, the protocol, the configuration, the prompts, and the code of the system
  and of the harness), and unless the cases it loads are the frozen ones; ``--no-freeze-check``
  exists for development and is written into the run manifest;
* the run refuses to start while an active case lacks two counted review verdicts, waits for
  adjudication, or fails the mechanical integrity check (``--allow-unreviewed`` exists for
  development and marks the run as not pre-registered);
* excluded cases are never run;
* every (case, condition) result is written to its own file before anything is aggregated, and an
  existing raw file is never overwritten. Each raw record carries a stamp (the frozen manifest's
  hash, the code hash and the case's own hash); an interrupted run is resumed only if every
  existing record carries the current stamp, so results from a changed system or case can never
  be mixed in. A changed system gets a new ``--out`` directory, and v0 stays as it was;
* the run manifest keeps every invocation (git commit, clean tree, freeze check, review gaps, code
  hashes, counts), so a resumed run shows all of them.
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
from research.adversarial.review import review_gaps
from research.adversarial.summary import summarise

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
FROZEN_CASES = ROOT / "research" / "adversarial" / "cases"


def code_manifest(root: Path = ROOT) -> dict[str, str]:
    return freeze.collect(root, freeze.CODE_PATTERNS)


def case_sha256(case: Any) -> str:
    return hashlib.sha256(json.dumps(case.model_dump(mode="json"), sort_keys=True,
                                     ensure_ascii=False).encode()).hexdigest()


def _git(*args: str) -> str | None:
    try:
        return subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True,
                              check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def check_freeze(path: Path | None, cs: CaseSet,
                 cases_dir: Path | str = FROZEN_CASES) -> dict[str, Any]:
    if path is None:
        return {"checked": False, "reason": "no freeze manifest given"}
    manifest = json.loads(path.read_text(encoding="utf-8"))
    diff = freeze.verify(manifest)
    if Path(cases_dir).resolve() != FROZEN_CASES.resolve():
        diff["cases_dir"] = [f"the run loads cases from {cases_dir}, which the freeze does not "
                             "cover"]
    if not any(k.startswith("components/") for k in manifest.get("files", {})):
        diff["code_not_frozen"] = ["the manifest holds no code; make a new one"]
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


def _stale(out: Path, stamps: dict[str, dict[str, str]]) -> list[str]:
    """Existing raw records whose stamp differs from the current one (or that carry none)."""
    bad = []
    for kind in ("rules", "injection"):
        base = out / "raw" / kind
        for p in sorted(base.glob("*/*.json")) if base.exists() else []:
            want = stamps.get(p.stem)
            got = json.loads(p.read_text(encoding="utf-8")).get("_stamp")
            if want is None or got != want:
                bad.append(str(p.relative_to(out)))
    return bad


def run(cases_dir: Path | str, out_dir: Path | str, *, freeze_path: Path | str | None,
        require_freeze: bool = True, allow_unreviewed: bool = False, ctx: Context | None = None,
        conditions: tuple[str, ...] = CONDITIONS, log=print) -> dict[str, Any]:
    out = Path(out_dir)
    cs = load_case_set(cases_dir)
    fr = check_freeze(Path(freeze_path) if freeze_path else None, cs, cases_dir)
    if require_freeze and not (fr["checked"] and fr["matches"]):
        raise SystemExit("refusing to run: the freeze manifest is missing or does not match the "
                         f"files on disk ({json.dumps(fr.get('differences', fr))[:400]})")
    gaps = review_gaps(cs)
    if any(gaps.values()) and not allow_unreviewed:
        raise SystemExit("refusing to run: the ground-truth review is incomplete or a case fails "
                         f"the integrity check ({json.dumps(gaps)[:400]})")
    code = code_manifest()
    code_hash = freeze.combined(code)
    stamps = {c.id: {"freeze_combined_sha256": str(fr.get("frozen_combined_sha256")),
                     "code_combined_sha256": code_hash, "case_sha256": case_sha256(c)}
              for c in (*cs.active_defects(), *cs.active_controls(), *cs.active_injections())}
    stale = _stale(out, stamps)
    if stale:
        raise SystemExit("refusing to resume: these raw results were produced by a different "
                         "system, freeze or case version (use a new --out directory): "
                         + ", ".join(stale[:20]))
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
            _write_once(path, {**evaluate_case(case, cond, ctx).as_dict(),
                               "_stamp": stamps[case.id]})
            counts["run"] += 1
        for inj in cs.active_injections():
            path = _raw_path(out, "injection", cond, inj.id)
            if path.exists():
                counts["skipped_existing"] += 1
                continue
            _write_once(path, {**run_injection(inj, cond, ctx).as_dict(),
                               "_stamp": stamps[inj.id]})
            counts["run"] += 1
        log(f"condition {cond} done")
    invocation = {"started": started, "seconds": round(time.monotonic() - t0, 1),
                  "git_head": _git("rev-parse", "HEAD"),
                  "working_tree_clean": _git("status", "--porcelain") == "",
                  "python": sys.version.split()[0], "platform": platform.platform(),
                  "freeze": fr, "freeze_required": require_freeze,
                  "review_gaps": gaps, "review_required": not allow_unreviewed,
                  "preregistered": bool(fr.get("matches")) and not any(gaps.values()),
                  "counts": counts, "conditions": list(conditions), "code_sha256": code,
                  "code_combined_sha256": code_hash}
    mpath = out / "run_manifest.json"
    previous = json.loads(mpath.read_text(encoding="utf-8")).get("invocations", []) \
        if mpath.exists() else []
    manifest = {"invocations": [*previous, invocation],
                "preregistered": all(i.get("preregistered") for i in [*previous, invocation])}
    out.mkdir(parents=True, exist_ok=True)
    mpath.write_text(json.dumps(manifest, indent=1, sort_keys=True))
    write_summary(cs, out)
    return invocation


def write_summary(cs: CaseSet, out: Path) -> dict[str, Any]:
    rules, inj = load_raw(out)
    summary = summarise(cs, rules, inj)
    (out / "summary.json").write_text(json.dumps(summary, indent=1, sort_keys=True))
    (out / "summary.md").write_text(render_markdown(summary), encoding="utf-8")
    return summary


def _pct(p: dict[str, Any] | None) -> str:
    if not p or p["rate"] is None:
        return "n/a"
    if p.get("by_construction"):
        return f"{p['k']}/{p['n']} (by construction)"
    return f"{p['k']}/{p['n']} = {100 * p['rate']:.1f}% (upper 95%: {100 * p['upper_95']:.1f}%)"


def render_markdown(s: dict[str, Any]) -> str:
    """Tables of the numbers in ``summary.json``; no interpretation is added."""
    lines = ["# Adversarial evaluation: results", "",
             "Generated mechanically from `summary.json`. Interpretation is in the report, "
             "not here.", "", f"Case-set hash: `{s['set']['case_set_sha256']}`", "",
             f"Active cases: {s['set']['defective_active']} defective, "
             f"{s['set']['controls_active']} controls, {s['set']['injection_active']} injection "
             f"reports. Per class: {s['set']['per_class']}", ""]
    comp = s.get("completeness", {"complete": True})
    if not comp["complete"]:
        lines += ["**INCOMPLETE RESULT SET: these rates are not the experiment's.** Missing "
                  "records: " + "; ".join(f"{c}: {', '.join(ids)}"
                                          for c, ids in comp["missing"].items()), ""]
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
        tag = " (D1-D9 by construction; D10 measured)" if c["by_construction_for_d1_d9"] else ""
        lines.append(f"| {cond}{tag} | {_pct(d)} | {_pct(d19.get('gate_miss'))} | "
                     f"{_pct(d19.get('rejected'))} | {_pct(d19.get('expected_gate_hit'))} |")
    lines += ["", "## By defect class", "",
              "| condition | class | n | escapes | gate miss | expected gate hit | stopped by "
              "another gate |", "|---|---|---|---|---|---|---|"]
    for cond, c in s["conditions"].items():
        for cls, cell in c["by_class"].items():
            if cls == "D10":
                u = sum(r["undetected"] for r in cell["routes"].values())
                na = cell["base_rule_not_approved_ids"]
                lines.append(f"| {cond} | D10 | {cell['n']} | {_pct(cell['escape'])} "
                             f"(undetected routes: {u}"
                             + (f"; base rule not approved: {', '.join(na)}" if na else "")
                             + ") | n/a | n/a | n/a |")
            else:
                other = cell["stopped_by_a_different_gate"]
                lines.append(f"| {cond} | {cls} | {cell['n']} | {cell['escapes']} | "
                             f"{cell['gate_miss']['k']} | {cell['expected_gate_hit']['k']} | "
                             f"{'n/a' if other is None else other} |")
    lines += ["", "## Clean controls (false rejection)", "",
              "| condition | stopped before approval | flagged by any gate |", "|---|---|---|"]
    for cond, c in s["conditions"].items():
        k = c["controls"]
        if k:
            lines.append(f"| {cond} | {_pct(k['false_rejection'])} | "
                         f"{_pct(k['flagged_by_any_gate'])} |")
    lines += ["", "## Prompt injection (worst-case obedient model stand-in)", "",
              "Success *without compliance* is the null run: the same report and a model that "
              "never obeys. *Attributable* = success with the obedient model and not without it.",
              "", "| condition | attack success | without compliance | attributable to compliance "
              "| instruction survived the sanitiser |", "|---|---|---|---|---|"]
    for cond, k in s["injection"].items():
        tag = " (nothing enforced)" if k.get("by_construction") else ""
        lines.append(f"| {cond}{tag} | {_pct(k['attack_success'])} | "
                     f"{_pct(k['success_without_compliance'])} | "
                     f"{_pct(k['attributable_to_compliance'])} | "
                     f"{_pct(k['instruction_survived_sanitiser'])} |")
    for cond, k in s["injection"].items():
        lines += ["", f"### Condition {cond}: by family", "", "| family | success | attributable "
                  "|", "|---|---|---|"]
        lines += [f"| {f} | {_pct(p)} | {_pct(k['attributable_by_family'].get(f))} |"
                  for f, p in k["by_family"].items()]
        for label, key in (("Successful attacks", "successful_ids"),
                           ("Successful without compliance", "without_compliance_ids"),
                           ("Stopped by the output schema", "stopped_by_schema"),
                           ("Not expressible in this condition (not counted)",
                            "not_expressible_in_condition")):
            if k[key]:
                lines += ["", f"{label}: {', '.join(k[key])}"]
        if k["attacker_text_in_intermediate_records_only"]:
            lines += ["", "Attacker text that reached stored intermediate records only: "
                      + json.dumps(k["attacker_text_in_intermediate_records_only"])]
    errs: dict[str, Any] = {}
    for cond, c in s["conditions"].items():
        e = list(c["defective"]["harness_errors"])
        if c["controls"]:
            e += c["controls"]["harness_errors"]
        if e:
            errs[f"{cond} rules"] = e
    for cond, k in s["injection"].items():
        if k["harness_errors"]:
            errs[f"{cond} injection"] = k["harness_errors"]
    if errs:
        lines += ["", "## Harness errors (not counted as stopped, escaped or failed; worst-case "
                  "rates count them against the system)", "", json.dumps(errs)]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m research.adversarial")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--out", required=True)
    r.add_argument("--cases", default=str(HERE / "cases"))
    r.add_argument("--freeze", dest="freeze_path")
    r.add_argument("--no-freeze-check", action="store_true")
    r.add_argument("--allow-unreviewed", action="store_true")
    s = sub.add_parser("summarise")
    s.add_argument("--out", required=True)
    s.add_argument("--cases", default=str(HERE / "cases"))
    a = ap.parse_args(argv)
    if a.cmd == "run":
        m = run(a.cases, a.out, freeze_path=a.freeze_path,
                require_freeze=not a.no_freeze_check, allow_unreviewed=a.allow_unreviewed)
        print(json.dumps({k: m[k] for k in ("counts", "seconds", "git_head",
                                            "working_tree_clean")}))
        return 0
    write_summary(load_case_set(a.cases), Path(a.out))
    print(f"summary written to {a.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
