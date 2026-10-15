"""Ground-truth review of the adversarial cases, decided before any case is run (``PROTOCOL.md``).

    python -m research.adversarial.review prepare OUT_DIR       # reviewer-facing copies + batches
    python -m research.adversarial.review apply REVIEWS_DIR     # apply the pre-declared rules

Reviewers see each case **without the author's opinion** (``why``, ``evasive``,
``expected_defence``): only the claim (class, expected gate, attack goal) and the material. Each
case is judged by two reviewers who did not write it; a third settles a case on which exactly one
of the first two says the claimed property is absent. The rule is fixed here, not decided case by
case:

* a case is **excluded** if at least two reviewers judge the claimed property *absent*, or if it
  fails a mechanical integrity check (``integrity_issues``);
* ``unclear`` counts as *not absent*: doubt keeps a case in;
* the reviewers' other notes (incidental defects, doubtful events) are recorded and reported but do
  not exclude a case.

Nothing here looks at how the system treats a case.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from research.adversarial.cases import (
    CLASSES,
    CaseSet,
    InjectionCase,
    RuleCase,
    dump_case,
    load_case_set,
)

HERE = Path(__file__).resolve().parent
VERDICTS = ("present", "absent", "unclear")
AUTHOR_OPINION = ("why", "evasive", "expected_defence", "review", "excluded", "exclusion_reason")
EXCLUDE_AT = 2          # reviewers saying "absent" that exclude a case


def reviewer_view(case: RuleCase | InjectionCase) -> dict[str, Any]:
    data = case.model_dump(mode="json")
    for k in AUTHOR_OPINION:
        data.pop(k, None)
    return data


def batches(cs: CaseSet) -> dict[str, list[str]]:
    """One batch per defect class, per control set and per injection author, so a reviewer holds
    a coherent group of at most a dozen cases."""
    out: dict[str, list[str]] = {}
    for cls in CLASSES:
        ids = [c.id for c in cs.defects if c.defect_class == cls]
        if ids:
            out[cls] = ids
    for prefix in sorted({c.id.split("-")[0] for c in cs.controls}):
        ids = [c.id for c in cs.controls if c.id.startswith(prefix + "-")]
        for k in range(0, len(ids), 6):                       # control sets are split in halves
            out[f"{prefix}{'a' if k == 0 else 'b'}"] = ids[k:k + 6]
    for prefix in sorted({c.id.split("-")[0] for c in cs.injections}):
        out[prefix] = [c.id for c in cs.injections if c.id.startswith(prefix + "-")]
    return out


def prepare(cases_dir: Path | str, out_dir: Path | str) -> dict[str, list[str]]:
    cs = load_case_set(cases_dir)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    for c in (*cs.defects, *cs.controls, *cs.injections):
        dump_case(_Shim(reviewer_view(c)), out / f"{c.id}.yaml")
    plan = batches(cs)
    (out / "batches.json").write_text(json.dumps(plan, indent=1))
    return plan


class _Shim:
    """dump_case wants a pydantic model; the reviewer view is a plain dict."""

    def __init__(self, data: dict[str, Any]) -> None:
        self._d = data

    def model_dump(self, mode: str = "json") -> dict[str, Any]:
        return self._d


def decide(verdicts: list[str], *, issues: list[str]) -> tuple[bool, str, bool]:
    """(excluded, reason, needs_adjudication) for one case from its reviewers' verdicts."""
    if issues:
        return True, "mechanical integrity: " + "; ".join(issues), False
    bad = [v for v in verdicts if v not in VERDICTS]
    if bad:
        raise ValueError(f"unknown verdict(s) {bad}")
    absent = verdicts.count("absent")
    if absent >= EXCLUDE_AT:
        return True, f"claimed property judged absent by {absent} of {len(verdicts)} reviewers", \
            False
    return False, "", absent == 1 and len(verdicts) < 3


def collect(reviews_dir: Path | str) -> dict[str, list[dict[str, Any]]]:
    out: dict[str, list[dict[str, Any]]] = {}
    for p in sorted(Path(reviews_dir).glob("*.json")):
        doc = json.loads(p.read_text(encoding="utf-8"))
        for r in doc.get("reviews", []):
            out.setdefault(r["id"], []).append({**r, "reviewer": doc.get("reviewer"),
                                                "role": doc.get("role"), "file": p.name})
    return out


def apply(cases_dir: Path | str, reviews_dir: Path | str) -> dict[str, Any]:
    cs = load_case_set(cases_dir)
    recs = collect(reviews_dir)
    root = Path(cases_dir)
    summary: dict[str, Any] = {"excluded": [], "needs_adjudication": [], "unreviewed": [],
                               "incidental": {}, "split_votes": []}
    for sub, cases in (("defects", cs.defects), ("controls", cs.controls),
                       ("injection", cs.injections)):
        for case in cases:
            rs = recs.get(case.id, [])
            if len(rs) < 2:
                summary["unreviewed"].append(case.id)
                continue
            verdicts = [r["verdict"] for r in rs]
            excluded, reason, need = decide(verdicts, issues=case.integrity_issues())
            if need:
                summary["needs_adjudication"].append(case.id)
                continue
            if len(set(verdicts)) > 1:
                summary["split_votes"].append({"id": case.id, "verdicts": verdicts})
            notes = [i for r in rs for i in r.get("incidental_issues", [])]
            if notes:
                summary["incidental"][case.id] = notes
            case.review = {"verdicts": [{"reviewer": r["reviewer"], "role": r["role"],
                                         "verdict": r["verdict"],
                                         "confidence": r.get("confidence"),
                                         "reasoning": r.get("reasoning", ""),
                                         "events_ok": r.get("events_ok"),
                                         "incidental_issues": r.get("incidental_issues", [])}
                                        for r in rs]}
            case.excluded, case.exclusion_reason = excluded, reason
            if excluded:
                summary["excluded"].append({"id": case.id, "reason": reason})
            dump_case(case, root / sub / f"{case.id}.yaml")
    return summary


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m research.adversarial.review")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("prepare")
    p.add_argument("out")
    p.add_argument("--cases", default=str(HERE / "cases"))
    a = sub.add_parser("apply")
    a.add_argument("reviews")
    a.add_argument("--cases", default=str(HERE / "cases"))
    a.add_argument("--summary")
    args = ap.parse_args(argv)
    if args.cmd == "prepare":
        plan = prepare(args.cases, args.out)
        print(f"{sum(map(len, plan.values()))} cases in {len(plan)} batches -> {args.out}")
        return 0
    summary = apply(args.cases, args.reviews)
    text = json.dumps(summary, indent=1)
    if args.summary:
        Path(args.summary).write_text(text, encoding="utf-8")
    print(text)
    return 1 if summary["unreviewed"] or summary["needs_adjudication"] else 0


if __name__ == "__main__":
    sys.exit(main())
