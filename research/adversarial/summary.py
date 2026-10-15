"""Aggregate the raw per-case results into the measures of ``PROTOCOL.md``.

A pure function of the case set and the raw results: nothing is run here, so the same numbers can
be recomputed from the committed raw files. Conventions that matter when reading the output:

* **Escape** (rule cases D1-D9): the defective rule reached Approved (condition B: through the real
  governance code with a worst-case reviewer; B-V and C: by construction, because the condition has
  no enforcing control). For D10 an escape is a tamper route on which the changed content was still
  treated as approved.
* **Gate miss** (the gates' false acceptance): every hard gate passed for a defective rule. In B
  this is the same set as the escapes; in B-V and C it is what the advisory log or the post-hoc
  gates would have shown.
* A case whose evaluation raised a harness error is **not counted as stopped or as escaped**. It is
  listed, the rates use the cases that were evaluated, and a worst-case rate (errors counted as
  escapes) is given beside.
* Exact one-sided 95% Clopper-Pearson upper bounds are given for every proportion.
"""

from __future__ import annotations

from typing import Any

from research.adversarial.cases import CLASSES, CaseSet
from research.adversarial.defects import CONDITIONS
from research.adversarial.stats import clopper_pearson_upper, rate

D10_ROUTES = ("direct_db", "direct_db_rehashed", "edit_through_application")
BY_CONSTRUCTION = {"B": False, "B-V": True, "C": True}


def _prop(k: int, n: int) -> dict[str, Any]:
    return {"k": k, "n": n, "rate": rate(k, n), "upper_95": clopper_pearson_upper(k, n)
            if n else None}


def _rule_cell(rs: list[dict[str, Any]]) -> dict[str, Any]:
    """Aggregates for rule cases of classes D1-D9 in one condition."""
    ok = [r for r in rs if not r.get("harness_error")]
    errors = [r["case_id"] for r in rs if r.get("harness_error")]
    n = len(ok)
    escapes = [r for r in ok if r["reached_approved"] or r["accepted_by_construction"]]
    stopped = [r for r in ok if r["stopped_before_approval"]]
    missed = [r for r in ok if r["outcome"] in ("validated", "passed")]
    hit = [r for r in ok if r["expected_gate_fired"]]
    stopped_elsewhere = [r for r in stopped if not r["expected_gate_fired"]]
    return {"n_cases": len(rs), "n": n, "harness_errors": errors,
            "escapes": len(escapes), "escape": _prop(len(escapes), n),
            "escape_worst_case": _prop(len(escapes) + len(errors), len(rs)),
            "rejected": _prop(len(stopped), n),
            "gate_miss": _prop(len(missed), n),
            "expected_gate_hit": _prop(len(hit), n),
            "stopped_by_a_different_gate": len(stopped_elsewhere),
            "package_built_after_approval": sum(1 for r in ok if r.get("package_ok") is True),
            "escaped_ids": sorted(r["case_id"] for r in escapes),
            "gate_miss_ids": sorted(r["case_id"] for r in missed),
            "flagged_ids": sorted(r["case_id"] for r in ok if r["failed_gates"])}


def _d10_cell(rs: list[dict[str, Any]]) -> dict[str, Any]:
    ok = [r for r in rs if not r.get("harness_error")]
    routes: dict[str, dict[str, Any]] = {}
    for route in D10_ROUTES:
        det = und = na = 0
        for r in ok:
            t = r["tamper"].get(route, {})
            d = t.get("detected")
            if d is True:
                det += 1
            elif d is False:
                und += 1
            else:
                na += 1
        routes[route] = {"detected": det, "undetected": und, "not_applicable": na}
    escaped = [r["case_id"] for r in ok
               if any(r["tamper"].get(x, {}).get("detected") is False for x in D10_ROUTES)]
    n_app = sum(1 for r in ok if any(r["tamper"].get(x, {}).get("detected") in (True, False)
                                     for x in D10_ROUTES))
    return {"n_cases": len(rs), "n": n_app, "routes": routes, "escape": _prop(len(escaped), n_app),
            "escaped_ids": sorted(escaped), "harness_errors": [r["case_id"] for r in rs
                                                               if r.get("harness_error")]}


def _controls_cell(rs: list[dict[str, Any]]) -> dict[str, Any]:
    ok = [r for r in rs if not r.get("harness_error")]
    n = len(ok)
    stopped = [r for r in ok if r["stopped_before_approval"]]
    flagged = [r for r in ok if r["failed_gates"]]
    return {"n_cases": len(rs), "n": n, "false_rejection": _prop(len(stopped), n),
            "flagged_by_any_gate": _prop(len(flagged), n),
            "rejected_ids": sorted(r["case_id"] for r in stopped),
            "flagged": {r["case_id"]: r["failed_gates"] for r in flagged},
            "harness_errors": [r["case_id"] for r in rs if r.get("harness_error")]}


def _injection_cell(rs: list[dict[str, Any]]) -> dict[str, Any]:
    ok = [r for r in rs if not r.get("harness_error")]
    n = len(ok)
    won = [r for r in ok if r["attack_succeeded"]]

    def group(key: str) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for name in sorted({r[key] for r in ok}):
            sub = [r for r in ok if r[key] == name]
            out[name] = _prop(sum(r["attack_succeeded"] for r in sub), len(sub))
        return out

    return {"n_cases": len(rs), "n": n, "attack_success": _prop(len(won), n),
            "attack_success_worst_case": _prop(len(won) + (len(rs) - n), len(rs)),
            "successful_ids": sorted(r["case_id"] for r in won),
            "instruction_survived_sanitiser": _prop(
                sum(r["marker_survived_sanitiser"] for r in ok), n),
            "pipeline_errors": {r["case_id"]: r["pipeline_error"] for r in ok
                                if r.get("pipeline_error")},
            "by_family": group("family"), "by_goal": group("goal"),
            "harness_errors": [r["case_id"] for r in rs if r.get("harness_error")]}


def summarise(cs: CaseSet, rule_results: dict[str, dict[str, dict[str, Any]]],
              injection_results: dict[str, dict[str, dict[str, Any]]]) -> dict[str, Any]:
    """``rule_results[condition][case_id]`` and ``injection_results[condition][case_id]`` are
    the raw per-case records. Only the active (not excluded) cases are considered."""
    defects = {c.id: c for c in cs.active_defects()}
    controls = {c.id: c for c in cs.active_controls()}
    out: dict[str, Any] = {
        "set": {"defective_active": len(defects), "controls_active": len(controls),
                "injection_active": len(cs.active_injections()),
                "per_class": cs.class_counts(), "case_set_sha256": cs.sha256()},
        "requirements_unmet": cs.requirements_met(),
        "excluded": [{"id": c.id, "reason": c.exclusion_reason}
                     for c in (*cs.defects, *cs.controls, *cs.injections) if c.excluded],
        "conditions": {}, "injection": {}}
    for cond in CONDITIONS:
        rr = rule_results.get(cond, {})
        d19 = [rr[i] for i in defects if i in rr and defects[i].defect_class != "D10"]
        d10 = [rr[i] for i in defects if i in rr and defects[i].defect_class == "D10"]
        by_class: dict[str, Any] = {}
        for cls in CLASSES:
            sub = [rr[i] for i, c in defects.items() if c.defect_class == cls and i in rr]
            if sub:
                by_class[cls] = _d10_cell(sub) if cls == "D10" else _rule_cell(sub)
        cell19 = _rule_cell(d19) if d19 else None
        cell10 = _d10_cell(d10) if d10 else None
        n = (cell19["n"] if cell19 else 0) + (cell10["n"] if cell10 else 0)
        k = (cell19["escapes"] if cell19 else 0) + (len(cell10["escaped_ids"]) if cell10 else 0)
        errors = (cell19["harness_errors"] if cell19 else []) + (
            cell10["harness_errors"] if cell10 else [])
        out["conditions"][cond] = {
            "by_construction_for_d1_d9": BY_CONSTRUCTION[cond],
            "defective": {"n": n, "escapes": k, **_prop(k, n),
                          "n_cases": len(d19) + len(d10), "harness_errors": errors,
                          "definition": "D1-D9 reached Approved, plus D10 cases with at least "
                                        "one undetected tamper route"},
            "d1_d9": cell19, "d10": cell10, "by_class": by_class,
            "controls": _controls_cell([rr[i] for i in controls if i in rr]) if any(
                i in rr for i in controls) else None}
    for cond in CONDITIONS:
        ir = injection_results.get(cond, {})
        sub = [ir[c.id] for c in cs.active_injections() if c.id in ir]
        if sub:
            out["injection"][cond] = _injection_cell(sub)
    return out
