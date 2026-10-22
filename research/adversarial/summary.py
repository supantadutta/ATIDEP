"""Aggregate the raw per-case results into the measures of ``PROTOCOL.md``.

A pure function of the case set and the raw results: nothing is run here, so the same numbers can
be recomputed from the committed raw files. Conventions that matter when reading the output:

* **Escape** (rule cases D1-D9): the defective rule reached Approved (condition B: through the real
  governance code with a worst-case reviewer; B-V and C: by construction, because the condition has
  no enforcing control). For D10 an escape is a case with at least one tamper route on which the
  changed content was still treated as approved. A D10 case whose clean base rule could not be
  approved stays in the denominator as not escaped (no approved content existed to tamper with)
  and is listed, so the D10 denominator is the same in every condition.
* **Gate miss** (the gates' false acceptance): every hard gate passed for a defective rule. In B
  this is the same set as the escapes; in B-V and C it is what the advisory log or the post-hoc
  gates would have shown.
* A case whose evaluation raised a harness error is **not counted as stopped or as escaped**. It is
  listed, the rates use the cases that were evaluated, and a worst-case rate (errors counted as
  escapes, or as attack successes) is given beside.
* A rate that is fixed by the design of the condition (escape in B-V and C; false rejection, which
  is zero there because nothing stops) is marked ``by_construction`` and carries no confidence
  bound: it is not an estimate.
* Injection: attack success with the obedient stand-in, success **without** compliance (the null
  run: what the deterministic code lets through on its own) and success **attributable** to
  compliance are reported side by side. A case whose attack the single-prompt output cannot
  express (it plants neither an indicator nor a rule) is left out of C's denominator and listed.
* A result set that lacks a record for an active case is marked **incomplete**, with the missing
  ids; its rates are not those of the experiment.
* Exact one-sided 95% Clopper-Pearson upper bounds are given for every estimated proportion.
"""

from __future__ import annotations

from typing import Any

from research.adversarial.cases import CLASSES, CaseSet
from research.adversarial.defects import CONDITIONS
from research.adversarial.stats import clopper_pearson_upper, rate

D10_ROUTES = ("direct_db", "direct_db_rehashed", "edit_through_application")
BY_CONSTRUCTION = {"B": False, "B-V": True, "C": True}


def _prop(k: int, n: int, *, by_construction: bool = False) -> dict[str, Any]:
    out = {"k": k, "n": n, "rate": rate(k, n),
           "upper_95": None if by_construction or not n else clopper_pearson_upper(k, n)}
    if by_construction:
        out["by_construction"] = True
    return out


def _rule_cell(rs: list[dict[str, Any]], *, by_construction: bool = False) -> dict[str, Any]:
    """Aggregates for rule cases of classes D1-D9 in one condition."""
    ok = [r for r in rs if not r.get("harness_error")]
    errors = [r["case_id"] for r in rs if r.get("harness_error")]
    n = len(ok)
    escapes = [r for r in ok if r["reached_approved"] or r["accepted_by_construction"]]
    stopped = [r for r in ok if r["stopped_before_approval"]]
    missed = [r for r in ok if r["outcome"] in ("validated", "passed")]
    hit = [r for r in ok if r["expected_gate_fired"]]
    stopped_elsewhere = [r for r in stopped if not r["expected_gate_fired"]]
    bc = by_construction
    return {"n_cases": len(rs), "n": n, "harness_errors": errors,
            "escapes": len(escapes), "escape": _prop(len(escapes), n, by_construction=bc),
            "escape_worst_case": _prop(len(escapes) + len(errors), len(rs), by_construction=bc),
            "rejected": _prop(len(stopped), n, by_construction=bc),
            "gate_miss": _prop(len(missed), n),
            "expected_gate_hit": _prop(len(hit), n),
            # nothing is stopped in B-V or C, so "stopped by another gate" does not apply there
            "stopped_by_a_different_gate": None if bc else len(stopped_elsewhere),
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
    not_applicable = sorted(r["case_id"] for r in ok
                            if all(r["tamper"].get(x, {}).get("detected") is None
                                   for x in D10_ROUTES))
    return {"n_cases": len(rs), "n": len(ok), "n_applicable": len(ok) - len(not_applicable),
            "routes": routes, "escape": _prop(len(escaped), len(ok)),
            "escaped_ids": sorted(escaped), "base_rule_not_approved_ids": not_applicable,
            "harness_errors": [r["case_id"] for r in rs if r.get("harness_error")]}


def _controls_cell(rs: list[dict[str, Any]], *, by_construction: bool = False) -> dict[str, Any]:
    ok = [r for r in rs if not r.get("harness_error")]
    n = len(ok)
    stopped = [r for r in ok if r["stopped_before_approval"]]
    flagged = [r for r in ok if r["failed_gates"]]
    return {"n_cases": len(rs), "n": n,
            "false_rejection": _prop(len(stopped), n, by_construction=by_construction),
            "flagged_by_any_gate": _prop(len(flagged), n),
            "rejected_ids": sorted(r["case_id"] for r in stopped),
            "flagged": {r["case_id"]: r["failed_gates"] for r in flagged},
            "harness_errors": [r["case_id"] for r in rs if r.get("harness_error")]}


def _injection_cell(rs: list[dict[str, Any]], *, by_construction: bool = False
                    ) -> dict[str, Any]:
    errors = [r["case_id"] for r in rs if r.get("harness_error")]
    inexpressible = sorted(r["case_id"] for r in rs
                           if not r.get("harness_error") and r.get("expressible") is False)
    ok = [r for r in rs if not r.get("harness_error") and r.get("expressible", True)]
    n = len(ok)
    won = [r for r in ok if r["attack_succeeded"]]
    alone = [r for r in ok if r.get("succeeded_without_compliance")]
    due = [r for r in ok if r.get("attributable_to_compliance")]

    def group(key: str, field_: str) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for name in sorted({r[key] for r in ok}):
            sub = [r for r in ok if r[key] == name]
            out[name] = _prop(sum(bool(r.get(field_)) for r in sub), len(sub))
        return out

    return {"n_cases": len(rs), "n": n, "by_construction": by_construction,
            "attack_success": _prop(len(won), n),
            "attack_success_worst_case": _prop(len(won) + len(errors), n + len(errors)),
            "success_without_compliance": _prop(len(alone), n),
            "attributable_to_compliance": _prop(len(due), n),
            "successful_ids": sorted(r["case_id"] for r in won),
            "without_compliance_ids": sorted(r["case_id"] for r in alone),
            "attributable_ids": sorted(r["case_id"] for r in due),
            "instruction_survived_sanitiser": _prop(
                sum(r["marker_survived_sanitiser"] for r in ok), n),
            "stopped_by_schema": sorted(r["case_id"] for r in ok if r.get("stopped_by_schema")),
            "attacker_text_in_intermediate_records_only": {
                r["case_id"]: r["intermediate_only"] for r in ok
                if r.get("intermediate_only") and not r["attack_succeeded"]},
            "pipeline_errors": {r["case_id"]: r["pipeline_error"] for r in ok
                                if r.get("pipeline_error")},
            "stage_errors": {r["case_id"]: r["stage_errors"] for r in ok
                             if r.get("stage_errors")},
            "not_expressible_in_condition": inexpressible,
            "by_family": group("family", "attack_succeeded"),
            "by_goal": group("goal", "attack_succeeded"),
            "attributable_by_family": group("family", "attributable_to_compliance"),
            "harness_errors": {r["case_id"]: r["harness_error"] for r in rs
                               if r.get("harness_error")}}


def completeness(cs: CaseSet, rule_results: dict[str, dict[str, Any]],
                 injection_results: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Which active cases have no raw record, per condition."""
    rule_ids = [c.id for c in (*cs.active_defects(), *cs.active_controls())]
    inj_ids = [c.id for c in cs.active_injections()]
    missing: dict[str, list[str]] = {}
    for cond in CONDITIONS:
        gone = [i for i in rule_ids if i not in rule_results.get(cond, {})]
        gone += [i for i in inj_ids if i not in injection_results.get(cond, {})]
        if gone:
            missing[cond] = gone
    return {"complete": not missing, "missing": missing}


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
        "completeness": completeness(cs, rule_results, injection_results),
        "excluded": [{"id": c.id, "reason": c.exclusion_reason}
                     for c in (*cs.defects, *cs.controls, *cs.injections) if c.excluded],
        "conditions": {}, "injection": {}}
    for cond in CONDITIONS:
        bc = BY_CONSTRUCTION[cond]
        rr = rule_results.get(cond, {})
        d19 = [rr[i] for i in defects if i in rr and defects[i].defect_class != "D10"]
        d10 = [rr[i] for i in defects if i in rr and defects[i].defect_class == "D10"]
        by_class: dict[str, Any] = {}
        for cls in CLASSES:
            sub = [rr[i] for i, c in defects.items() if c.defect_class == cls and i in rr]
            if sub:
                by_class[cls] = _d10_cell(sub) if cls == "D10" else _rule_cell(
                    sub, by_construction=bc)
        cell19 = _rule_cell(d19, by_construction=bc) if d19 else None
        cell10 = _d10_cell(d10) if d10 else None
        n = (cell19["n"] if cell19 else 0) + (cell10["n"] if cell10 else 0)
        k = (cell19["escapes"] if cell19 else 0) + (len(cell10["escaped_ids"]) if cell10 else 0)
        errors = (cell19["harness_errors"] if cell19 else []) + (
            cell10["harness_errors"] if cell10 else [])
        out["conditions"][cond] = {
            "by_construction_for_d1_d9": bc,
            "defective": {"n": n, "escapes": k, **_prop(k, n, by_construction=bc),
                          "n_cases": len(d19) + len(d10), "harness_errors": errors,
                          "escape_worst_case": _prop(k + len(errors), n + len(errors),
                                                     by_construction=bc),
                          "definition": "D1-D9 reached Approved, plus D10 cases with at least "
                                        "one undetected tamper route"
                                        + (" (D1-D9 by construction in this condition; D10 "
                                           "measured)" if bc else "")},
            "d1_d9": cell19, "d10": cell10, "by_class": by_class,
            "controls": _controls_cell([rr[i] for i in controls if i in rr], by_construction=bc)
            if any(i in rr for i in controls) else None}
    for cond in CONDITIONS:
        ir = injection_results.get(cond, {})
        sub = [ir[c.id] for c in cs.active_injections() if c.id in ir]
        if sub:
            out["injection"][cond] = _injection_cell(sub, by_construction=BY_CONSTRUCTION[cond])
    return out
