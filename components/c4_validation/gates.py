"""Hard gates G1-G7: checks that need no events (blueprint §17.4.1).

Every gate is pass/fail; there is no weighted route around a failure. G1-G5 and G7 are
repairable, so their failures come back as structured :class:`Defect` records for the repair
loop. G6 (telemetry) is not repairable: it ends the loop as *blocked*.

The gates read the rule text, the verified quotations, the pinned ATT&CK release and the
telemetry catalog. They never read the original report.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

import yaml

from app.config import PoliciesConfig
from components.c2_processing.attack import AttackRelease
from components.c3_detection.rule_agent import LoopCheck, RuleContext
from components.c4_validation.converter import ConversionResult, convert_ir
from components.c4_validation.sigma_ir import RuleIR, SubsetError, parse_rule
from schemas.detection_opportunity import DetectionOpportunity
from schemas.sigma_subset import Assumption, Level, UnsupportedReason
from schemas.validation_result import Defect, GateId, GateResult, GateStatus

MAX_RULE_BYTES = 50_000
KNOWN_KEYS = frozenset({
    "title", "id", "status", "description", "references", "author", "date", "modified", "tags",
    "logsource", "detection", "falsepositives", "level", "related", "fields", "taxonomy",
    "license"})
EXEMPT_FIELDS = frozenset({"Initiated"})          # booleans carry no report-derived content


@dataclass
class GateInputs:
    opportunity: DetectionOpportunity
    quotes: dict[str, str]                        # verified quotations, evidence_id -> text
    catalog: dict[str, Any]
    wazuh_mapping: dict[str, Any]
    attack: AttackRelease
    policy: PoliciesConfig
    allocate: Callable[[str], int]


@dataclass
class StaticReport:
    results: list[GateResult] = field(default_factory=list)
    defects: list[Defect] = field(default_factory=list)
    blocked: bool = False
    ir: RuleIR | None = None
    conversion: ConversionResult | None = None
    stats: dict[str, Any] = field(default_factory=dict)

    def result(self, gate: GateId) -> GateResult | None:
        return next((r for r in self.results if r.gate is gate), None)

    @property
    def passed(self) -> bool:
        return not self.defects and not self.blocked and all(
            r.status is GateStatus.PASSED for r in self.results)


def _defect(gate: GateId, code: str, path: str, message: str) -> Defect:
    return Defect(gate=gate, code=f"{gate.value}_{code}", path=path, message=message[:400])


def _result(gate: GateId, defects: list[Defect], note: str = "") -> GateResult:
    if defects:
        return GateResult(gate=gate, status=GateStatus.FAILED,
                          reason_codes=sorted({d.code for d in defects}),
                          message="; ".join(f"{d.path}: {d.message}" for d in defects)[:900])
    return GateResult(gate=gate, status=GateStatus.PASSED, message=note)


def _not_run(gate: GateId, why: str) -> GateResult:
    return GateResult(gate=gate, status=GateStatus.NOT_RUN, message=why)


# ---- G1 --------------------------------------------------------------------------------------
def gate_g1(text: str) -> tuple[list[Defect], dict | None]:
    if len(text.encode("utf-8")) > MAX_RULE_BYTES:
        return [_defect(GateId.G1, "TOO_LARGE", "(rule)", "the rule is too large")], None
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        return [_defect(GateId.G1, "YAML", "(rule)", f"not valid YAML: {str(exc)[:200]}")], None
    if not isinstance(doc, dict):
        return [_defect(GateId.G1, "NOT_A_MAPPING", "(rule)",
                        "a Sigma rule is a YAML mapping")], None
    try:
        from sigma.rule import SigmaRule

        rule = SigmaRule.from_yaml(text)
        for cond in rule.detection.parsed_condition:         # conditions are parsed lazily
            _ = cond.parsed
        problems = [str(e) for e in rule.errors]
    except Exception as exc:  # noqa: BLE001 - pySigma raises many exception types
        return [_defect(GateId.G1, "SIGMA", "(rule)",
                        f"pySigma rejects the rule: {type(exc).__name__}: {str(exc)[:200]}")], doc
    if problems:
        return [_defect(GateId.G1, "SIGMA", "(rule)", p) for p in problems[:3]], doc
    return [], doc


# ---- G2 --------------------------------------------------------------------------------------
def _parse_date(value: Any) -> bool:
    if hasattr(value, "year") and not isinstance(value, str):
        return True                                           # YAML turned it into a date
    if not isinstance(value, str):
        return False
    for fmt in ("%Y/%m/%d", "%Y-%m-%d"):
        try:
            datetime.strptime(value, fmt)
            return True
        except ValueError:
            continue
    return False


def gate_g2(doc: dict[str, Any]) -> list[Defect]:
    out: list[Defect] = []

    def need(key: str, ok: bool, msg: str) -> None:
        if key not in doc:
            out.append(_defect(GateId.G2, "MISSING", key, f"required field {key!r} is missing"))
        elif not ok:
            out.append(_defect(GateId.G2, "INVALID", key, msg))

    def text(key: str) -> bool:
        return isinstance(doc.get(key), str) and bool(doc[key].strip())

    def items(key: str) -> bool:
        v = doc.get(key)
        return isinstance(v, list) and bool(v) and all(isinstance(x, str) and x.strip() for x in v)

    try:
        uuid.UUID(str(doc.get("id", "")))
        valid_id = True
    except ValueError:
        valid_id = False
    need("id", valid_id, "id must be a UUID")
    need("title", text("title"), "title must be non-empty text")
    need("status", doc.get("status") == "experimental", "status must be 'experimental'")
    need("description", text("description"), "description must be non-empty text")
    need("author", text("author"), "author must be non-empty text")
    need("date", _parse_date(doc.get("date")), "date must be YYYY/MM/DD")
    need("references", items("references"), "references must be a non-empty list of text")
    need("falsepositives", items("falsepositives"),
         "falsepositives must be a non-empty list of text")
    need("level", doc.get("level") in {lv.value for lv in Level},
         f"level must be one of {[lv.value for lv in Level]}")
    tags = doc.get("tags")
    need("tags", items("tags") and any(str(t).startswith("attack.") for t in tags or []),
         "tags must be a list that includes at least one attack.* tag")
    ls = doc.get("logsource")
    need("logsource", isinstance(ls, dict) and bool(ls.get("category")),
         "logsource must give a category")
    return out


# ---- G3 --------------------------------------------------------------------------------------
def gate_g3(text: str, inp: GateInputs) -> tuple[list[Defect], RuleIR | None,
                                                  ConversionResult | None]:
    """Subset check and conversion. The parsed rule is returned even when conversion fails, so
    G4 and G5 can still report on it. Problems that another gate reports better are not
    repeated here: an invented field (G5) and an invalid level (G1, G2)."""
    try:
        ir = parse_rule(text)
    except SubsetError as exc:
        return [_defect(GateId.G3, exc.code.value, exc.path, exc.message)], None, None
    try:
        conv = convert_ir(ir, allocate=inp.allocate, wazuh_mapping=inp.wazuh_mapping,
                          max_siblings=inp.policy.deployment.max_sibling_rules_per_sigma_rule)
    except SubsetError as exc:
        entry = _catalog_entry(inp.catalog, ir.category)
        allowed = set(entry[1].get("fields", [])) if entry else set()
        invented = exc.code is UnsupportedReason.UNMAPPED_FIELD and \
            exc.path.removeprefix("detection.") not in allowed
        if invented or exc.path == "level":
            return [], ir, None
        return [_defect(GateId.G3, exc.code.value, exc.path, exc.message)], ir, None
    return [], ir, conv


# ---- G4 --------------------------------------------------------------------------------------
def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", s.replace("\\\\", "\\").casefold()).strip()


def _core(value: str) -> str:
    return _norm(re.sub(r"[*?]", "", value)).strip("\\/ ")


def _literal_runs(regex: str) -> list[str]:
    return [r for r in re.findall(r"[A-Za-z0-9_.\-]{3,}", re.sub(r"\\[A-Za-z]", " ", regex))]


def gate_g4(ir: RuleIR, assumptions: list[Assumption], quotes: dict[str, str]
            ) -> tuple[list[Defect], dict[str, int]]:
    quoted_text = " ".join(_norm(q) for q in quotes.values())
    covers = [_core(c) for a in assumptions for c in a.covers if c.strip()]
    stats = {"values": 0, "quoted": 0, "assumed": 0, "unsupported": 0}
    defects: list[Defect] = []
    for m in ir.matchers():
        if m.field in EXEMPT_FIELDS:
            continue
        for v in m.values:
            parts = _literal_runs(v) if m.kind == "re" else [v]
            for part in parts:
                core = _core(part)
                if not core:
                    continue
                stats["values"] += 1
                if core in quoted_text:
                    stats["quoted"] += 1
                elif any(core in c or c in core for c in covers if c):
                    stats["assumed"] += 1
                else:
                    stats["unsupported"] += 1
                    defects.append(_defect(
                        GateId.G4, "UNSUPPORTED_VALUE", f"detection.{m.field}",
                        f"value {part[:60]!r} is not in a verified quotation and no declared "
                        "assumption covers it"))
    return defects, stats


# ---- G5 / G6 ---------------------------------------------------------------------------------
def _catalog_entry(catalog: dict[str, Any], category: str) -> tuple[str, dict[str, Any]] | None:
    for name, info in catalog.get("logsources", {}).items():
        if info.get("sigma_category") == category:
            return name, info
    return None


def gate_g5(ir: RuleIR, inp: GateInputs) -> list[Defect]:
    entry = _catalog_entry(inp.catalog, ir.category)
    if entry is None:
        return [_defect(GateId.G5, "NO_LOGSOURCE", "logsource",
                        f"no catalog log source for category {ir.category}")]
    name, info = entry
    allowed = set(info.get("fields", []))
    out = [_defect(GateId.G5, "UNKNOWN_FIELD", f"detection.{f}",
                   f"field {f!r} is not available for {name}; allowed: {sorted(allowed)}")
           for f in ir.fields_used() if f not in allowed]
    wanted = inp.opportunity.required_log_source
    if wanted and wanted != name:
        out.append(_defect(GateId.G5, "LOGSOURCE_MISMATCH", "logsource",
                           f"the opportunity requires {wanted}, the rule targets {name}"))
    return out


def gate_g6(category: str | None, inp: GateInputs) -> list[Defect]:
    """Not repairable by rewriting: the telemetry is missing."""
    sources = inp.catalog.get("logsources", {})
    needed: list[str] = []
    if inp.opportunity.required_log_source:
        needed.append(inp.opportunity.required_log_source)
    if category:
        entry = _catalog_entry(inp.catalog, category)
        needed.append(entry[0] if entry else f"(category {category})")
    out = []
    for name in dict.fromkeys(needed):
        info = sources.get(name)
        if not info or not info.get("available"):
            hint = (info or {}).get("enable_hint", "enable this telemetry before deploying")
            out.append(_defect(GateId.G6, "TELEMETRY_UNAVAILABLE", "logsource",
                               f"{name} is not available. {hint}"))
    return out


# ---- G7 --------------------------------------------------------------------------------------
_TECH = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.I)


def gate_g7(doc: dict[str, Any], assumptions: list[Assumption], inp: GateInputs
            ) -> list[Defect]:
    tags = [str(t) for t in doc.get("tags", []) if isinstance(t, str)]
    techniques = [m.group(1).upper() for t in tags if (m := _TECH.match(t.strip()))]
    tactic_tags = [t.strip()[7:].replace("_", "-").lower() for t in tags
                   if t.strip().startswith("attack.") and not _TECH.match(t.strip())]
    out: list[Defect] = []
    if not techniques:
        out.append(_defect(GateId.G7, "NO_TECHNIQUE", "tags",
                           "name at least one ATT&CK technique, for example attack.t1059.001"))
    allowed_tactics: set[str] = set()
    covers = {_core(c).upper() for a in assumptions for c in a.covers}
    for tid in techniques:
        tech = inp.attack.get(tid)
        if tech is None or not tech.active:
            out.append(_defect(GateId.G7, "UNKNOWN_TECHNIQUE", "tags",
                               f"{tid} is not an active technique in ATT&CK {inp.attack.version}"))
            continue
        allowed_tactics |= set(tech.tactics)
        if tid not in inp.opportunity.attack_techniques and tid not in covers:
            out.append(_defect(GateId.G7, "UNSUPPORTED_MAPPING", "tags",
                               f"{tid} is not supported by a verified quotation or a declared "
                               "assumption"))
    known_tactics = inp.attack.tactic_shortnames()
    for tac in tactic_tags:
        if tac not in known_tactics:
            valid = ", ".join(sorted(t.replace("-", "_") for t in known_tactics))
            out.append(_defect(GateId.G7, "UNKNOWN_TACTIC", "tags",
                               f"attack.{tac.replace('-', '_')} is not a tactic in ATT&CK "
                               f"{inp.attack.version}; valid tactic tags: {valid}"))
        elif allowed_tactics and tac not in allowed_tactics:
            out.append(_defect(GateId.G7, "INCONSISTENT_TACTIC", "tags",
                               f"tactic {tac} does not belong to the listed technique(s)"))
    return out


# ---- the static run --------------------------------------------------------------------------
def run_static_gates(text: str, assumptions: list[Assumption], inp: GateInputs) -> StaticReport:
    rep = StaticReport()
    g1, doc = gate_g1(text)
    rep.results.append(_result(GateId.G1, g1))
    rep.defects += g1
    if doc is None:
        for g in (GateId.G2, GateId.G3, GateId.G4, GateId.G5, GateId.G7):
            rep.results.append(_not_run(g, "the rule could not be parsed"))
        g6 = gate_g6(None, inp)
        rep.results.append(_result(GateId.G6, g6))
        rep.defects += g6
        rep.blocked = bool(g6)
        rep.results.sort(key=lambda r: int(r.gate.value[1:]))
        return rep

    g2 = gate_g2(doc)
    rep.results.append(_result(GateId.G2, g2))
    rep.defects += g2
    extra = sorted(set(doc) - KNOWN_KEYS)
    if extra:
        rep.stats["unknown_keys"] = extra

    g3, ir, conv = gate_g3(text, inp)
    rep.results.append(_result(GateId.G3, g3))
    rep.defects += g3
    rep.ir, rep.conversion = ir, conv
    if ir is not None:
        g4, st = gate_g4(ir, assumptions, inp.quotes)
        g5 = gate_g5(ir, inp)
        rep.stats["evidence"] = st
        rep.results += [_result(GateId.G4, g4), _result(GateId.G5, g5)]
        rep.defects += g4 + g5
    else:
        rep.results += [_not_run(GateId.G4, "the rule is outside the supported subset"),
                        _not_run(GateId.G5, "the rule is outside the supported subset")]

    g6 = gate_g6(doc.get("logsource", {}).get("category") if isinstance(doc.get("logsource"),
                                                                        dict) else None, inp)
    rep.results.append(_result(GateId.G6, g6))
    rep.defects += g6
    rep.blocked = bool(g6)

    g7 = gate_g7(doc, assumptions, inp)
    rep.results.append(_result(GateId.G7, g7))
    rep.defects += g7
    rep.results.sort(key=lambda r: int(r.gate.value[1:]))
    return rep


def make_loop_validator(*, catalog: dict[str, Any], wazuh_mapping: dict[str, Any],
                        attack: AttackRelease, policy: PoliciesConfig,
                        allocate: Callable[[str], int]
                        ) -> Callable[[str, list[Assumption], RuleContext], LoopCheck]:
    """Adapter so the Rule Agent's repair loop is driven by these gates."""
    def validate(sigma_yaml: str, assumptions: list[Assumption], ctx: RuleContext) -> LoopCheck:
        scoped = GateInputs(ctx.opportunity, ctx.quotes, catalog, wazuh_mapping, attack, policy,
                            allocate)
        rep = run_static_gates(sigma_yaml, assumptions, scoped)
        if rep.blocked:
            reasons = "; ".join(d.message for d in rep.defects if d.gate is GateId.G6)
            return LoopCheck(defects=rep.defects, blocked=True, blocked_reason=reasons)
        return LoopCheck(defects=rep.defects)
    return validate
