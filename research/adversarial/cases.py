"""Case files for the adversarial evaluation (protocol: ``PROTOCOL.md``).

A case is one scenario: a report excerpt (the evidence corpus), verbatim evidence quotations, the
opportunity, the rule under test, declared assumptions and the events that gates G8-G11 replay.
Cases are YAML files so a reviewer can read them; the loader checks their *integrity* (ids,
shapes, verbatim quotations, buildable events) but never judges them against the system.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal, Self

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

from components.c4_validation import sysmon_factory as sf
from components.c4_validation.corpus import TestEvent, TestSet
from research.adversarial.pdf import build_pdf

CLASSES = tuple(f"D{i}" for i in range(1, 11))
LOGSOURCE_KINDS = {"windows_process_creation": "process_create",
                   "windows_network_connection": "network_connect",
                   "windows_dns_query": "dns_query",
                   "windows_powershell_script_block": "process_create"}


class CaseError(Exception):
    pass


class EventSpec(BaseModel):
    model_config = ConfigDict(extra="ignore")
    kind: Literal["process_create", "network_connect", "dns_query"]
    image: str | None = None
    cmd: str | None = None
    parent: str | None = None
    parent_cmd: str | None = None
    user: str | None = None
    dest_ip: str | None = None
    dest_port: str | None = None
    name: str | None = None


class Events(BaseModel):
    model_config = ConfigDict(extra="forbid")
    positive: list[EventSpec] = Field(default_factory=list)
    negative: list[EventSpec] = Field(default_factory=list)
    lookalike: list[EventSpec] = Field(default_factory=list)


class Assumption(BaseModel):
    model_config = ConfigDict(extra="forbid")
    statement: str
    justification: str
    covers: list[str] = Field(default_factory=list)


class RuleCase(BaseModel):
    """A seeded defective rule (``role: defective``) or a clean control (``role: control``)."""

    model_config = ConfigDict(extra="forbid")
    id: str = Field(pattern=r"^[A-Z0-9]+-\d{2}$")
    role: Literal["defective", "control"]
    defect_class: str
    evasive: bool = False
    why: str
    expected_gate: str
    report_text: str = Field(min_length=40)
    evidence: list[str] = Field(min_length=1)
    logsource: str
    techniques: list[str] = Field(default_factory=list)
    sigma_yaml: str
    assumptions: list[Assumption] = Field(default_factory=list)
    events: Events
    tamper_sigma_yaml: str = ""
    # filled by the independent ground-truth review, before any run
    review: dict[str, Any] = Field(default_factory=dict)
    excluded: bool = False
    exclusion_reason: str = ""

    @model_validator(mode="after")
    def _shape(self) -> Self:
        if self.role == "defective" and self.defect_class not in CLASSES:
            raise ValueError(f"defect_class must be one of {CLASSES}")
        if self.role == "control" and self.defect_class != "NONE":
            raise ValueError("a control has defect_class NONE")
        if self.defect_class == "D10" and not self.tamper_sigma_yaml.strip():
            raise ValueError("a D10 case needs tamper_sigma_yaml")
        return self

    def integrity_issues(self) -> list[str]:
        """Mechanical problems that make a case meaningless; decided without running anything."""
        issues: list[str] = []
        for q in self.evidence:
            if q not in self.report_text:
                issues.append(f"an evidence quotation is not verbatim in the report: {q[:60]!r}")
        if self.logsource not in LOGSOURCE_KINDS:
            issues.append(f"unknown log source {self.logsource!r}")
        else:
            want = LOGSOURCE_KINDS[self.logsource]
            for group, evs in (("positive", self.events.positive),
                               ("negative", self.events.negative),
                               ("lookalike", self.events.lookalike)):
                for e in evs:
                    if e.kind != want:
                        issues.append(f"{group} event kind {e.kind} does not fit {self.logsource}")
        if not (self.events.positive and self.events.negative and self.events.lookalike):
            issues.append("a case needs positive, negative and look-alike events")
        try:
            build_test_set(self)
        except CaseError as exc:
            issues.append(str(exc))
        return issues


class InjectionCase(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(pattern=r"^INJ[A-Z]-\d{2}$")
    family: str
    ext: Literal["html", "txt", "pdf"]
    document: str = Field(min_length=40)
    pdf_metadata: dict[str, str] = Field(default_factory=dict)
    padding_text: str = ""
    padding_repeat: int = 0
    legit_indicators: list[dict[str, str]] = Field(default_factory=list)
    legit_behaviours: list[dict[str, Any]] = Field(default_factory=list)
    honest_extraction: dict[str, Any]
    attack_goal: str
    instruction_marker: str
    planted_indicators: list[dict[str, str]] = Field(default_factory=list)
    compliant_extraction: dict[str, Any]
    honest_opportunity: dict[str, Any] | None = None
    compliant_opportunity: dict[str, Any] | None = None
    honest_rule: dict[str, Any] | None = None
    compliant_rule: dict[str, Any] | None = None
    success_predicates: list[dict[str, Any]] = Field(min_length=1)
    expected_defence: str = ""
    review: dict[str, Any] = Field(default_factory=dict)
    excluded: bool = False
    exclusion_reason: str = ""

    def raw_document(self) -> bytes:
        text = self.document
        if self.ext == "pdf":
            return build_pdf(text, self.pdf_metadata)
        if self.padding_text and self.padding_repeat > 0:
            pad = (self.padding_text + " ") * self.padding_repeat
            if self.ext == "html" and "</body>" in text:
                text = text.replace("</body>", f"<p>{pad}</p></body>", 1)
            else:
                text = text + "\n\n" + pad
        return text.encode("utf-8")


def _event(spec: EventSpec, record: int) -> TestEvent:
    try:
        if spec.kind == "process_create":
            if not (spec.image and spec.cmd is not None):
                raise CaseError("a process_create event needs image and cmd")
            ev = sf.process_create(
                record, spec.image, spec.cmd, spec.parent or "C:\\Windows\\explorer.exe",
                spec.parent_cmd or "", user=spec.user or "LAB\\alice")
        elif spec.kind == "network_connect":
            if not (spec.dest_ip and spec.dest_port):
                raise CaseError("a network_connect event needs dest_ip and dest_port")
            ev = sf.network_connect(record, spec.dest_ip, spec.dest_port, spec.image or sf.BROWSER)
        else:
            if not spec.name:
                raise CaseError("a dns_query event needs name")
            ev = sf.dns_query(record, spec.name, spec.image or sf.PS)
    except TypeError as exc:
        raise CaseError(f"cannot build event: {exc}") from exc
    return TestEvent(f"ev{record}.json", ev)


def build_test_set(case: RuleCase) -> TestSet:
    """Full Sysmon events from the compact specs. Record ids are unique within the case and are
    kept clear of the benign baseline's."""
    rec = iter(range(900_000, 900_900))
    ts = TestSet(case.id)
    for attr in ("positive", "negative", "lookalike"):
        setattr(ts, attr, [_event(s, next(rec)) for s in getattr(case.events, attr)])
    return ts


@dataclass
class CaseSet:
    defects: list[RuleCase] = field(default_factory=list)
    controls: list[RuleCase] = field(default_factory=list)
    injections: list[InjectionCase] = field(default_factory=list)

    def active_defects(self) -> list[RuleCase]:
        return [c for c in self.defects if not c.excluded]

    def active_controls(self) -> list[RuleCase]:
        return [c for c in self.controls if not c.excluded]

    def active_injections(self) -> list[InjectionCase]:
        return [c for c in self.injections if not c.excluded]

    def sha256(self) -> str:
        blob = json.dumps({"defects": [c.model_dump() for c in self.defects],
                           "controls": [c.model_dump() for c in self.controls],
                           "injections": [c.model_dump() for c in self.injections]},
                          sort_keys=True, ensure_ascii=False, default=str)
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()

    def class_counts(self) -> dict[str, int]:
        out = {c: 0 for c in CLASSES}
        for c in self.active_defects():
            out[c.defect_class] += 1
        return out

    def requirements_met(self) -> list[str]:
        """What the protocol requires and the active set still lacks (empty list: all met)."""
        problems = [f"{k}: {n} case(s), at least 4 needed"
                    for k, n in self.class_counts().items() if n < 4]
        if len(self.active_defects()) < 40:
            problems.append(f"{len(self.active_defects())} defective rules, at least 40 needed")
        if len(self.active_injections()) < 12:
            problems.append(f"{len(self.active_injections())} injection reports, at least 12 "
                            "needed")
        return problems


def _represent_str(dumper: yaml.Dumper, data: str) -> Any:
    if "\n" in data:
        return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="|")
    return dumper.represent_scalar("tag:yaml.org,2002:str", data)


class _Dumper(yaml.SafeDumper):
    pass


_Dumper.add_representer(str, _represent_str)


def dump_case(case: BaseModel, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.dump(case.model_dump(mode="json"), Dumper=_Dumper, sort_keys=False,
                              allow_unicode=True, width=100), encoding="utf-8")


def load_case_set(root: Path | str) -> CaseSet:
    r = Path(root)
    cs = CaseSet()
    for sub, model, bucket in (("defects", RuleCase, cs.defects),
                               ("controls", RuleCase, cs.controls),
                               ("injection", InjectionCase, cs.injections)):
        d = r / sub
        if not d.is_dir():
            continue
        for p in sorted(d.glob("*.yaml")):
            try:
                bucket.append(model.model_validate(yaml.safe_load(p.read_text(encoding="utf-8"))))
            except Exception as exc:  # noqa: BLE001 - name the file
                raise CaseError(f"{p}: {exc}") from exc
    ids = [c.id for c in (*cs.defects, *cs.controls, *cs.injections)]
    dup = {i for i in ids if ids.count(i) > 1}
    if dup:
        raise CaseError(f"duplicate case ids: {sorted(dup)}")
    return cs
