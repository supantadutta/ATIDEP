"""C5 orchestration: package, dry run, lab deployment, rollback, retirement, IOC expiry sweep
(blueprint §17.5, §20.3-20.5).

Modes: ``export`` writes a package and touches no manager; ``dry_run`` loads the converted rule
into a scratch file, runs the test events through logtest (tier 2a: the rule body only, with a
stand-in parent, because logtest cannot run the Windows decoder) and neutralises the scratch
file; ``lab`` needs a hash-bound approval, snapshots the files it will replace, uploads,
restarts and verifies. Production deployment does not exist.

Indicator lists are shared: ``atidep-domains`` and ``atidep-ips`` and the IOC rule file are
rebuilt from **all active bundles**, never grown by hand, and expired entries are dropped.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import AppConfig
from app.db import models as m
from app.db.audit import append_audit_event
from app.services.claims import load_claims
from app.services.detection import add_rule_version
from app.services.governance import (
    GovernanceError,
    load_report,
    report_sha256,
    transition,
    verify_approval,
)
from app.services.rule_ids import allocate_rule_id
from components.c3_detection.ioc_builder import build_bundle, render_lists, render_rules
from components.c4_validation.converter import convert_sigma
from components.c4_validation.corpus import TestSet
from components.c4_validation.ioc_gates import synthesize_tests
from components.c5_deployment.adapter import NEUTRAL_RULES_XML, AdapterError, WazuhAdapter
from components.c5_deployment.package import (
    Package,
    build_package,
    load_package,
    verify_package,
    write_package,
)
from schemas.common import RuleKind, RuleState
from schemas.ioc_bundle import IocBundle, IocEntry

IOC_RULE_FILE = "0900-atidep_ioc.xml"
SCRATCH_FILE = "0999-atidep_dryrun.xml"
ACTIVE_STATES = (RuleState.APPROVED.value, RuleState.DEPLOYED.value, RuleState.MONITORED.value)
SHIM_IDS = {"process_creation": (199001, "1"), "network_connection": (199003, "3"),
            "dns_query": (199022, "22")}
SCRATCH_ID_OFFSET = 80000


class DeploymentError(Exception):
    pass


@dataclass
class Artifacts:
    kind: str
    rule_files: dict[str, str]
    lists: dict[str, str] = field(default_factory=dict)
    rule_ids: list[int] = field(default_factory=list)
    report: dict[str, Any] = field(default_factory=dict)
    category: str | None = None


def _utc(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def rule_file_name(rule_id: str) -> str:
    return f"0910-atidep_{re.sub(r'[^a-z0-9]+', '_', rule_id.lower()).strip('_')}.xml"


def _version(session: Session, rule: m.Rule) -> m.RuleVersion:
    return session.scalars(select(m.RuleVersion).where(
        m.RuleVersion.rule_id == rule.rule_id,
        m.RuleVersion.version == rule.current_version)).one()


def _allocator(session: Session, cfg: AppConfig):
    rng = tuple(cfg.policies.deployment.custom_rule_id_range)
    return lambda key: allocate_rule_id(session, key, id_range=rng)


def _live(entries: list[IocEntry], now: datetime) -> list[IocEntry]:
    return [e for e in entries if _utc(e.expires_at) > now]


def active_bundles(session: Session, now: datetime, include: str | None = None,
                   exclude: str | None = None) -> dict[str, list[IocEntry]]:
    out: dict[str, list[IocEntry]] = {}
    for rule in session.scalars(select(m.Rule).where(m.Rule.kind == RuleKind.IOC_LIST.value)):
        if rule.rule_id == exclude or not (rule.state in ACTIVE_STATES or rule.rule_id == include):
            continue
        bundle = IocBundle.model_validate(json.loads(_version(session, rule).content)["bundle"])
        entries = _live(bundle.entries, now)
        if entries:
            out[bundle.bundle_id] = entries
    return out


def compose_artifacts(session: Session, rule_id: str, cfg: AppConfig, *, now: datetime,
                      exclude: str | None = None) -> Artifacts:
    rule = session.get(m.Rule, rule_id)
    if rule is None:
        raise DeploymentError(f"unknown rule {rule_id}")
    alloc = _allocator(session, cfg)
    if rule.kind == RuleKind.SIGMA.value:
        conv = convert_sigma(
            _version(session, rule).content, allocate=alloc, wazuh_mapping=cfg.wazuh_mapping,
            max_siblings=cfg.policies.deployment.max_sibling_rules_per_sigma_rule)
        import yaml
        cat = yaml.safe_load(_version(session, rule).content)["logsource"]["category"]
        return Artifacts("sigma", {rule_file_name(rule_id): conv.xml}, {}, conv.rule_ids,
                         conv.report, cat)
    bundles = active_bundles(session, now, include=rule_id, exclude=exclude)
    all_entries = [e for entries in bundles.values() for e in entries]
    rendered = render_rules(bundles, policy=cfg.policies, allocate=alloc)
    return Artifacts("ioc_list", {IOC_RULE_FILE: rendered.xml or NEUTRAL_RULES_XML},
                     render_lists(all_entries, cfg.policies), sorted(rendered.rule_ids.values()),
                     {"bundles": sorted(bundles), "entries": len(all_entries),
                      "rule_ids": rendered.rule_ids})


# ---- package --------------------------------------------------------------------------------
def _telemetry_statement(cfg: AppConfig, names: list[str]) -> str:
    lines = ["# Required telemetry", ""]
    for n in names:
        info = cfg.telemetry_catalog.get("logsources", {}).get(n, {})
        lines.append(f"- **{n}**: {'available' if info.get('available') else 'NOT available'}; "
                     f"events {', '.join(info.get('events', []))}; fields "
                     f"{', '.join(info.get('fields', []))}")
        if not info.get("available") and info.get("enable_hint"):
            lines.append(f"  - to enable: {info['enable_hint']}")
    return "\n".join(lines) + "\n"


def build_rule_package(session: Session, rule_id: str, cfg: AppConfig, *, now: datetime,
                       test_set: TestSet | None = None,
                       previous: dict[str, str | None] | None = None,
                       require_approval: bool = False) -> tuple[Package, Artifacts]:
    rule = session.get(m.Rule, rule_id)
    if rule is None:
        raise DeploymentError(f"unknown rule {rule_id}")
    version = _version(session, rule)
    report = load_report(session, version.id)
    if not report or any(r.status.value != "passed" for r in report):
        raise DeploymentError("only a rule whose current version passed every gate can be "
                              "packaged")
    approval = verify_approval(session, rule_id) if require_approval else None
    if approval is None:
        approval = session.scalars(select(m.Approval).where(
            m.Approval.rule_version_id == version.id, m.Approval.decision == "approved"
        ).order_by(m.Approval.id.desc())).first()
    opp = session.get(m.DetectionOpportunity, rule.opportunity_id)
    item = session.get(m.IntelligenceItem, opp.intel_id)
    source = session.get(m.Source, item.source_id)
    claims = {c.evidence.evidence_id: c for c in load_claims(session, item.intel_id)}
    art = compose_artifacts(session, rule_id, cfg, now=now)

    files: dict[str, bytes | str] = {}
    files["intel/reference.json"] = json.dumps({
        "intel_id": item.intel_id, "title": item.title, "url": item.url, "source": source.name,
        "published_at": item.published_at.isoformat() if item.published_at else None,
        "retrieved_at": item.retrieved_at.isoformat(), "raw_sha256": item.raw_sha256,
        "sanitised_sha256": item.sanitised_sha256, "priority_score": item.priority_score,
        "priority_band": item.priority_band,
        "opportunity": {"decision": opp.decision, "concept": opp.detection_concept,
                        "techniques": opp.attack_techniques,
                        "false_positive_hypotheses": opp.false_positive_hypotheses},
        "evidence": [{"evidence_id": e, "quote": claims[e].evidence.quote,
                      "verified": claims[e].evidence.verified}
                     for e in opp.evidence_ids if e in claims]},
        indent=2, sort_keys=True)
    if rule.kind == RuleKind.SIGMA.value:
        files["rule/sigma.yml"] = version.content
        files["rule/use_case.json"] = json.dumps(version.use_case, indent=2, sort_keys=True)
        files["rule/assumptions.json"] = json.dumps(version.assumptions, indent=2, sort_keys=True)
        files["wazuh/conversion_report.json"] = json.dumps(art.report, indent=2, sort_keys=True)
    else:
        files["rule/ioc_bundle.json"] = version.content
        files["wazuh/build_report.json"] = json.dumps(art.report, indent=2, sort_keys=True)
    for name, xml in art.rule_files.items():
        files[f"wazuh/{name}"] = xml
    for name, content in art.lists.items():
        files[f"wazuh/lists/{name}"] = content
    files["wazuh/rule_ids.json"] = json.dumps(art.rule_ids)
    tests = test_set or (synthesize_tests(IocBundle.model_validate(
        json.loads(version.content)["bundle"]).entries) if rule.kind == RuleKind.IOC_LIST.value
        else None)
    if tests is not None:
        for label, group in (("positive", tests.positive), ("negative", tests.negative),
                             ("benign_lookalike", tests.lookalike)):
            for i, ev in enumerate(group):
                files[f"tests/events/{label}/{i:03d}.json"] = json.dumps(
                    ev.event, indent=1, sort_keys=True)
    files["tests/results.json"] = json.dumps({
        "report_sha256": report_sha256(report),
        "gates": [{"gate": r.gate.value, "status": r.status.value, "tier": r.tier,
                   "reason_codes": r.reason_codes, "message": r.message} for r in report]},
        indent=2, sort_keys=True)
    sources = sorted({opp.required_log_source} - {None}) or []
    files["telemetry.md"] = _telemetry_statement(cfg, sources)
    if approval is not None:
        files["approval.json"] = json.dumps({
            "approval_id": approval.id, "reviewer": approval.reviewer, "author": approval.author,
            "decision": approval.decision, "comment": approval.comment,
            "content_sha256": approval.content_sha256,
            "validation_report_sha256": approval.validation_report_sha256,
            "deployment_target": approval.deployment_target}, indent=2, sort_keys=True)
    prev = previous or {}
    files["rollback/rollback.json"] = json.dumps(
        {name: (c is not None) for name, c in sorted(prev.items())}, indent=2, sort_keys=True)
    for name, content in prev.items():
        if content is not None:
            files[f"rollback/previous/{name}"] = content
    files["README.md"] = _readme(rule_id, version.version, art, bool(prev))
    pkg = build_package(f"{rule_id}-v{version.version}", files, {
        "rule_id": rule_id, "version": version.version, "kind": rule.kind,
        "content_sha256": version.content_sha256, "wazuh_rule_ids": art.rule_ids})
    return Package(f"{pkg.name}-{pkg.sha256[:8]}", pkg.files, pkg.meta), art


def _readme(rule_id: str, version: int, art: Artifacts, has_rollback: bool) -> str:
    files = ", ".join(f"`{n}`" for n in [*art.rule_files, *art.lists])
    return (f"# {rule_id} version {version}\n\n"
            "Generated by ATIDEP. Review `intel/reference.json` (the evidence), `rule/` (the "
            "rule), `tests/results.json` (the gate results) and `approval.json`.\n\n"
            "## Deploy to the lab manager\n\n"
            f"1. Upload {files} through the Wazuh API (lists first, then the rule file).\n"
            "2. Restart the manager: a rule or list change takes effect only after a restart.\n"
            "3. Replay the events in `tests/events/` and check that positives alert and the "
            "others do not.\n\n## Roll back\n\n"
            + ("Upload the files in `rollback/previous/` over the deployed ones (a file listed "
               "in `rollback/rollback.json` as `false` did not exist: replace it with a "
               "placeholder rule that matches nothing), then restart.\n" if has_rollback else
               "This export has no rollback data; a lab deployment adds it.\n"))


# ---- export ---------------------------------------------------------------------------------
def _record(session: Session, rule: m.Rule, mode: str, status: str, pkg: Package | None,
            path: Path | None, rule_ids: list[int], details: dict[str, Any],
            approval_id: int | None = None) -> m.Deployment:
    dep = m.Deployment(
        rule_version_id=_version(session, rule).id, approval_id=approval_id, mode=mode,
        package_sha256=pkg.sha256 if pkg else "0" * 64,
        package_path=str(path) if path else None, status=status, wazuh_rule_ids=rule_ids,
        details=details)
    session.add(dep)
    session.flush()
    return dep


def export_package(session: Session, rule_id: str, cfg: AppConfig, *, out_dir: Path | str,
                   now: datetime, test_set: TestSet | None = None, actor: str = "system"
                   ) -> m.Deployment:
    rule = session.get(m.Rule, rule_id)
    pkg, art = build_rule_package(session, rule_id, cfg, now=now, test_set=test_set)
    path = write_package(pkg, out_dir)
    dep = _record(session, rule, "export", "ok", pkg, path, art.rule_ids, {"files": len(pkg.files)})
    append_audit_event(session, actor=actor, action="deploy.export", entity_type="rule",
                       entity_id=rule_id, details={"package_sha256": pkg.sha256,
                                                   "path": str(path)})
    return dep


# ---- dry run (tier 2a) ----------------------------------------------------------------------
def _shim_xml(art: Artifacts) -> str:
    """The converted rules with their real parent replaced by a stand-in that matches the same
    Sysmon event on pre-decoded JSON, and shifted IDs so nothing collides with a deployed rule."""
    sid, eid = SHIM_IDS[art.category or "process_creation"]
    xml = next(iter(art.rule_files.values()))
    xml = re.sub(r"<if_sid>[^<]*</if_sid>", f"<if_sid>{sid}</if_sid>", xml)
    xml = re.sub(r'<rule id="(\d+)"',
                 lambda mo: f'<rule id="{int(mo.group(1)) + SCRATCH_ID_OFFSET}"', xml)
    shim = (f'  <rule id="{sid}" level="0">\n    <decoded_as>json</decoded_as>\n'
            '    <field name="win.system.providerName">^Microsoft-Windows-Sysmon$</field>\n'
            f'    <field name="win.system.eventID">^{eid}$</field>\n'
            "    <description>ATIDEP dry-run stand-in parent</description>\n  </rule>\n")
    return xml.replace('<group name="atidep,sigma,">\n', '<group name="atidep,sigma,">\n' + shim, 1)


def dry_run(session: Session, rule_id: str, adapter: WazuhAdapter, cfg: AppConfig, *,
            now: datetime, test_set: TestSet | None = None, actor: str = "system"
            ) -> m.Deployment:
    rule = session.get(m.Rule, rule_id)
    if rule is None:
        raise DeploymentError(f"unknown rule {rule_id}")
    art = compose_artifacts(session, rule_id, cfg, now=now)
    details: dict[str, Any] = {"tier": "2a", "scope": "rule body only; no parent chain, no lists"}
    status, problems = "ok", []
    try:
        if art.kind == "sigma":
            adapter.put_rule_file(SCRATCH_FILE, _shim_xml(art))
            ids = {i + SCRATCH_ID_OFFSET for i in art.rule_ids}
            ts = test_set
            if ts is None:
                raise DeploymentError("a test set is needed to dry-run a Sigma rule")
            for label, group, should in (("positive", ts.positive, True),
                                         ("negative", ts.negative, False),
                                         ("lookalike", ts.lookalike, False)):
                for ev in group:
                    res = adapter.logtest(json.dumps(ev.event, separators=(",", ":")))
                    fired = res.fired_rule in ids
                    if fired is not should:
                        problems.append(f"{label} {ev.name}: "
                                        f"{'did not fire' if should else 'fired'}")
            details["events"] = sum(len(g) for g in (ts.positive, ts.negative, ts.lookalike))
        else:
            adapter.put_rule_file(SCRATCH_FILE, art.rule_files[IOC_RULE_FILE])
            details["scope"] = "XML accepted by the manager; lists need a restart to test"
    except AdapterError as exc:
        status, problems = "failed", [str(exc)]
    finally:
        try:
            adapter.put_rule_file(SCRATCH_FILE, NEUTRAL_RULES_XML)
        except AdapterError as exc:                          # leave a trace, never hide it
            problems.append(f"could not neutralise the scratch file: {exc}")
            status = "failed"
    if problems:
        status = "failed"
    details["problems"] = problems
    dep = _record(session, rule, "dry_run", status, None, None, art.rule_ids, details)
    append_audit_event(session, actor=actor, action="deploy.dry_run", entity_type="rule",
                       entity_id=rule_id, details={"status": status, "problems": problems[:5]})
    return dep


# ---- lab deployment -------------------------------------------------------------------------
def _snapshot(adapter: WazuhAdapter, art: Artifacts) -> dict[str, str | None]:
    snap: dict[str, str | None] = {}
    for name in art.rule_files:
        snap[name] = adapter.get_rule_file(name)
    for name in art.lists:
        snap[name] = adapter.get_list(name)
    return snap


def _restore(adapter: WazuhAdapter, previous: dict[str, str | None]) -> None:
    for name, content in previous.items():
        if name.startswith("atidep-"):
            if content is not None:
                adapter.put_list(name, content)
        else:
            adapter.put_rule_file(name, content if content is not None else NEUTRAL_RULES_XML)
    adapter.restart()


def deploy_lab(session: Session, rule_id: str, adapter: WazuhAdapter, cfg: AppConfig, *,
               out_dir: Path | str, now: datetime, test_set: TestSet | None = None,
               verify=None, actor: str = "system") -> m.Deployment:
    """Returns the deployment record; ``status`` is ``failed`` (after an automatic rollback)
    if anything went wrong. ``verify`` is an optional callable run after the restart (the
    tier 2 replay in the lab) that returns a dict stored with the record and must contain
    ``"ok": True``."""
    rule = session.get(m.Rule, rule_id)
    if rule is None:
        raise DeploymentError(f"unknown rule {rule_id}")
    approval = verify_approval(session, rule_id)                   # raises ApprovalError
    art = compose_artifacts(session, rule_id, cfg, now=now)
    previous = _snapshot(adapter, art)
    pkg, _ = build_rule_package(session, rule_id, cfg, now=now, test_set=test_set,
                                previous=previous, require_approval=True)
    path = write_package(pkg, out_dir)
    problems = verify_package(path)
    if problems:
        raise DeploymentError(f"the package on disk is not intact: {problems[:3]}")
    details: dict[str, Any] = {"previous_files": {k: v is not None for k, v in previous.items()}}
    status = "ok"
    try:
        for name, content in art.lists.items():
            adapter.put_list(name, content)
        for name, xml in art.rule_files.items():
            adapter.put_rule_file(name, xml)
        details["restart_seconds"] = round(adapter.restart(), 1)
        if verify is not None:
            details["verification"] = verify()
            if not details["verification"].get("ok"):
                raise DeploymentError("post-deployment verification failed")
    except (AdapterError, DeploymentError) as exc:
        status = "failed"
        details["error"] = str(exc)[:300]
        try:
            _restore(adapter, previous)
            details["rolled_back"] = True
        except AdapterError as exc2:
            details["rolled_back"] = False
            details["rollback_error"] = str(exc2)[:300]
    dep = _record(session, rule, "lab", status, pkg, path, art.rule_ids, details, approval.id)
    if status == "ok" and rule.state == RuleState.APPROVED.value:
        transition(session, rule, RuleState.DEPLOYED, actor=actor, reason=f"deployment {dep.id}")
    append_audit_event(session, actor=actor, action=f"deploy.lab.{status}", entity_type="rule",
                       entity_id=rule_id, details={"deployment_id": dep.id,
                                                   "package_sha256": pkg.sha256,
                                                   "rule_ids": art.rule_ids})
    return dep


def rollback(session: Session, deployment_id: int, adapter: WazuhAdapter, *,
             actor: str = "system") -> m.Deployment:
    dep = session.get(m.Deployment, deployment_id)
    if dep is None or dep.mode != "lab" or dep.status != "ok" or not dep.package_path:
        raise DeploymentError("only a successful lab deployment can be rolled back")
    problems = verify_package(dep.package_path)
    if problems:
        raise DeploymentError(f"the package is not intact, refusing to roll back: {problems[:3]}")
    pkg = load_package(dep.package_path)
    existed = json.loads(pkg.files["rollback/rollback.json"].decode())
    previous = {name: (pkg.files[f"rollback/previous/{name}"].decode() if had else None)
                for name, had in existed.items()}
    _restore(adapter, previous)
    dep.status = "rolled_back"
    dep.details = {**dep.details, "rolled_back_at": datetime.now(UTC).isoformat()}
    version = session.get(m.RuleVersion, dep.rule_version_id)
    rule = session.get(m.Rule, version.rule_id)
    if rule.state in (RuleState.DEPLOYED.value, RuleState.MONITORED.value):
        transition(session, rule, RuleState.APPROVED, actor=actor, reason="rollback")
    append_audit_event(session, actor=actor, action="deploy.rollback", entity_type="rule",
                       entity_id=rule.rule_id, details={"deployment_id": dep.id})
    session.flush()
    return dep


def retire_rule(session: Session, rule_id: str, adapter: WazuhAdapter, cfg: AppConfig, *,
                now: datetime, out_dir: Path | str | None = None, actor: str = "system"
                ) -> m.Deployment:
    rule = session.get(m.Rule, rule_id)
    if rule is None:
        raise DeploymentError(f"unknown rule {rule_id}")
    if rule.state not in (RuleState.DEPLOYED.value, RuleState.MONITORED.value):
        raise GovernanceError(f"{rule_id} is {rule.state}; only a deployed rule can be retired")
    if rule.kind == RuleKind.SIGMA.value:
        art = Artifacts("sigma", {rule_file_name(rule_id): NEUTRAL_RULES_XML})
    else:
        art = compose_artifacts(session, rule_id, cfg, now=now, exclude=rule_id)
    previous = _snapshot(adapter, art)
    for name, content in art.lists.items():
        adapter.put_list(name, content)
    for name, xml in art.rule_files.items():
        adapter.put_rule_file(name, xml)
    seconds = adapter.restart()
    transition(session, rule, RuleState.RETIRED, actor=actor, reason="retired")
    approval = session.scalars(select(m.Approval).where(
        m.Approval.rule_version_id == _version(session, rule).id,
        m.Approval.decision == "approved").order_by(m.Approval.id.desc())).first()
    dep = _record(session, rule, "lab", "ok", None, None, [],
                  {"retired": True, "restart_seconds": round(seconds, 1),
                   "previous_files": {k: v is not None for k, v in previous.items()}},
                  approval.id if approval else None)
    append_audit_event(session, actor=actor, action="deploy.retire", entity_type="rule",
                       entity_id=rule_id, details={"deployment_id": dep.id})
    return dep


# ---- IOC expiry sweep -----------------------------------------------------------------------
@dataclass
class SweepResult:
    rule_id: str
    removed: int
    now_empty: bool
    new_version: int | None


def expiry_sweep(session: Session, cfg: AppConfig, *, now: datetime, benign_domains: list[str],
                 actor: str = "system") -> list[SweepResult]:
    """Rebuild every active IOC bundle that holds expired entries. Each change is a new rule
    version that voids the approval (it must pass the gates and be approved again); a bundle
    with nothing left is reported so it can be retired."""
    out: list[SweepResult] = []
    for rule in session.scalars(select(m.Rule).where(
            m.Rule.kind == RuleKind.IOC_LIST.value, m.Rule.state.in_(ACTIVE_STATES))).all():
        version = _version(session, rule)
        doc = json.loads(version.content)
        bundle = IocBundle.model_validate(doc["bundle"])
        expired = [e for e in bundle.entries if _utc(e.expires_at) <= now]
        if not expired:
            continue
        opp = session.get(m.DetectionOpportunity, rule.opportunity_id)
        built = build_bundle(opp.intel_id, load_claims(session, opp.intel_id), now=now,
                             benign_domains=benign_domains, policy=cfg.policies,
                             catalog=cfg.telemetry_catalog)
        if not built.bundle.entries:
            out.append(SweepResult(rule.rule_id, len(expired), True, None))
            continue
        content = json.dumps({"bundle": json.loads(built.bundle.model_dump_json()),
                              "report": built.report}, sort_keys=True, indent=2)
        new = add_rule_version(session, rule, origin="ioc_builder", content=content)
        if rule.state in (RuleState.APPROVED.value, RuleState.DEPLOYED.value,
                          RuleState.MONITORED.value):
            transition(session, rule, RuleState.REVISED, actor=actor, reason="expiry sweep")
            transition(session, rule, RuleState.DRAFT, actor=actor, reason="new version")
        append_audit_event(session, actor=actor, action="ioc.expiry_sweep",
                           entity_type="rule", entity_id=rule.rule_id,
                           details={"removed": len(expired), "new_version": new.version})
        out.append(SweepResult(rule.rule_id, len(expired), False, new.version))
    return out

