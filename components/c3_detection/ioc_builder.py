"""IOC list builder (blueprint §17.3.4). Deterministic: no model writes an indicator rule.

A bundle is built only from verified, in-date, public, non-allowlisted indicators. Lists and
rules are rendered separately so that several approved bundles can share the two CDB lists
(the lists are regenerated from all active bundles, never grown by hand):

* ``atidep-domains``  exact, case-sensitive keys, looked up on Sysmon DNS queries (event 22)
* ``atidep-ips``      exact addresses, looked up with ``address_match_key`` on connections (3)
* hashes              one PCRE2 alternation per hash type and chunk on process creation (1),
                      because a CDB key cannot match Sysmon's combined ``Hashes`` field

All behaviour was confirmed on Wazuh 4.14.8 (ADR-001, F8). URLs cannot be matched as such by
Sysmon telemetry, so a URL contributes its host (a domain or an address) to the lists.
"""

from __future__ import annotations

import ipaddress
import re
from collections import Counter
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import urlsplit
from xml.sax.saxutils import escape

from app.config import PoliciesConfig
from components.c1_ingest.ssrf import host_allowed, is_public_address
from components.c2_processing.indicators import USER_CONTENT_DOMAINS
from components.wazuh_knowledge import Parent, parent_for
from schemas.claim import Claim, ClaimKind, IndicatorContext, IndicatorType
from schemas.ioc_bundle import ExcludedIoc, ExclusionReason, IocBundle, IocEntry

IOC_RULE_LEVEL = 10
HASH_LENGTH = {IndicatorType.MD5: 32, IndicatorType.SHA1: 40, IndicatorType.SHA256: 64}
HASH_LABEL = {IndicatorType.MD5: "MD5", IndicatorType.SHA1: "SHA1", IndicatorType.SHA256: "SHA256"}
_DOMAIN = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$")
_HEX = re.compile(r"^[0-9a-f]+$")


class IocBuildError(Exception):
    pass


@dataclass
class BundleBuild:
    bundle: IocBundle
    report: dict = field(default_factory=dict)


def bundle_id_for(intel_id: str) -> str:
    return "IOC-" + intel_id.removeprefix("TI-")


def _host_of(url: str) -> str:
    return (urlsplit(url).hostname or "").lower()


def _canonical(t: IndicatorType, value: str | None) -> str:
    """Hashes, domains and addresses are case-insensitive and stored lower case; a URL's path
    can be case-sensitive and is kept as written."""
    v = (value or "").strip()
    return v if t is IndicatorType.URL else v.lower()


def _check(c: Claim, v: str, now: datetime, benign: tuple[str, ...], require_malicious: bool
           ) -> ExclusionReason | None:
    """The reason an indicator claim must stay out of every detection list, if any."""
    t = c.type
    if not c.evidence.verified:
        return ExclusionReason.UNVERIFIED_EVIDENCE
    if not c.valid or not v:
        return ExclusionReason.INVALID_FORMAT
    if t in (IndicatorType.IPV4, IndicatorType.IPV6):
        try:
            ip = ipaddress.ip_address(v)
        except ValueError:
            return ExclusionReason.INVALID_FORMAT
        if not is_public_address(str(ip)):
            return ExclusionReason.RESERVED_RANGE
    if c.context is IndicatorContext.REFERENCE_ONLY:
        return ExclusionReason.BENIGN_ALLOWLIST
    if t is IndicatorType.IPV6:
        return ExclusionReason.UNSUPPORTED_BY_TARGET        # CDB keys use ':' as separator
    if t in HASH_LENGTH and not (len(v) == HASH_LENGTH[t] and _HEX.match(v)):
        return ExclusionReason.INVALID_FORMAT
    if t is IndicatorType.DOMAIN:
        if not _DOMAIN.match(v):
            return ExclusionReason.INVALID_FORMAT
        if host_allowed(v, benign) or host_allowed(v, USER_CONTENT_DOMAINS):
            return ExclusionReason.BENIGN_ALLOWLIST
    if t is IndicatorType.URL:
        host = _host_of(v)
        if not host or not urlsplit(v).scheme.startswith("http"):
            return ExclusionReason.INVALID_FORMAT
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            if not _DOMAIN.match(host):
                return ExclusionReason.INVALID_FORMAT
            if host_allowed(host, benign) or host_allowed(host, USER_CONTENT_DOMAINS):
                return ExclusionReason.BENIGN_ALLOWLIST    # shared service: not blockable by host
        else:
            if ip.version == 6:
                return ExclusionReason.UNSUPPORTED_BY_TARGET
            if not is_public_address(host):
                return ExclusionReason.RESERVED_RANGE
    if c.expires_at is None:
        return ExclusionReason.INVALID_FORMAT
    if c.expires_at <= now:
        return ExclusionReason.EXPIRED
    if require_malicious and c.context is not IndicatorContext.MALICIOUS:
        return ExclusionReason.NO_THREAT_CONTEXT
    return None


def build_bundle(intel_id: str, claims: Iterable[Claim], *, now: datetime,
                 benign_domains: Iterable[str], policy: PoliciesConfig) -> BundleBuild:
    benign = tuple(benign_domains)
    entries: list[IocEntry] = []
    excluded: list[ExcludedIoc] = []
    seen: set[tuple[IndicatorType, str]] = set()
    reasons: Counter[str] = Counter()
    context: Counter[str] = Counter()
    duplicates = 0
    for c in claims:
        if c.kind is not ClaimKind.INDICATOR or not isinstance(c.type, IndicatorType):
            continue
        value = _canonical(c.type, c.value)
        key = (c.type, value.lower())
        if key in seen:
            duplicates += 1
            continue
        seen.add(key)
        reason = _check(c, value, now, benign, policy.ioc.require_malicious_context)
        if reason is not None:
            excluded.append(ExcludedIoc(value=value or "(empty)", reason=reason))
            reasons[reason.value] += 1
            continue
        assert c.expires_at is not None
        entries.append(IocEntry(type=c.type, value=value, evidence_id=c.evidence.evidence_id,
                                expires_at=c.expires_at))
        context[c.context.value] += 1
    if len(entries) > policy.ioc.max_list_entries:
        raise IocBuildError(f"{len(entries)} indicators exceed the limit of "
                            f"{policy.ioc.max_list_entries} for one bundle")
    # an excluded value equal to an included one (same value, different type) stays excluded
    included_values = {e.value.lower() for e in entries}
    excluded = [x for x in excluded if x.value.lower() not in included_values]
    bundle = IocBundle(bundle_id=bundle_id_for(intel_id), intel_id=intel_id, entries=entries,
                       excluded=excluded)
    notes = []
    if any(e.type is IndicatorType.URL for e in entries):
        notes.append("URLs are matched by their host (a domain or an address): Sysmon records "
                     "no URLs")
    notes.append("domain keys are lower case and matched exactly; sub-domains are not covered")
    return BundleBuild(bundle, {
        "included": len(entries), "excluded": dict(reasons), "duplicates_dropped": duplicates,
        "included_by_context": dict(context),
        "included_by_type": dict(Counter(e.type.value for e in entries)), "notes": notes})


# ---- rendering -----------------------------------------------------------------------------
def _split_targets(entries: Iterable[IocEntry]
                   ) -> tuple[set[str], set[str], dict[IndicatorType, set[str]]]:
    """(domains, ipv4 addresses, hashes by type) the entries contribute."""
    domains: set[str] = set()
    ips: set[str] = set()
    hashes: dict[IndicatorType, set[str]] = {t: set() for t in HASH_LENGTH}
    for e in entries:
        if e.type is IndicatorType.DOMAIN:
            domains.add(e.value.lower())
        elif e.type is IndicatorType.IPV4:
            ips.add(e.value)
        elif e.type is IndicatorType.URL:
            host = _host_of(e.value)
            try:
                ipaddress.IPv4Address(host)
                ips.add(host)
            except ValueError:
                domains.add(host)
        elif e.type in HASH_LENGTH:
            hashes[e.type].add(e.value.lower())
    return domains, ips, hashes


def render_lists(entries: Iterable[IocEntry], policy: PoliciesConfig) -> dict[str, str]:
    """CDB list files (file name -> content) for the given entries, sorted and deduplicated."""
    domains, ips, _ = _split_targets(entries)
    names = policy.ioc.list_names
    ip_sorted = sorted(ips, key=lambda a: tuple(int(p) for p in a.split(".")))
    return {names["domain"]: "".join(f"{d}:\n" for d in sorted(domains)),
            names["ipv4"]: "".join(f"{a}:\n" for a in ip_sorted)}


@dataclass
class RenderedRules:
    xml: str
    rule_ids: dict[str, int]


def _rule(rid: int, parent: Parent, body: str, description: str) -> str:
    return (f'  <rule id="{rid}" level="{IOC_RULE_LEVEL}">\n'
            f"    <if_sid>{parent.if_sid}</if_sid>\n{body}"
            f"    <description>{escape(description)}</description>\n"
            f"    <group>atidep,ioc,</group>\n  </rule>\n")


def render_rules(bundles: Mapping[str, Iterable[IocEntry]], *, policy: PoliciesConfig,
                 allocate: Callable[[str], int]) -> RenderedRules:
    """Rule XML for the active bundles. The domain and address rules are templates shared by
    all bundles (the lists carry the data); hash rules carry their hashes and are split into
    chunks of ``max_hashes_per_rule``."""
    names = policy.ioc.list_names
    all_entries = [e for entries in bundles.values() for e in entries]
    domains, ips, _ = _split_targets(all_entries)
    ids: dict[str, int] = {}
    parts: list[str] = []
    if domains:
        ids["ioc-template:dns-domain"] = allocate("ioc-template:dns-domain")
        parts.append(_rule(
            ids["ioc-template:dns-domain"], parent_for("dns_query"),
            f'    <list field="win.eventdata.queryName" lookup="match_key">'
            f"etc/lists/{names['domain']}</list>\n",
            "ATIDEP IOC: DNS query for a listed domain"))
    if ips:
        ids["ioc-template:net-ipv4"] = allocate("ioc-template:net-ipv4")
        parts.append(_rule(
            ids["ioc-template:net-ipv4"], parent_for("network_connection"),
            f'    <list field="win.eventdata.destinationIp" lookup="address_match_key">'
            f"etc/lists/{names['ipv4']}</list>\n",
            "ATIDEP IOC: connection to a listed address"))
    cap = policy.ioc.max_hashes_per_rule
    for bundle_id in sorted(bundles):
        _, _, hashes = _split_targets(bundles[bundle_id])
        for htype, values in hashes.items():
            ordered = sorted(values)
            for n, start in enumerate(range(0, len(ordered), cap), start=1):
                chunk = ordered[start:start + cap]
                key = f"ioc:{bundle_id}:{HASH_LABEL[htype].lower()}:{n}"
                ids[key] = allocate(key)
                pattern = f"(?i){HASH_LABEL[htype]}=(" + "|".join(chunk) + ")"
                parts.append(_rule(
                    ids[key], parent_for("process_creation"),
                    f'    <field name="win.eventdata.hashes" type="pcre2">{pattern}</field>\n',
                    f"ATIDEP IOC {bundle_id}: process with a listed {HASH_LABEL[htype]}"))
    xml = ('<!-- Generated by ATIDEP from approved IOC bundles. Do not edit by hand. -->\n'
           '<group name="atidep,ioc,">\n' + "".join(parts) + "</group>\n") if parts else ""
    return RenderedRules(xml, ids)
