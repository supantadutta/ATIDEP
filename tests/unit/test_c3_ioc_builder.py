import re
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.exc import IntegrityError

from app.config import load_config
from app.db import models as m
from app.db.session import init_db, make_engine, session_scope
from app.services.rule_ids import RuleIdExhausted, allocate_rule_id, allocations
from components.c2_processing.indicators import load_benign_domains
from components.c3_detection.ioc_builder import (
    IocBuildError,
    build_bundle,
    bundle_id_for,
    render_lists,
    render_rules,
)
from components.wazuh_knowledge import parent_for
from schemas.claim import Claim, ClaimKind, Evidence, IndicatorContext, IndicatorType
from schemas.ioc_bundle import ExclusionReason

POLICY = load_config().policies
BENIGN = load_benign_domains()
NOW = datetime(2026, 10, 2, tzinfo=UTC)
SOON = NOW + timedelta(days=10)
SHA = "a" * 64
H_MD5 = "44d88612fea8a8f36de82e1278abb02f"
H_SHA1 = "3395856ce81f2b7382dee72602f798b642f14140"
H_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"

_n = 0


def ind(typ, value, *, context=IndicatorContext.MALICIOUS, expires=SOON, verified=True,
        valid=True):
    global _n
    _n += 1
    return Claim(
        claim_id=f"CL-2026-0001-{_n:03d}", kind=ClaimKind.INDICATOR, type=typ, value=value,
        valid=valid, context=context, expires_at=expires,
        evidence=Evidence(evidence_id=f"EV-2026-0001-{_n:03d}", quote=value[:20] or "x",
                          char_start=0, char_end=5, source_sha256=SHA, verified=verified))


def build(claims, policy=POLICY):
    return build_bundle("TI-2026-0001", claims, now=NOW, benign_domains=BENIGN, policy=policy)


def reasons(b):
    return {x.value: x.reason for x in b.bundle.excluded}


def test_bundle_id_follows_the_item_id():
    assert bundle_id_for("TI-2026-0042") == "IOC-2026-0042"


# ---- what may enter a bundle ---------------------------------------------------------------
def test_only_verified_public_in_date_non_allowlisted_indicators_are_included():
    claims = [
        ind(IndicatorType.DOMAIN, "bad.example.invalid".replace(".invalid", ".net")),
        ind(IndicatorType.IPV4, "1.2.3.4"),
        ind(IndicatorType.SHA256, H_SHA256),
        ind(IndicatorType.DOMAIN, "evil.org", verified=False),
        ind(IndicatorType.IPV4, "10.1.2.3"),
        ind(IndicatorType.IPV4, "198.51.100.23", context=IndicatorContext.REFERENCE_ONLY),
        ind(IndicatorType.DOMAIN, "microsoft.com"),
        ind(IndicatorType.DOMAIN, "old.example.com", expires=NOW - timedelta(days=1)),
        ind(IndicatorType.DOMAIN, "ref.example.org", context=IndicatorContext.REFERENCE_ONLY),
        ind(IndicatorType.SHA1, "xyz"),
        ind(IndicatorType.IPV6, "2001:db8::1"),
        ind(IndicatorType.DOMAIN, "broken..com", valid=False),
    ]
    b = build(claims)
    assert [e.value for e in b.bundle.entries] == ["bad.example.net", "1.2.3.4", H_SHA256]
    r = reasons(b)
    assert r["evil.org"] is ExclusionReason.UNVERIFIED_EVIDENCE
    assert r["10.1.2.3"] is ExclusionReason.RESERVED_RANGE
    assert r["198.51.100.23"] is ExclusionReason.RESERVED_RANGE
    assert r["microsoft.com"] is ExclusionReason.BENIGN_ALLOWLIST
    assert r["old.example.com"] is ExclusionReason.EXPIRED
    assert r["ref.example.org"] is ExclusionReason.BENIGN_ALLOWLIST
    assert r["xyz"] is ExclusionReason.INVALID_FORMAT
    assert r["2001:db8::1"] is ExclusionReason.RESERVED_RANGE
    assert r["broken..com"] is ExclusionReason.INVALID_FORMAT
    assert b.report["included"] == 3 and sum(b.report["excluded"].values()) == 9


def test_a_public_ipv6_address_is_excluded_because_cdb_keys_use_a_colon_separator():
    b = build([ind(IndicatorType.IPV6, "2606:4700:4700::1111")])
    assert b.bundle.entries == []
    assert reasons(b)["2606:4700:4700::1111"] is ExclusionReason.UNSUPPORTED_BY_TARGET


def test_reserved_addresses_stay_out_even_if_the_claim_says_malicious():
    """Defence in depth: the builder re-checks the address itself."""
    b = build([ind(IndicatorType.IPV4, "192.168.0.7", context=IndicatorContext.MALICIOUS),
               ind(IndicatorType.IPV4, "127.0.0.1")])
    assert b.bundle.entries == []
    assert set(reasons(b).values()) == {ExclusionReason.RESERVED_RANGE}


def test_indicators_expiring_exactly_now_are_expired():
    b = build([ind(IndicatorType.DOMAIN, "edge.example.net", expires=NOW)])
    assert reasons(b) == {"edge.example.net": ExclusionReason.EXPIRED}


def test_urls_on_shared_services_are_not_blockable_by_host():
    claims = [ind(IndicatorType.URL, "https://github.com/evil/repo/releases/download/x/a.exe"),
              ind(IndicatorType.URL, "https://cdn.discordapp.com/attachments/1/2/a.bin"),
              ind(IndicatorType.URL, "https://stage.bad-host.net/payload.bin"),
              ind(IndicatorType.URL, "http://1.2.3.4:8080/a"),
              ind(IndicatorType.URL, "http://10.0.0.5/a")]
    b = build(claims)
    assert [e.value for e in b.bundle.entries] == ["https://stage.bad-host.net/payload.bin",
                                                   "http://1.2.3.4:8080/a"]
    r = reasons(b)
    assert r["https://github.com/evil/repo/releases/download/x/a.exe"] is \
        ExclusionReason.BENIGN_ALLOWLIST
    assert r["http://10.0.0.5/a"] is ExclusionReason.RESERVED_RANGE
    assert any("host" in n for n in b.report["notes"])


def test_urls_keep_their_case_but_domains_and_hashes_are_lower_cased():
    b = build([ind(IndicatorType.URL, "https://Stage.Bad-Host.net/Payload.BIN"),
               ind(IndicatorType.DOMAIN, "Mixed.Case.NET"),
               ind(IndicatorType.SHA256, H_SHA256.upper())])
    assert [e.value for e in b.bundle.entries] == [
        "https://Stage.Bad-Host.net/Payload.BIN", "mixed.case.net", H_SHA256]


def test_duplicates_are_dropped_and_counted():
    b = build([ind(IndicatorType.DOMAIN, "dup.example.net"),
               ind(IndicatorType.DOMAIN, "DUP.example.net"),
               ind(IndicatorType.IPV4, "1.2.3.4")])
    assert len(b.bundle.entries) == 2 and b.report["duplicates_dropped"] == 1


def test_a_policy_can_demand_explicit_threat_context():
    import copy

    cfg = load_config()
    raw = copy.deepcopy(cfg.policies.model_dump())
    raw["ioc"]["require_malicious_context"] = True
    strict = type(cfg.policies)(**raw)
    claims = [ind(IndicatorType.DOMAIN, "named.example.net"),
              ind(IndicatorType.DOMAIN, "mention.example.net", context=IndicatorContext.UNKNOWN)]
    b = build(claims, strict)
    assert [e.value for e in b.bundle.entries] == ["named.example.net"]
    assert reasons(b) == {"mention.example.net": ExclusionReason.NO_THREAT_CONTEXT}
    assert len(build(claims).bundle.entries) == 2          # default: unknown context allowed
    assert build(claims).report["included_by_context"] == {"malicious": 1, "unknown": 1}


def test_a_bundle_over_the_size_limit_is_refused_not_truncated():
    import copy

    raw = copy.deepcopy(POLICY.model_dump())
    raw["ioc"]["max_list_entries"] = 2
    small = type(POLICY)(**raw)
    with pytest.raises(IocBuildError, match="exceed"):
        build([ind(IndicatorType.DOMAIN, f"d{i}.example.net") for i in range(3)], small)


def test_non_indicator_claims_are_ignored():
    from schemas.claim import EntityType

    cve = Claim(claim_id="CL-2026-0001-900", kind=ClaimKind.ENTITY, type=EntityType.VULNERABILITY,
                value="CVE-2025-1", evidence=Evidence(
                    evidence_id="EV-1", quote="CVE-2025-1", char_start=0, char_end=10,
                    source_sha256=SHA, verified=True))
    assert build([cve]).bundle.entries == []


# ---- lists ---------------------------------------------------------------------------------
def test_lists_are_sorted_deduplicated_and_urls_contribute_their_host():
    b = build([ind(IndicatorType.DOMAIN, "b.example.net"), ind(IndicatorType.DOMAIN, "a.example.net"),
               ind(IndicatorType.URL, "https://b.example.net/x"),
               ind(IndicatorType.URL, "https://c.example.net/y"),
               ind(IndicatorType.IPV4, "9.9.9.9"), ind(IndicatorType.IPV4, "1.2.3.4"),
               ind(IndicatorType.URL, "http://1.2.3.4:81/z"),
               ind(IndicatorType.IPV4, "100.50.0.1"),
               ind(IndicatorType.SHA256, H_SHA256)])
    lists = render_lists(b.bundle.entries, POLICY)
    assert set(lists) == {"atidep-domains", "atidep-ips"}
    assert lists["atidep-domains"] == "a.example.net:\nb.example.net:\nc.example.net:\n"
    assert lists["atidep-ips"] == "1.2.3.4:\n9.9.9.9:\n100.50.0.1:\n"      # numeric order
    assert "SHA256" not in "".join(lists.values())          # hashes never go into a CDB list


def test_empty_bundles_render_empty_lists_and_no_rules():
    lists = render_lists([], POLICY)
    assert lists == {"atidep-domains": "", "atidep-ips": ""}
    assert render_rules({}, policy=POLICY, allocate=lambda k: 1).xml == ""


# ---- rules ---------------------------------------------------------------------------------
def counter_allocator():
    ids = {}

    def allocate(key):
        return ids.setdefault(key, 110000 + len(ids))
    return allocate, ids


def test_rule_templates_use_the_parents_and_lookups_confirmed_in_s1():
    b = build([ind(IndicatorType.DOMAIN, "a.example.net"), ind(IndicatorType.IPV4, "1.2.3.4")])
    allocate, ids = counter_allocator()
    out = render_rules({b.bundle.bundle_id: b.bundle.entries}, policy=POLICY, allocate=allocate)
    assert set(out.rule_ids) == {"ioc-template:dns-domain", "ioc-template:net-ipv4"}
    xml = out.xml
    assert '<if_sid>61650</if_sid>' in xml                                   # Sysmon event 22
    assert '<list field="win.eventdata.queryName" lookup="match_key">etc/lists/atidep-domains</list>' in xml
    # network rules list the shadowing sibling as an extra parent (ADR-001 F6)
    assert '<if_sid>61605, 92101</if_sid>' in xml
    assert 'lookup="address_match_key">etc/lists/atidep-ips</list>' in xml
    assert xml.count("<rule ") == 2 and xml.startswith("<!--")
    ids = [int(x) for x in re.findall(r'<rule id="(\d+)"', xml)]
    assert ids == sorted(set(ids)) and all(110000 <= i < 120000 for i in ids)


def test_hash_rules_use_one_alternation_per_type_and_split_at_the_cap():
    import copy

    raw = copy.deepcopy(POLICY.model_dump())
    raw["ioc"]["max_hashes_per_rule"] = 2
    small = type(POLICY)(**raw)
    hashes = [f"{i:064x}" for i in range(1, 6)]
    b = build([ind(IndicatorType.SHA256, h) for h in hashes] +
              [ind(IndicatorType.MD5, H_MD5), ind(IndicatorType.SHA1, H_SHA1)], small)
    allocate, ids = counter_allocator()
    out = render_rules({b.bundle.bundle_id: b.bundle.entries}, policy=small, allocate=allocate)
    assert set(out.rule_ids) == {
        "ioc:IOC-2026-0001:sha256:1", "ioc:IOC-2026-0001:sha256:2", "ioc:IOC-2026-0001:sha256:3",
        "ioc:IOC-2026-0001:md5:1", "ioc:IOC-2026-0001:sha1:1"}
    patterns = re.findall(r'type="pcre2">([^<]+)</field>', out.xml)
    assert len(patterns) == 5
    assert f"(?i)SHA256=({hashes[0]}|{hashes[1]})" in patterns
    assert f"(?i)MD5=({H_MD5})" in patterns
    assert out.xml.count("<if_sid>61603</if_sid>") == 5
    assert "atidep-domains" not in out.xml                     # no domains, no domain template


def test_rendered_xml_is_well_formed_and_escapes_text():
    from defusedxml import ElementTree

    b = build([ind(IndicatorType.DOMAIN, "a.example.net"), ind(IndicatorType.SHA256, H_SHA256),
               ind(IndicatorType.IPV4, "1.2.3.4")])
    allocate, _ = counter_allocator()
    out = render_rules({"IOC-2026-0001": b.bundle.entries, "IOC-2026-0002<&>": []},
                       policy=POLICY, allocate=allocate)
    root = ElementTree.fromstring(out.xml)
    assert root.tag == "group" and len(root.findall("rule")) == 3


def test_several_bundles_share_the_templates_but_keep_their_own_hash_rules():
    a = build([ind(IndicatorType.DOMAIN, "a.example.net"), ind(IndicatorType.SHA256, H_SHA256)])
    other = build_bundle("TI-2026-0002", [ind(IndicatorType.DOMAIN, "z.example.net"),
                                          ind(IndicatorType.MD5, H_MD5)], now=NOW,
                         benign_domains=BENIGN, policy=POLICY)
    allocate, _ = counter_allocator()
    out = render_rules({a.bundle.bundle_id: a.bundle.entries,
                        other.bundle.bundle_id: other.bundle.entries},
                       policy=POLICY, allocate=allocate)
    assert list(out.rule_ids) == ["ioc-template:dns-domain", "ioc:IOC-2026-0001:sha256:1",
                                  "ioc:IOC-2026-0002:md5:1"]
    lists = render_lists(a.bundle.entries + other.bundle.entries, POLICY)
    assert lists["atidep-domains"] == "a.example.net:\nz.example.net:\n"


def test_parent_lookup_comes_from_the_s1_knowledge_file():
    assert (parent_for("process_creation").sid, parent_for("dns_query").sid) == (61603, 61650)
    assert parent_for("network_connection").if_sid == "61605, 92101"
    with pytest.raises(KeyError):
        parent_for("registry_set")


# ---- rule-ID allocation --------------------------------------------------------------------
@pytest.fixture()
def engine():
    e = make_engine("sqlite:///:memory:")
    init_db(e)
    return e


def test_allocation_is_stable_sequential_and_skips_reserved_ids(engine):
    rng = tuple(POLICY.deployment.custom_rule_id_range)
    with session_scope(engine) as s:
        a = allocate_rule_id(s, "sigma:aaa#0", id_range=rng)
        b = allocate_rule_id(s, "sigma:aaa#1", id_range=rng)
        again = allocate_rule_id(s, "sigma:aaa#0", id_range=rng)
        c = allocate_rule_id(s, "sigma:bbb#0", id_range=rng, reserved=[110002, 110003])
        assert (a, b, again, c) == (110000, 110001, 110000, 110004)
        assert allocations(s)["sigma:bbb#0"] == 110004


def test_ids_outside_the_block_are_never_handed_out_and_exhaustion_is_an_error(engine):
    with session_scope(engine) as s:
        assert allocate_rule_id(s, "a", id_range=(110000, 110002)) == 110000
        assert allocate_rule_id(s, "b", id_range=(110000, 110002)) == 110001
        with pytest.raises(RuleIdExhausted):
            allocate_rule_id(s, "c", id_range=(110000, 110002))


def test_the_database_refuses_ids_outside_the_wazuh_custom_range(engine):
    with pytest.raises(IntegrityError), session_scope(engine) as s:
        s.add(m.RuleIdAllocation(wazuh_id=100, owner_key="x"))
    with pytest.raises(IntegrityError), session_scope(engine) as s:
        s.add(m.RuleIdAllocation(wazuh_id=110000, owner_key="y"))
        s.add(m.RuleIdAllocation(wazuh_id=110001, owner_key="y"))                 # owner unique
