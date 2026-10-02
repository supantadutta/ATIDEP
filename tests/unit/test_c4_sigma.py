import random
import re
from itertools import count

import pytest
import yaml
from defusedxml import ElementTree

from app.config import load_config
from components.c4_validation.converter import (
    attack_ids,
    convert_sigma,
    matcher_regex,
    value_regex,
)
from components.c4_validation.sigma_ir import (
    Matcher,
    SubsetError,
    parse_rule,
    to_clauses,
)
from components.c4_validation.tier1 import (
    event_category,
    event_value,
    matcher_matches,
    rule_matches,
)
from schemas.sigma_subset import UnsupportedReason
from tests.events import sysmon_factory as f

MAPPING = load_config().wazuh_mapping
SID = "11111111-1111-4111-8111-111111111111"


def sigma(detection, *, category="process_creation", level="high", tags=None, extra=None):
    doc = {"title": "Test rule", "id": SID, "status": "experimental", "description": "d",
           "references": ["https://example.com"], "author": "ATIDEP", "date": "2026/10/02",
           "tags": tags or ["attack.execution", "attack.t1059.001"],
           "logsource": {"category": category, "product": "windows"}, "detection": detection,
           "falsepositives": ["admin"], "level": level, **(extra or {})}
    return yaml.safe_dump(doc, sort_keys=False)


def allocator():
    n = count(110000)
    ids = {}
    return (lambda key: ids.setdefault(key, next(n))), ids


def convert(detection, **kw):
    alloc, _ = allocator()
    return convert_sigma(sigma(detection, **kw), allocate=alloc, wazuh_mapping=MAPPING)


def refused(detection, code, **kw):
    with pytest.raises(SubsetError) as ei:
        parse_rule(sigma(detection, **kw))
    assert ei.value.code is code, ei.value
    return ei.value


ENC = {"selection": {"Image|endswith": "\\powershell.exe", "CommandLine|contains": ["-enc", "-ec "]},
       "condition": "selection"}


# ---- what the subset accepts ---------------------------------------------------------------
def test_a_typical_rule_parses_into_one_clause_with_two_terms():
    ir = parse_rule(sigma(ENC))
    assert ir.category == "process_creation" and ir.sigma_id == SID and len(ir.clauses) == 1
    assert {m.field for m, neg in ir.clauses[0]} == {"Image", "CommandLine"}
    assert ir.fields_used() == ["Image", "CommandLine"] and len(ir.matchers()) == 2


@pytest.mark.parametrize("cat", ["process_creation", "network_connection", "dns_query"])
def test_supported_log_sources(cat):
    field = {"process_creation": "Image", "network_connection": "DestinationIp",
             "dns_query": "QueryName"}[cat]
    assert parse_rule(sigma({"s": {field: "x.exe"}, "condition": "s"}, category=cat)).category == cat


def test_condition_forms_all_of_one_of_not_and_parentheses():
    det = {"sel_a": {"Image|endswith": "\\a.exe"}, "sel_b": {"Image|endswith": "\\b.exe"},
           "filter": {"ParentImage|endswith": "\\ok.exe"}, "condition": "1 of sel* and not filter"}
    clauses = parse_rule(sigma(det)).clauses
    assert len(clauses) == 2 and all(len(c) == 2 for c in clauses)
    det2 = {**det, "condition": "all of sel*"}
    assert len(parse_rule(sigma(det2)).clauses) == 1
    det3 = {**det, "condition": "(sel_a or sel_b) and not filter"}
    assert len(parse_rule(sigma(det3)).clauses) == 2
    det4 = {**det, "condition": "1 of them and not filter"}
    assert len(parse_rule(sigma(det4)).clauses) == 3 or len(parse_rule(sigma(det4)).clauses) >= 2


def test_all_modifier_means_every_value_must_match():
    ir = parse_rule(sigma({"s": {"CommandLine|contains|all": ["-w", "hidden"]}, "condition": "s"}))
    assert len(ir.clauses) == 1 and len(ir.clauses[0]) == 2


def test_a_list_of_maps_is_an_or_of_conjunctions():
    det = {"s": [{"Image|endswith": "\\a.exe", "CommandLine|contains": "x"},
                 {"Image|endswith": "\\b.exe"}], "condition": "s"}
    assert len(parse_rule(sigma(det)).clauses) == 2


def test_negating_a_conjunction_expands_by_de_morgan():
    det = {"s": {"Image|endswith": "\\a.exe"}, "f": {"ParentImage|endswith": "\\p.exe",
                                                       "User|contains": "svc"},
           "condition": "s and not f"}
    clauses = parse_rule(sigma(det)).clauses
    assert len(clauses) == 2          # a and not parent; a and not user


def test_contradictions_and_redundant_alternatives_are_removed():
    det = {"s": {"Image|endswith": "\\a.exe"}, "t": {"CommandLine|contains": "x"},
           "condition": "s or (s and t)"}
    assert len(parse_rule(sigma(det)).clauses) == 1                     # absorption
    det2 = {"s": {"Image|endswith": "\\a.exe"}, "condition": "s and not s"}
    with pytest.raises(SubsetError, match="never be true"):
        parse_rule(sigma(det2))


def test_values_are_normalised_booleans_and_numbers_become_text():
    ir = parse_rule(sigma({"s": {"Initiated": True, "DestinationPort": 443}, "condition": "s"},
                          category="network_connection"))
    values = sorted(v for m, _ in ir.clauses[0] for v in m.values)
    assert values == ["443", "true"]


# ---- what it refuses, with stable codes -----------------------------------------------------
@pytest.mark.parametrize("mod", ["base64", "base64offset", "cidr", "lt", "lte", "gt", "gte",
                                 "exists", "fieldref", "expand", "utf16le", "cased"])
def test_unsupported_modifiers_are_refused(mod):
    refused({"s": {f"CommandLine|{mod}": "x"}, "condition": "s"}, UnsupportedReason.UNSUPPORTED_MODIFIER)


def test_conflicting_modifiers_are_refused():
    refused({"s": {"CommandLine|contains|startswith": "x"}, "condition": "s"},
            UnsupportedReason.UNSUPPORTED_MODIFIER)
    refused({"s": {"CommandLine|re|windash": "x"}, "condition": "s"},
            UnsupportedReason.UNSUPPORTED_MODIFIER)


@pytest.mark.parametrize("cond", ["selection | count() > 5", "selection | near other",
                                  "selection | count() by Image > 2"])
def test_aggregation_is_refused(cond):
    refused({"selection": {"Image": "x"}, "condition": cond}, UnsupportedReason.UNSUPPORTED_AGGREGATION)
    refused({"selection": {"Image": "x"}, "condition": "selection", "timeframe": "5m"},
            UnsupportedReason.UNSUPPORTED_AGGREGATION)


def test_correlation_rules_are_refused():
    with pytest.raises(SubsetError) as ei:
        parse_rule(sigma(ENC, extra={"correlation": {"type": "event_count"}}))
    assert ei.value.code is UnsupportedReason.UNSUPPORTED_CORRELATION


@pytest.mark.parametrize("category,product", [("registry_set", "windows"),
                                              ("process_creation", "linux"),
                                              ("process_creation", "macos")])
def test_other_log_sources_are_refused(category, product):
    doc = yaml.safe_load(sigma(ENC))
    doc["logsource"] = {"category": category, "product": product}
    with pytest.raises(SubsetError) as ei:
        parse_rule(yaml.safe_dump(doc))
    assert ei.value.code is UnsupportedReason.UNSUPPORTED_LOGSOURCE


@pytest.mark.parametrize("det", [
    {"s": ["keyword one", "keyword two"], "condition": "s"},          # keyword search
    {"s": {"Image": None}, "condition": "s"},                         # null value
    {"s": {"Image": []}, "condition": "s"},
    {"s": {}, "condition": "s"},
    {"s": {"Image": {"nested": "map"}}, "condition": "s"},
])
def test_unsupported_selection_forms(det):
    refused(det, UnsupportedReason.UNSUPPORTED_SELECTION)


@pytest.mark.parametrize("cond", ["", "nosuch", "s and", "(s", "s)", "or s", "1 of nosuch*",
                                  "not", "s s"])
def test_broken_conditions(cond):
    refused({"s": {"Image": "x"}, "condition": cond}, UnsupportedReason.INVALID_CONDITION)


def test_missing_condition_and_non_yaml():
    refused({"s": {"Image": "x"}}, UnsupportedReason.INVALID_CONDITION)
    with pytest.raises(SubsetError) as ei:
        parse_rule("just: [a list")
    assert ei.value.code is UnsupportedReason.INVALID_CONDITION
    with pytest.raises(SubsetError):
        parse_rule("- a\n- b")


def test_a_rule_with_only_negative_terms_is_refused():
    refused({"s": {"Image": "x"}, "condition": "not s"}, UnsupportedReason.UNSUPPORTED_SELECTION)


def test_bad_regex_and_oversized_value_lists_are_refused():
    refused({"s": {"CommandLine|re": "(unclosed"}, "condition": "s"}, UnsupportedReason.INVALID_REGEX)
    refused({"s": {"CommandLine|contains": [f"v{i}" for i in range(201)]}, "condition": "s"},
            UnsupportedReason.EXPANSION_TOO_LARGE)


def test_dnf_explosion_is_stopped():
    det = {f"s{i}": {"Image|endswith": [f"\\a{i}.exe", f"\\b{i}.exe"],
                     "CommandLine|contains": f"x{i}"} for i in range(1)}
    parts = {f"k{i}": [{"Image": f"a{i}"}, {"Image": f"b{i}"}, {"Image": f"c{i}"}]
             for i in range(8)}
    det = {**parts, "condition": " and ".join(parts)}
    refused(det, UnsupportedReason.EXPANSION_TOO_LARGE)


def test_to_clauses_orders_deterministically():
    a = to_clauses(parse_rule(sigma({"x": {"Image": "a"}, "y": {"Image": "b"},
                                     "condition": "x or y"})).expr)
    b = to_clauses(parse_rule(sigma({"x": {"Image": "a"}, "y": {"Image": "b"},
                                     "condition": "y or x"})).expr)
    assert a == b


# ---- converter output ----------------------------------------------------------------------
def test_conversion_produces_a_scoped_rule_with_the_confirmed_field_names():
    res = convert(ENC)
    root = ElementTree.fromstring(res.xml)
    assert root.tag == "group" and root.get("name") == "atidep,sigma,"
    rule = root.find("rule")
    assert rule.get("id") == "110000" and rule.get("level") == "10"
    assert rule.find("if_sid").text == "61603"
    names = sorted(e.get("name") for e in rule.findall("field"))
    assert names == ["win.eventdata.commandLine", "win.eventdata.image"]
    assert all(e.get("type") == "pcre2" for e in rule.findall("field"))
    assert rule.find("mitre/id").text == "T1059.001" and rule.find("description").text == "Test rule"
    assert SID in rule.find("group").text
    assert res.rule_ids == [110000] and res.report["sibling_rules"] == 1


def test_regexes_are_case_insensitive_and_backslash_tolerant():
    res = convert(ENC)
    fields = {e.get("name"): e.text for e in ElementTree.fromstring(res.xml).iter("field")}
    image = fields["win.eventdata.image"]
    assert image == "(?i)\\\\{1,2}powershell\\.exe$"
    assert re.search(image, "C:\\Windows\\System32\\powershell.exe")        # single
    assert re.search(image, "C:\\\\Windows\\\\System32\\\\POWERSHELL.EXE")  # doubled by the pipeline
    cmd = fields["win.eventdata.commandLine"]
    assert cmd == "(?i)(?:-enc|-ec )"
    assert re.search(cmd, "powershell -ENC AAAA") and re.search(cmd, "powershell -ec AAAA")
    assert not re.search(cmd, "powershell -ecx")
    assert res.report["backslashes_made_tolerant"] == 1 and res.report["value_alternations"] == 1


def test_a_pattern_that_would_end_in_a_space_is_protected_from_trimming():
    res = convert({"s": {"CommandLine|contains": "-ec "}, "condition": "s"})
    text = ElementTree.fromstring(res.xml).find("rule/field").text
    assert text == "(?i)-ec\\x20" and re.search(text, "x -ec y") and not re.search(text, "x -ec")


def test_network_rules_list_the_shadowing_sibling_as_a_second_parent():
    res = convert({"s": {"DestinationIp": "203.0.113.55"}, "condition": "s"},
                  category="network_connection")
    assert "<if_sid>61605, 92101</if_sid>" in res.xml
    assert res.report["shadow_risk"][0]["sid"] == 92101
    assert "<if_sid>61650</if_sid>" in convert({"s": {"QueryName": "bad.test"}, "condition": "s"},
                                               category="dns_query").xml


def test_negation_becomes_negate_yes_and_sibling_rules_get_stable_ids():
    det = {"sel": {"Image|endswith": ["\\a.exe", "\\b.exe"]},
           "filter": {"ParentImage|endswith": "\\p.exe", "User|contains": "svc"},
           "condition": "sel and not filter"}
    alloc, ids = allocator()
    res = convert_sigma(sigma(det), allocate=alloc, wazuh_mapping=MAPPING)
    root = ElementTree.fromstring(res.xml)
    rules = root.findall("rule")
    assert len(rules) == 2 and res.rule_ids == [110000, 110001]
    assert list(ids) == [f"sigma:{SID}#0", f"sigma:{SID}#1"]
    for r in rules:
        negs = [e for e in r.findall("field") if e.get("negate") == "yes"]
        assert len(negs) == 1
    assert "(1/2)" in rules[0].find("description").text
    assert res.report["negated_terms"] == 2
    again = convert_sigma(sigma(det), allocate=alloc, wazuh_mapping=MAPPING)
    assert again.xml == res.xml                                   # deterministic


def test_two_tests_on_one_field_are_two_field_elements():
    det = {"s": {"CommandLine|contains|all": ["-w", "hidden"]}, "condition": "s"}
    root = ElementTree.fromstring(convert(det).xml)
    assert len(root.find("rule").findall("field")) == 2


def test_wildcards_windash_and_escapes():
    assert value_regex("ab*c?d")[0] == "ab.*c.d"
    assert value_regex("a\\*b\\?c")[0] == "a\\*b\\?c"
    assert value_regex("a.b(c)")[0] == "a\\.b\\(c\\)"
    body, st = value_regex("-enc -w", windash=True)
    assert body.count("[") == 2 and st["windash"] == 2
    rx = "(?i)" + body
    assert re.search(rx, "x /enc \u2013w") and re.search(rx, "x -enc -w")
    assert not re.search(rx, "x enc w")


def test_regex_values_pass_through_and_xml_special_characters_are_escaped():
    det = {"s": {"CommandLine|re": "a&b<c>|d"}, "condition": "s"}
    res = convert(det)
    assert ElementTree.fromstring(res.xml).find("rule/field").text == "(?i)a&b<c>|d"
    assert "&amp;" in res.xml and "&lt;" in res.xml


def test_oversized_patterns_and_too_many_siblings_are_refused():
    big = {"s": {"CommandLine|contains": ["x" * 3000, "y" * 3000]}, "condition": "s"}
    with pytest.raises(SubsetError) as ei:
        convert(big)
    assert ei.value.code is UnsupportedReason.EXPANSION_TOO_LARGE
    many = {"s": [{"Image": f"a{i}", "CommandLine": f"c{i}"} for i in range(21)], "condition": "s"}
    with pytest.raises(SubsetError) as ei:
        convert(many)
    assert ei.value.code is UnsupportedReason.EXPANSION_TOO_LARGE and "CDB" in ei.value.message
    alloc, _ = allocator()
    ok = {"s": [{"Image": f"a{i}", "CommandLine": f"c{i}"} for i in range(20)], "condition": "s"}
    assert len(convert_sigma(sigma(ok), allocate=alloc, wazuh_mapping=MAPPING).rule_ids) == 20


def test_unmapped_fields_and_unknown_levels_are_refused_by_the_converter():
    with pytest.raises(SubsetError) as ei:
        convert({"s": {"SomethingElse": "x"}, "condition": "s"})
    assert ei.value.code is UnsupportedReason.UNMAPPED_FIELD
    with pytest.raises(SubsetError):
        convert(ENC, level="apocalyptic")


def test_every_field_the_catalog_allows_for_a_convertible_log_source_is_mapped():
    cfg = load_config()
    for name, info in cfg.telemetry_catalog["logsources"].items():
        if "sigma_category" in info:
            missing = [x for x in info["fields"] if x not in MAPPING["field_map"]]
            assert not missing, (name, missing)
    assert all(v.startswith("win.eventdata.") for v in MAPPING["field_map"].values())


def test_severity_mapping_and_mitre_extraction():
    assert 'level="3"' in convert(ENC, level="informational").xml
    assert 'level="12"' in convert(ENC, level="critical").xml
    assert attack_ids(["attack.execution", "attack.t1059.001", "attack.T1105", "attack.t1059.001",
                       "attack.t1"]) == ["T1059.001", "T1105"]
    assert "<mitre>" not in convert(ENC, tags=["attack.execution"]).xml


# ---- Tier 1 matcher --------------------------------------------------------------------------
PS = f.PS
EXP = "C:\\Windows\\explorer.exe"
ENC_CMD = "powershell -nop -w hidden -enc SQBFAFgAIAAoAE4A"


def t1(detection, event, **kw):
    return rule_matches(parse_rule(sigma(detection, **kw)), event, MAPPING)


def test_tier1_matches_the_encoded_powershell_rule_on_the_sample_events():
    assert t1(ENC, f.process_create(1, PS, ENC_CMD, EXP))
    assert t1(ENC, f.process_create(2, PS.upper(), ENC_CMD.upper(), EXP))          # case-insensitive
    assert not t1(ENC, f.process_create(3, PS, "powershell -nop Get-Process", EXP))
    assert not t1(ENC, f.process_create(4, "C:\\Windows\\notepad.exe", ENC_CMD, EXP))


def test_tier1_checks_the_event_type_and_missing_fields():
    assert not t1(ENC, f.network_connect(5, "203.0.113.5"))                         # wrong category
    ev = f.process_create(6, PS, ENC_CMD, EXP)
    del ev["win"]["eventdata"]["commandLine"]
    assert not t1(ENC, ev)
    assert event_category(ev) == "process_creation" and event_value(ev, "Nope", MAPPING["field_map"]) is None


def test_tier1_negation_and_alternatives():
    det = {"sel": {"CommandLine|contains": "-enc"}, "filter": {"ParentImage|endswith": "\\ccmexec.exe"},
           "condition": "sel and not filter"}
    assert t1(det, f.process_create(7, PS, ENC_CMD, EXP))
    assert not t1(det, f.process_create(8, PS, ENC_CMD, "C:\\Windows\\CCM\\ccmexec.exe"))


@pytest.mark.parametrize("kind,value,text,expected", [
    ("exact", "cmd.exe", "CMD.EXE", True), ("exact", "cmd.exe", "xcmd.exe", False),
    ("exact", "c*.exe", "cmd.exe", True), ("exact", "c?d.exe", "cmd.exe", True),
    ("exact", "c?d.exe", "cd.exe", False), ("contains", "-enc", "a -ENC b", True),
    ("contains", "a*z", "a123z", True), ("startswith", "C:\\Win", "c:\\windows\\x", True),
    ("startswith", "Win", "C:\\Windows", False), ("endswith", "\\a.exe", "x\\A.EXE", True),
    ("endswith", "a.exe", "a.exe.txt", False), ("exact", "a\\*b", "a*b", True),
    ("exact", "a\\*b", "axb", False), ("re", "^a+b$", "AAB", True), ("re", "^a+b$", "ab c", False),
    ("contains", "*", "anything", True), ("exact", "", "", True),
])
def test_tier1_glob_semantics(kind, value, text, expected):
    assert matcher_matches(Matcher("CommandLine", kind, (value,)), text) is expected


def test_tier1_windash():
    m = Matcher("CommandLine", "contains", ("-enc",), windash=True)
    assert matcher_matches(m, "x /enc y") and matcher_matches(m, "x \u2013enc y")
    assert not matcher_matches(m, "xenc")
    assert not matcher_matches(Matcher("CommandLine", "contains", ("-enc",)), "x /enc y")


# ---- differential test: converter regex vs the independent Tier 1 matcher ---------------------
ALPHABET = list("ab-/ .\\*?()x") + ["ps", "enc"]


def _rand_text(rng, n=12):
    text = "".join(rng.choice(ALPHABET) for _ in range(rng.randint(0, n)))
    return re.sub(r"\\+", r"\\", text)        # events carry single backslashes


def test_a_question_mark_next_to_a_backslash_is_a_reported_limitation():
    m = Matcher("CommandLine", "startswith", ("?x",))
    regex, _ = matcher_regex(m)
    assert re.search(regex, "\\x") and not re.search(regex, "\\\\x")     # single ok, doubled not
    res = convert({"s": {"CommandLine|startswith": "?\\x"}, "condition": "s"})
    assert res.report["warnings"][0]["code"] == "SINGLE_CHAR_WILDCARD"
    assert convert({"s": {"CommandLine|contains": "a\\?b"}, "condition": "s"}
                   ).report["warnings"] == []                      # an escaped ? is a literal
    assert convert(ENC).report["warnings"] == []


def test_converter_regexes_agree_with_the_tier1_matcher_on_random_inputs():
    """Two independent implementations of the same semantics must agree. The pipeline doubles
    backslashes, so the regex is also tried on the doubled text."""
    rng = random.Random(20261002)
    disagreements = []
    checked = 0
    for _ in range(3000):
        kind = rng.choice(["exact", "contains", "startswith", "endswith"])
        vals = tuple(v for v in (re.sub(r"\\+", r"\\", _rand_text(rng, 5))
                                 for _ in range(rng.randint(1, 3))) if v)
        if not vals:
            continue
        has_q = any("?" in v for v in vals)
        m = Matcher("CommandLine", kind, vals, rng.random() < 0.2)
        regex, _ = matcher_regex(m)
        for _ in range(4):
            text = _rand_text(rng, 14)
            if has_q and "\\" in text:
                continue                   # the documented ? limitation, tested separately
            want = matcher_matches(m, text)
            for shown in (text, text.replace("\\", "\\\\")):
                checked += 1
                if (re.search(regex, shown) is not None) != want:
                    disagreements.append((m, shown, want))
    assert checked > 10000 and not disagreements, disagreements[:3]
