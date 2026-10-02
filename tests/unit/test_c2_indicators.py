import pytest

from components.c2_processing.indicators import (
    extract_cves,
    extract_indicators,
    load_benign_domains,
    refang,
)
from schemas.claim import IndicatorContext as Ctx
from schemas.claim import IndicatorType as T

BENIGN = load_benign_domains()


def by_type(inds, t):
    return [i for i in inds if i.type is t]


def values(inds, t):
    return [i.value for i in by_type(inds, t)]


# ---- refanging ---------------------------------------------------------------------------
@pytest.mark.parametrize("raw,clean", [
    ("hxxp://bad[.]example[.]com/a", "http://bad.example.com/a"),
    ("hXXps://bad(.)example(.)com", "https://bad.example.com"),
    ("h**p://bad.example.com", "http://bad.example.com"),
    ("hxxp[:]//bad.example.com", "http://bad.example.com"),
    ("hxxp[://]bad.example.com", "http://bad.example.com"),
    ("bad[dot]example[dot]com", "bad.example.com"),
    ("user[@]bad.example.com", "user@bad.example.com"),
])
def test_refang_forms(raw, clean):
    assert refang(raw) == clean


# ---- every indicator quotes exactly its own span ------------------------------------------
def test_quotes_are_the_exact_source_span():
    text = ("C2 at hxxps://evil[.]example[.]com/gate.php and 203[.]0[.]113[.]9, hash "
            "d41d8cd98f00b204e9800998ecf8427e. Also bad.example.org.")
    for ind in extract_indicators(text, allow_test_tlds=True):
        assert text[ind.start:ind.end] == ind.quote
    assert extract_indicators(text, allow_test_tlds=True)


# ---- domains -----------------------------------------------------------------------------
def test_defanged_and_plain_domains():
    text = "Beacons to evil[.]example[.]com and then to Backup.Example.NET."
    assert values(extract_indicators(text), T.DOMAIN) == ["evil.example.com", "backup.example.net"]
    d = by_type(extract_indicators(text), T.DOMAIN)[0]
    assert d.defanged and d.quote == "evil[.]example[.]com"


@pytest.mark.parametrize("text", [
    "ran powershell.exe and cmd.exe then loaded payload.dll and run.ps1",
    "version 1.2.3 and build 10.0.19045",
    "mail alice@example.com for details",
    "see readme.md and install.sh and setup.py",
    "path C:\\Windows\\System32\\drivers\\etc and a.b",
    "timestamp 10:30:45 on 2026.10.02",
])
def test_lookalikes_are_not_domains(text):
    assert values(extract_indicators(text), T.DOMAIN) == []


def test_inert_test_tlds_only_when_allowed():
    text = "queried bad.example.invalid"
    assert values(extract_indicators(text), T.DOMAIN) == []
    assert values(extract_indicators(text, allow_test_tlds=True), T.DOMAIN) == ["bad.example.invalid"]


def test_benign_and_publisher_domains_are_reference_only():
    text = "See attack.mitre.org and blog.vendor-example.com; the actor used evil.example.net."
    inds = {i.value: i for i in extract_indicators(text, benign_domains=BENIGN,
                                                   publisher_domains=["vendor-example.com"])}
    assert inds["attack.mitre.org"].benign and inds["attack.mitre.org"].context is Ctx.REFERENCE_ONLY
    assert inds["blog.vendor-example.com"].benign
    assert not inds["evil.example.net"].benign


def test_abusable_hosting_domains_are_not_allowlisted():
    inds = extract_indicators("payload on mybucket.s3.amazonaws.com and x.github.io",
                              benign_domains=BENIGN)
    assert all(not i.benign for i in inds)


# ---- IPs ---------------------------------------------------------------------------------
def test_ipv4_plain_and_defanged_with_reserved_flags():
    text = "Connections to 8.8.4.4, 203[.]0[.]113[.]9, 10.0.0.5 and 169.254.169.254; also 999.1.1.1 and 1.2.3.4.5."
    inds = {i.value: i for i in extract_indicators(text)}
    assert inds["8.8.4.4"].reserved is False
    assert inds["203.0.113.9"].reserved                  # documentation range
    assert inds["10.0.0.5"].reserved and inds["169.254.169.254"].reserved
    assert "999.1.1.1" not in inds and not any(v.startswith("1.2.3.4") for v in inds)
    assert inds["10.0.0.5"].context is Ctx.REFERENCE_ONLY


def test_ipv6():
    inds = extract_indicators("C2 at 2606:4700:4700::1111 and local fe80::1 and ::1; time 12:30:45")
    vals = values(inds, T.IPV6)
    assert "2606:4700:4700::1111" in vals and "fe80::1" in vals
    assert all(i.reserved for i in by_type(inds, T.IPV6) if i.value in ("fe80::1", "::1"))
    assert "12:30:45" not in vals


# ---- hashes ------------------------------------------------------------------------------
def test_hashes_by_length_and_lowercased():
    md5, sha1, sha256 = "A" * 32, "b" * 40, "C" * 64
    inds = extract_indicators(f"md5 {md5} sha1 {sha1} sha256 {sha256} and {'d' * 33} and {'e' * 31}")
    assert values(inds, T.MD5) == [md5.lower()]
    assert values(inds, T.SHA1) == [sha1]
    assert values(inds, T.SHA256) == [sha256.lower()]
    assert len(inds) == 3                                # 31- and 33-char hex runs are not hashes


def test_hash_inside_a_longer_hex_run_is_not_extracted():
    assert extract_indicators("a" * 70) == []


# ---- URLs --------------------------------------------------------------------------------
def test_urls_trim_punctuation_and_keep_defanged_brackets():
    inds = extract_indicators("Download from hxxp://bad[.]example[.]com/a/b.bin, then run it. "
                              "Also (https://other.example.org/x).")
    urls = values(inds, T.URL)
    assert "http://bad.example.com/a/b.bin" in urls and "https://other.example.org/x" in urls


def test_reference_site_urls_are_references_but_user_content_paths_are_kept():
    inds = {i.value: i for i in extract_indicators(
        "see https://www.microsoft.com/ and https://attack.mitre.org/techniques/T1059/001/ "
        "and https://medium.com/ and https://medium.com/@actor/payload and "
        "https://evil.example.org/x", benign_domains=BENIGN)}
    assert inds["https://www.microsoft.com/"].benign
    assert inds["https://attack.mitre.org/techniques/T1059/001/"].benign   # reference page
    assert inds["https://medium.com/"].benign                                # bare domain
    assert not inds["https://medium.com/@actor/payload"].benign              # can be attacker content
    assert not inds["https://evil.example.org/x"].benign


def test_url_with_private_host_still_extracted_but_domain_inside_url_not_duplicated():
    inds = extract_indicators("fetched http://10.1.2.3/stage2 and http://bad.example.com/x")
    assert "http://10.1.2.3/stage2" in values(inds, T.URL)
    assert values(inds, T.DOMAIN) == []                 # the host sits inside the URL span


# ---- context heuristic --------------------------------------------------------------------
def test_context_uses_threat_wording_in_the_same_sentence_only():
    text = ("The malware beacons to evil.example.net every ten minutes. "
            "Researchers also referenced quiet.example.org in an appendix.")
    inds = {i.value: i for i in extract_indicators(text)}
    assert inds["evil.example.net"].context is Ctx.MALICIOUS
    assert inds["quiet.example.org"].context is Ctx.UNKNOWN     # cue is in the previous sentence


def test_a_cue_inside_another_indicators_path_does_not_leak_across_sentences():
    text = ("It contacted hxxps://x[.]example[.]net/beacon over TCP. "
            "See the MITRE page for background on quiet.example.org.")
    inds = {i.value: i for i in extract_indicators(text)}
    assert inds["quiet.example.org"].context is Ctx.UNKNOWN


def test_list_blocks_under_an_ioc_heading_are_malicious_context():
    text = ("Summary of the intrusion.\n\nIndicators of Compromise\n198.51.100.23\n"
            "evil.example.net\n\nAcknowledgements\nthanks.example.org")
    inds = {i.value: i for i in extract_indicators(text)}
    assert inds["evil.example.net"].context is Ctx.MALICIOUS
    assert inds["thanks.example.org"].context is Ctx.UNKNOWN


# ---- order and dedupe ---------------------------------------------------------------------
def test_duplicates_collapse_to_the_first_mention_in_document_order():
    inds = extract_indicators("b.example.org then a.example.org then b.example.org again")
    assert [i.value for i in inds] == ["b.example.org", "a.example.org"]


# ---- CVEs --------------------------------------------------------------------------------
def test_cves():
    got = extract_cves("Exploits CVE-2026-1234 and cve-2025-99999; again CVE-2026-1234. CVE-26-1 no.")
    assert [c.value for c in got] == ["CVE-2026-1234", "CVE-2025-99999"]
    assert got[1].quote == "cve-2025-99999"
