from datetime import UTC, datetime

import pytest

from components.c2_processing.evidence import ClaimFactory, check_quote
from components.c2_processing.indicators import extract_cves, extract_indicators
from schemas.claim import ClaimKind, EntityType, IndicatorContext

TEXT = ("The actor ran powershell.exe with an encoded command\nto download the second stage "
        "from hxxp://bad[.]example[.]com/a. It exploited CVE-2026-1234 first.")
SHA = "a" * 64
NOW = datetime(2026, 10, 2, tzinfo=UTC)
EXPIRY = {"ip": 30, "domain": 90, "url": 90, "hash": 365}


def test_quote_is_found_with_exact_offsets_despite_line_breaks():
    c = check_quote("encoded command to download the second stage", TEXT)
    assert c.ok and TEXT[c.start:c.end].replace("\n", " ") == "encoded command to download the second stage"


@pytest.mark.parametrize("quote,reason", [
    ("", "empty"), ("   ", "empty"), ("short", "too_short"), ("x" * 601, "too_long"),
    ("the actor used mimikatz to dump credentials", "not_found"),
    ("THE ACTOR RAN POWERSHELL.EXE", "not_found"),           # case matters
])
def test_unsupported_quotes_are_rejected_with_a_reason(quote, reason):
    c = check_quote(quote, TEXT)
    assert not c.ok and c.reason == reason


def test_unicode_variants_of_a_real_quote_still_verify():
    assert check_quote("ｐｏｗｅｒｓｈｅｌｌ.exe with an encoded", TEXT).ok     # fullwidth letters


def test_indicator_and_cve_claims_are_verified_by_construction():
    f = ClaimFactory("TI-2026-0001", SHA)
    claims = [f.indicator_claim(i, NOW, EXPIRY) for i in extract_indicators(TEXT)]
    claims += [f.cve_claim(c) for c in extract_cves(TEXT)]
    assert all(c.evidence.verified for c in claims)
    url = next(c for c in claims if c.value.startswith("http://"))
    assert url.refanged_from == "hxxp://bad[.]example[.]com/a" and url.kind is ClaimKind.INDICATOR
    assert url.expires_at == datetime(2026, 12, 31, tzinfo=UTC)      # 2 Oct + 90 days
    cve = next(c for c in claims if c.kind is ClaimKind.ENTITY)
    assert cve.type is EntityType.VULNERABILITY and cve.value == "CVE-2026-1234"
    for c in claims:                                                    # offsets index the text
        assert check_quote(c.evidence.quote, TEXT).ok


def test_ids_are_unique_stable_and_derived_from_the_intel_id():
    f = ClaimFactory("TI-2026-0042", SHA)
    ids = [f.cve_claim(c).claim_id for c in extract_cves("CVE-2026-1111 and CVE-2026-2222")]
    assert ids == ["CL-2026-0042-001", "CL-2026-0042-002"]


def test_reference_only_indicators_get_no_expiry():
    f = ClaimFactory("TI-2026-0001", SHA)
    ind = extract_indicators("see 10.0.0.5 internal")[0]
    claim = f.indicator_claim(ind, NOW, EXPIRY)
    assert claim.context is IndicatorContext.REFERENCE_ONLY and claim.expires_at is None


def test_unverified_model_claims_are_kept_but_never_usable():
    f = ClaimFactory("TI-2026-0001", SHA)
    bad = f.checked_claim(check_quote("the actor used mimikatz", TEXT), "the actor used mimikatz",
                          kind=ClaimKind.BEHAVIOR, description="Credential dumping",
                          attack_id="T1003")
    assert not bad.evidence.verified and not bad.usable
    good = f.checked_claim(check_quote("ran powershell.exe with an encoded command", TEXT),
                           "ran powershell.exe with an encoded command", kind=ClaimKind.BEHAVIOR,
                           description="Encoded PowerShell", attack_id="T1059.001")
    assert good.evidence.verified and good.usable
