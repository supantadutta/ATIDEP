import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.api.main import AppContext, create_app
from app.config import load_config
from app.db.session import init_db, make_engine
from components.c1_ingest.evidence import EvidenceStore
from components.c1_ingest.ssrf import FetchResult
from components.c2_processing.attack import load_release
from components.c2_processing.indicators import load_benign_domains
from components.c4_validation.corpus import load_baseline, load_test_set
from components.llm.prompts import load_prompt_set
from tests.unit.test_pipeline import (
    EXTRACTION,
    REPORT,
    Router,
    draft,
    opportunity_from_request,
)

CFG = load_config()
EVENTS = Path(__file__).resolve().parents[1] / "events"
KEY = "test-key"
NOW = datetime(2026, 10, 2, 9, 0, tzinfo=UTC)
AUTH = {"Authorization": f"Bearer {KEY}", "X-Analyst": "Dr. Rahman"}


class FakeFetcher:
    def __init__(self, domains):
        self.domains = domains

    def fetch(self, url):
        feed = (b'<?xml version="1.0"?><rss version="2.0"><channel><item><title>Feed report'
                b'</title><link>https://example.invalid/r1</link><description>'
                + (b"The actor used 5.6.7.8 for command and control and ran powershell.exe -enc "
                   b"JABzAD0A. " * 20) + b"</description></item></channel></rss>")
        return FetchResult(url, 200, "application/rss+xml", feed)


@pytest.fixture()
def http(tmp_path):
    engine = make_engine(f"sqlite:///{tmp_path}/http.db")    # handlers run in other threads
    init_db(engine)
    router = Router(extraction=EXTRACTION, opportunity=opportunity_from_request,
                    rule=[draft()], improvement=json.dumps({"recommendations": []}))
    ctx = AppContext(
        cfg=CFG, engine=engine, store=EvidenceStore(tmp_path / "evidence"),
        attack=load_release(), prompts=load_prompt_set(), api_key=KEY,
        benign_domains=load_benign_domains(), llm=lambda: router, packages_dir=tmp_path / "pkg",
        baseline=load_baseline(EVENTS / "benign_baseline" / "baseline.jsonl"),
        test_set_for=lambda intel_id: load_test_set(EVENTS), fetcher=FakeFetcher,
        allow_test_tlds=True, now=lambda: NOW)
    client = TestClient(create_app(ctx))
    client.router = router
    return client


def upload(c, body=REPORT, **params):
    q = {"source": "Vendor A", "title": "APT Example", "reliability": "A", "credibility": 2,
         **params}
    return c.post("/intelligence/upload", params=q, content=body.encode(), headers=AUTH)


def processed(c):
    iid = upload(c).json()["intel_id"]
    out = c.post(f"/intelligence/{iid}/process", json={"seed": 1}, headers=AUTH)
    assert out.status_code == 200, out.text
    return iid, out.json()


# ---- authentication ------------------------------------------------------------------------------
def test_health_is_open_and_everything_else_needs_the_key(http):
    assert http.get("/health").json() == {"status": "ok"}
    for method, path in [("get", "/overview"), ("get", "/intelligence"), ("get", "/rules"),
                         ("get", "/audit"), ("get", "/costs/summary"),
                         ("post", "/intelligence/TI-2026-0001/process"),
                         ("post", "/rules/RULE-2026-0001/approve")]:
        assert getattr(http, method)(path).status_code == 401
        wrong = getattr(http, method)(path, headers={"Authorization": "Bearer nope",
                                                    "X-Analyst": "a"})
        assert wrong.status_code == 401


def test_acting_endpoints_need_a_name(http):
    r = http.post("/intelligence/upload", params={"source": "V"}, content=b"x",
                 headers={"Authorization": f"Bearer {KEY}"})
    assert r.status_code == 400 and "X-Analyst" in r.json()["detail"]


# ---- the workflow ----------------------------------------------------------------------------------
def test_upload_process_generate_validate_approve_package(http, tmp_path):
    iid, out = processed(http)
    assert out["processed"] and out["claims"] >= 5 and out["unsupported_claims"] == 0
    assert out["status"] == "assessed" and len(out["opportunity_ids"]) == 2

    item = http.get(f"/intelligence/{iid}", headers=AUTH).json()
    assert item["priority"]["band"] in {"low", "medium", "high", "critical"}
    assert {c["kind"] for c in item["claims"]} == {"indicator", "behavior"}
    assert all(c["evidence"]["verified"] for c in item["claims"])
    assert {o["decision"] for o in item["opportunities"]} == {"behavioral", "ioc_based"}
    text = http.get(f"/intelligence/{iid}/text", headers=AUTH).json()["text"]
    beh = next(c for c in item["claims"] if c["kind"] == "behavior")
    assert text[beh["evidence"]["start"]:beh["evidence"]["end"]] == beh["evidence"]["quote"]

    listing = http.get("/intelligence", params={"status": "assessed"}, headers=AUTH).json()
    assert [i["intel_id"] for i in listing] == [iid]

    sigma_opp = next(o for o in item["opportunities"] if o["decision"] == "behavioral")
    gen = http.post(f"/opportunities/{sigma_opp['opportunity_id']}/generate-rule", json={},
                   headers=AUTH).json()
    assert gen["kind"] == "sigma" and gen["loop_status"] == "passed" and gen["repairs_used"] == 0
    rid = gen["rule_id"]

    val = http.post(f"/rules/{rid}/validate", headers=AUTH).json()
    assert val["outcome"] == "validated" and 0 <= val["quality_score"] <= 100
    assert [g["gate"] for g in val["gates"]] == [f"G{i}" for i in range(1, 12)]

    rule = http.get(f"/rules/{rid}", headers=AUTH).json()
    assert rule["state"] == "validated" and "detection:" in rule["content"]
    assert rule["assumptions"][0]["covers"] == ["ccmexec.exe"] and len(rule["gates"]) == 11

    assert http.post(f"/rules/{rid}/submit", headers=AUTH).json()["state"] == "pending_approval"
    ok = http.post(f"/rules/{rid}/approve", json={"comment": "good"}, headers=AUTH).json()
    assert ok["reviewer"] == "Dr. Rahman" and len(ok["content_sha256"]) == 64

    pkg = http.post(f"/rules/{rid}/package", headers=AUTH).json()
    assert Path(pkg["path"]).is_dir() and len(pkg["package_sha256"]) == 64
    states = {r["rule_id"]: r["state"] for r in http.get("/rules", headers=AUTH).json()}
    assert states[rid] == "approved"

    ov = http.get("/overview", headers=AUTH).json()
    assert ov["items"] == 1 and ov["opportunities"] == 2 and ov["rules_by_state"] == {
        "approved": 1}
    audit = http.get("/audit", headers=AUTH).json()
    assert audit["chain_ok"] and audit["events"][0]["action"].startswith("deploy.export")
    only = http.get("/audit", params={"entity_id": rid}, headers=AUTH).json()["events"]
    assert {e["entity_id"] for e in only} == {rid}


def test_a_person_can_edit_a_rule_which_voids_validation_and_approval(http):
    iid, _ = processed(http)
    opp = http.get("/opportunities", params={"intel_id": iid}, headers=AUTH).json()
    sig = next(o for o in opp if o["decision"] == "behavioral")
    rid = http.post(f"/opportunities/{sig['opportunity_id']}/generate-rule",
                   headers=AUTH).json()["rule_id"]
    http.post(f"/rules/{rid}/validate", headers=AUTH)
    http.post(f"/rules/{rid}/submit", headers=AUTH)
    http.post(f"/rules/{rid}/approve", headers=AUTH)
    content = http.get(f"/rules/{rid}", headers=AUTH).json()["content"]
    r = http.put(f"/rules/{rid}/content", json={"content": content.replace("high", "medium")},
                headers=AUTH)
    assert r.status_code == 200 and r.json()["version"] == 2 and r.json()["state"] == "draft"
    assert http.post(f"/rules/{rid}/submit", headers=AUTH).status_code == 409   # re-validate first
    assert http.put(f"/rules/{rid}/content", json={"content": content}, headers={
        **AUTH, "X-Analyst": "system"}).status_code == 403
    assert http.put(f"/rules/{rid}/content", json={"content": "x"}, headers=AUTH).status_code == 422


def test_an_indicator_opportunity_becomes_a_validated_bundle(http):
    iid, _ = processed(http)
    opps = http.get("/opportunities", params={"intel_id": iid}, headers=AUTH).json()
    ioc = next(o for o in opps if o["decision"] == "ioc_based")
    gen = http.post(f"/opportunities/{ioc['opportunity_id']}/generate-rule", headers=AUTH).json()
    assert gen["kind"] == "ioc_list"
    assert http.post(f"/rules/{gen['rule_id']}/validate", headers=AUTH).json()[
        "outcome"] == "validated"


def test_only_a_person_can_approve_and_the_state_machine_is_enforced(http):
    iid, out = processed(http)
    opp = http.get("/opportunities", params={"intel_id": iid}, headers=AUTH).json()
    rid = http.post(f"/opportunities/{opp[0]['opportunity_id']}/generate-rule",
                   headers=AUTH).json()["rule_id"]
    # approving a draft is refused (409), validating then approving without submitting too
    assert http.post(f"/rules/{rid}/approve", headers=AUTH).status_code == 409
    http.post(f"/rules/{rid}/validate", headers=AUTH)
    assert http.post(f"/rules/{rid}/approve", headers=AUTH).status_code == 409
    http.post(f"/rules/{rid}/submit", headers=AUTH)
    for name in ("system", "agent:rule", "LLM"):
        r = http.post(f"/rules/{rid}/approve", headers={**AUTH, "X-Analyst": name})
        assert r.status_code == 403 and "human" in r.json()["detail"]
    assert http.post(f"/rules/{rid}/reject", json={"comment": "no"}, headers=AUTH).status_code == 200
    assert http.post(f"/rules/{rid}/approve", headers=AUTH).status_code == 409   # already decided


def test_errors_map_to_clear_status_codes(http):
    assert http.get("/intelligence/TI-2026-9999", headers=AUTH).status_code == 404
    assert http.get("/rules/RULE-9999-9999", headers=AUTH).status_code == 404
    assert http.post("/opportunities/999/generate-rule", headers=AUTH).status_code == 404
    assert http.post("/rules/RULE-9999-9999/validate", headers=AUTH).status_code in (404, 409)
    assert http.post("/intelligence/upload", params={"source": "V"}, content=b"   ",
                    headers=AUTH).status_code == 422                 # nothing readable
    assert http.post("/intelligence/upload", params={"source": "V", "reliability": "Z"},
                    content=b"x" * 50, headers=AUTH).status_code == 422


def test_a_duplicate_upload_is_reported_not_stored_twice(http):
    first = upload(http).json()
    again = upload(http).json()
    assert first["status"] == "new" and again["status"] == "duplicate"
    assert again["duplicate_of"] == first["intel_id"]
    assert len(http.get("/intelligence", headers=AUTH).json()) == 1


def test_a_behaviour_opportunity_that_does_not_generate_is_refused(http):
    processed(http)
    http.router.q["opportunity"] = [json.dumps({"opportunities": [
        {"decision": "hunting_only", "decision_reason": "Too generic to alert on"}]})]
    iid2 = upload(http, body=REPORT.replace("5.6.7.8", "9.9.9.9"), title="Second").json()["intel_id"]
    http.post(f"/intelligence/{iid2}/process", headers=AUTH)
    opp = next(o for o in http.get("/opportunities", params={"intel_id": iid2},
                                  headers=AUTH).json())
    r = http.post(f"/opportunities/{opp['opportunity_id']}/generate-rule", headers=AUTH)
    assert r.status_code == 409 and "does not generate" in r.json()["detail"]


def test_collection_run_ingests_configured_sources(http):
    out = http.post("/collection/run", headers=AUTH).json()
    assert out["sources"][0]["source"] == "example-feed" and out["sources"][0]["new"] == 1
    again = http.post("/collection/run", headers=AUTH).json()
    assert again["sources"][0]["duplicates"] == 1 and again["sources"][0]["new"] == 0


def test_tier_2_and_deployment_need_a_configured_lab(http):
    iid, _ = processed(http)
    opp = http.get("/opportunities", params={"intel_id": iid}, headers=AUTH).json()[0]
    rid = http.post(f"/opportunities/{opp['opportunity_id']}/generate-rule",
                   headers=AUTH).json()["rule_id"]
    assert http.post(f"/rules/{rid}/test", json={"tier": 2}, headers=AUTH).status_code == 503
    assert http.post(f"/rules/{rid}/deploy-lab", json={"dry_run": True},
                    headers=AUTH).status_code == 503
    t1 = http.post(f"/rules/{rid}/test", json={"tier": 1}, headers=AUTH).json()
    assert t1["stored"] is False and t1["passed"] is True and t1["tier"] == 1
    assert http.get(f"/rules/{rid}", headers=AUTH).json()["state"] == "draft"   # no state change
    assert http.post(f"/rules/{rid}/test", json={"tier": 3}, headers=AUTH).status_code == 422


def test_the_timer_and_cost_endpoints(http):
    iid, _ = processed(http)
    start = http.post(f"/timers/{iid}/start", json={"condition": "B", "activity": "review_approval"},
                     headers=AUTH)
    assert start.status_code == 200
    assert http.post(f"/timers/{iid}/start", json={}, headers=AUTH).status_code == 409
    assert http.post(f"/timers/{iid}/heartbeat", headers=AUTH).json()["state"] == "running"
    assert http.post(f"/timers/{iid}/pause", headers=AUTH).json()["state"] == "paused"
    assert http.post(f"/timers/{iid}/resume", headers=AUTH).json()["state"] == "running"
    stopped = http.post(f"/timers/{iid}/stop", headers=AUTH).json()
    assert stopped["condition"] == "B" and stopped["active_seconds"] >= 0
    assert http.post(f"/timers/{iid}/stop", headers=AUTH).status_code == 409
    assert http.post(f"/timers/{iid}/start", json={"condition": "C"}, headers=AUTH).status_code == 409
    cost = http.get("/costs/summary", headers=AUTH).json()
    assert cost["items"] == 1 and "extraction" in cost["agents"] and cost["currency"] == "BDT"
    assert cost["tokens"]["input"] > 0


def test_a_missing_model_is_reported_not_crashed(http):
    iid = upload(http).json()["intel_id"]
    http.router.q.pop("extraction")
    out = http.post(f"/intelligence/{iid}/process", headers=AUTH).json()
    assert out["processed"] is False and "model" in out["error"]
    assert http.get(f"/intelligence/{iid}", headers=AUTH).json()["status"] == "sanitised"
