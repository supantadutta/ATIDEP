import pytest
from streamlit.testing.v1 import AppTest

from tests.unit.test_api import KEY
from ui.client import ApiClient, ApiError
from ui.pages import highlight


# ---- highlighting ----------------------------------------------------------------------------------
def test_highlight_marks_verified_spans_and_escapes_everything_else():
    text = "Run <script>alert(1)</script> then powershell.exe -enc AAAA & stop"
    start = text.index("powershell.exe")
    out = highlight(text, [(start, start + len("powershell.exe -enc AAAA"))])
    assert "<mark>powershell.exe -enc AAAA</mark>" in out
    assert "<script>" not in out and "&lt;script&gt;" in out and "&amp; stop" in out


def test_highlight_skips_overlaps_and_out_of_range_spans():
    out = highlight("abcdefgh", [(0, 4), (2, 6), (6, 99), (5, 7)])
    assert out.count("<mark>") == 2 and "<mark>abcd</mark>" in out and "<mark>fg</mark>" in out
    assert highlight("plain", []).count("<mark>") == 0


# ---- the client against the real API -------------------------------------------------------------------
@pytest.fixture()
def client(http):
    c = ApiClient("http://testserver", KEY, "Dr. Rahman")
    c._http = http                                  # talk to the app in-process
    return c


def test_the_client_sends_the_key_and_the_name_and_maps_errors(client):
    assert client.get("/overview")["items"] == 0
    with pytest.raises(ApiError) as ei:
        client.get("/rules/RULE-9999-9999")
    assert ei.value.status == 404
    with pytest.raises(ApiError) as ei:
        client.post("/rules/RULE-9999-9999/approve", json={})
    assert ei.value.status in (404, 409)
    bad = ApiClient("http://testserver", "wrong", "x")
    bad._http = client._http
    with pytest.raises(ApiError) as ei:
        bad.get("/overview")
    assert ei.value.status == 401


def test_upload_through_the_client(client):
    out = client.upload(b"The actor beaconed to 1.2.3.4 and 5.6.7.8 using powershell.exe " * 3,
                        source="Vendor", title="t")
    assert out["status"] == "new" and out["intel_id"].startswith("TI-")


# ---- the pages, run headlessly with a fake client ---------------------------------------------------
class Fake:
    """Canned answers; remembers what the page sent."""

    def __init__(self, state="pending_approval"):
        self.state, self.sent = state, []

    def get(self, path, **params):
        table = {
            "/overview": {"items": 2, "duplicates_seen": 1, "high_priority": 1,
                          "opportunities": 3, "alerts": 4, "items_by_status": {},
                          "rules_by_state": {"validated": 1}},
            "/costs/summary": {"currency": "BDT", "tokens": {"input": 1200, "output": 300},
                               "analyst_active_minutes": 12.5,
                               "cost": {"total": 166.67, "labour": 166.67, "tokens": 0.0},
                               "items": 2, "accepted_rules": 1, "agents": {
                                   "extraction": {"calls": 2, "input_tokens": 1200}},
                               "note": "local inference is recorded with zero token cost"},
            "/intelligence": [{"intel_id": "TI-2026-0001", "title": "APT Example",
                               "status": "assessed", "priority_band": "high",
                               "priority_score": 71.2}],
            "/rules": [{"rule_id": "RULE-2026-0001", "kind": "sigma", "state": self.state,
                        "version": 1, "quality_score": 82, "intel_id": "TI-2026-0001",
                        "content_sha256": "ab" * 32}],
            "/rules/RULE-2026-0001": {
                "rule_id": "RULE-2026-0001", "kind": "sigma", "state": self.state, "version": 1,
                "quality_score": 82, "intel_id": "TI-2026-0001", "content_sha256": "ab" * 32,
                "content": "title: Encoded PowerShell\n", "assumptions": [
                    {"statement": "Exclude SCCM", "justification": "admin", "covers": ["x"]}],
                "use_case": {"objective": "o"}, "gates": [
                    {"gate": "G1", "status": "passed", "tier": None, "reason_codes": [],
                     "message": ""},
                    {"gate": "G10", "status": "failed", "tier": 1, "reason_codes": ["X"],
                     "message": "matched the SCCM event"}],
                "versions": [{"version": 1, "origin": "llm_initial"}], "approvals": [],
                "deployments": []},
            "/intelligence/TI-2026-0001": {
                "claims": [{"claim_id": "CL-1", "kind": "behavior", "type": None,
                            "value": None, "description": "PowerShell", "attack_id": "T1059.001",
                            "context": "unknown", "usable": True,
                            "evidence": {"start": 4, "end": 14, "verified": True}}],
                "sanitisation_stripped": ["hidden_html"],
                "priority": {"score": 71.2, "band": "high", "independent_sources": 1,
                             "components": [{"component": "recency", "value": 100.0}]},
                "opportunities": [{"opportunity_id": 1, "decision": "behavioral",
                                   "reason": "visible", "override_applied": True,
                                   "override_reason": "telemetry missing"}]},
            "/intelligence/TI-2026-0001/text": {"text": "The powershell ran <b>x</b>"},
            "/opportunities": [{"opportunity_id": 1, "intel_id": "TI-2026-0001",
                                "decision": "behavioral"}],
            "/detections": [{"id": 5, "wazuh_rule": 110000, "event_time": "t",
                             "disposition": "unknown", "analyst": None}],
            "/audit": {"chain_ok": True, "checked": 7, "events": [
                {"id": 1, "ts": "t", "actor": "a", "action": "ingest.accepted",
                 "entity_id": "TI-2026-0001"}]},
        }
        self.sent.append(("GET", path))
        return table[path]

    def post(self, path, json=None, **params):
        self.sent.append(("POST", path, json))
        return {"ok": True}

    put = post
    upload = post


def render(page, state="pending_approval"):
    script = f"""
import streamlit as st
from tests.unit.test_ui import Fake
from ui.pages import {page}
fake = st.session_state.setdefault("fake", Fake({state!r}))
{page}(fake)
"""
    at = AppTest.from_string(script).run(timeout=30)
    return at


def test_the_overview_page_shows_counts_cost_and_the_queue():
    at = render("overview_page")
    assert not at.exception
    assert [m.value for m in at.metric][:3] == ["2", "1", "3"]
    labels = [m.label for m in at.metric]
    assert "Analyst minutes" in labels and any(label.startswith("Cost") for label in labels)
    assert at.dataframe and at.selectbox[0].options == ["TI-2026-0001"]


def test_the_workbench_shows_gates_and_only_offers_approval_in_the_pending_state():
    at = render("workbench_page", "pending_approval")
    assert not at.exception
    text = " ".join(w.value for w in at.warning)
    assert "SHA-256" in text and "ab" * 32 in text                 # the hash being approved
    buttons = [b.label for b in at.button]
    assert "Approve" in buttons and "Reject" in buttons
    assert "Export package" in buttons

    draft = render("workbench_page", "draft")
    labels = [b.label for b in draft.button]
    assert "Approve" not in labels and "Submit for approval" not in labels
    assert "Deploy to the lab" not in labels
    assert any("cannot be deployed" in c.value for c in draft.caption)

    validated = render("workbench_page", "validated")
    assert "Submit for approval" in [b.label for b in validated.button]


def test_clicking_approve_sends_the_comment_to_the_api():
    at = render("workbench_page", "pending_approval")
    next(t for t in at.text_input if t.label == "Comment").set_value("looks right").run()
    next(b for b in at.button if b.label == "Approve").click().run()
    sent = at.session_state["fake"].sent
    assert ("POST", "/rules/RULE-2026-0001/approve", {"comment": "looks right"}) in sent


def test_deploying_needs_an_explicit_confirmation():
    at = render("workbench_page", "approved")
    deploy = next(b for b in at.button if b.label == "Deploy to the lab")
    assert deploy.disabled
    next(c for c in at.checkbox if "restarts it" in c.label).check().run()
    deploy = next(b for b in at.button if b.label == "Deploy to the lab")
    assert not deploy.disabled
    deploy.click().run()
    assert ("POST", "/rules/RULE-2026-0001/deploy-lab", {"dry_run": False}) in \
        at.session_state["fake"].sent


def test_the_results_page_shows_cost_detections_and_the_audit_chain():
    at = render("results_page")
    assert not at.exception
    assert any("Hash chain intact" in s.value for s in at.success)
    assert at.dataframe and at.selectbox
