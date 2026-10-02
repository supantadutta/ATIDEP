"""The three pages (blueprint §23). Each function takes the API client, so it can be tested with
a fake one. Nothing here decides anything: it shows what the services return and sends the
person's actions back."""

from __future__ import annotations

import html
from typing import Any

import streamlit as st

from ui.client import ApiClient, ApiError

ICON = {"passed": "✅", "failed": "❌", "not_run": "⏺️"}
BAND_ORDER = ["critical", "high", "medium", "low"]


def _guard(fn):
    def run(*a: Any, **k: Any) -> Any:
        try:
            return fn(*a, **k)
        except ApiError as exc:
            st.error(f"{exc.status}: {exc.detail}")
            return None
    return run


def highlight(text: str, spans: list[tuple[int, int]]) -> str:
    """HTML for the sanitised report with verified quotations marked. Everything is escaped
    first; only the ``<mark>`` tags are ours."""
    out, pos = [], 0
    for start, end in sorted(spans):
        if start < pos or end > len(text):
            continue                                   # overlapping or out of range: skip
        out.append(html.escape(text[pos:start]))
        out.append("<mark>" + html.escape(text[start:end]) + "</mark>")
        pos = end
    out.append(html.escape(text[pos:]))
    return "<div style='white-space:pre-wrap;font-size:0.9rem'>" + "".join(out) + "</div>"


# ---- page 1 ----------------------------------------------------------------------
def overview_page(api: ApiClient) -> None:
    st.header("Overview and queue")
    ov = api.get("/overview")
    cols = st.columns(5)
    cols[0].metric("Items", ov["items"])
    cols[1].metric("High priority", ov["high_priority"])
    cols[2].metric("Opportunities", ov["opportunities"])
    cols[3].metric("Duplicates seen", ov["duplicates_seen"])
    cols[4].metric("Alerts", ov["alerts"])
    st.caption("Rules by state: " + (", ".join(f"{k}: {v}" for k, v in sorted(
        ov["rules_by_state"].items())) or "none yet"))
    cost = api.get("/costs/summary")
    c = st.columns(3)
    c[0].metric("Tokens (in / out)", f"{cost['tokens']['input']:,} / {cost['tokens']['output']:,}")
    c[1].metric("Analyst minutes", cost["analyst_active_minutes"])
    c[2].metric(f"Cost ({cost['currency']})", cost["cost"]["total"])

    st.subheader("Review queue (highest priority first)")
    items = api.get("/intelligence", limit=200)
    if items:
        st.dataframe([{"id": i["intel_id"], "title": i["title"], "status": i["status"],
                       "band": i["priority_band"], "score": i["priority_score"]} for i in items],
                     use_container_width=True, hide_index=True)
        pick = st.selectbox("Open an item", [i["intel_id"] for i in items], key="queue_pick")
        if st.button("Process with the models (extract, score, find opportunities)"):
            with st.spinner("Working…"):
                _guard(lambda: st.json(api.post(f"/intelligence/{pick}/process", json={})))()
    else:
        st.info("Nothing in the queue yet. Upload a report or run the collectors.")

    with st.expander("Add intelligence"):
        up = st.file_uploader("Report (HTML, PDF, text, RSS, JSON)", key="upload")
        source = st.text_input("Source name", "Manual upload")
        rel = st.selectbox("Source reliability (Admiralty)", list("ABCDEF"), index=2)
        cred = st.selectbox("Information credibility", [1, 2, 3, 4, 5, 6], index=2)
        if st.button("Ingest") and up is not None:
            _guard(lambda: st.json(api.upload(up.getvalue(), source=source, title=up.name,
                                              reliability=rel, credibility=cred)))()
        if st.button("Run the configured collectors"):
            _guard(lambda: st.json(api.post("/collection/run")))()


# ---- page 2 ----------------------------------------------------------------------
def _timer_controls(api: ApiClient, intel_id: str) -> None:
    st.caption("Analyst timer: runs only while you work on this item; it auto-pauses after two "
               "minutes without activity.")
    cols = st.columns(5)
    cond = cols[0].selectbox("Condition", ["B", "A"], key=f"cond_{intel_id}")
    act = cols[1].selectbox("Activity", ["review_approval", "reading", "editing", "validation",
                                         "testing", "packaging", "other"], key=f"act_{intel_id}")
    if cols[2].button("Start", key=f"ts_{intel_id}"):
        _guard(lambda: api.post(f"/timers/{intel_id}/start",
                                json={"condition": cond, "activity": act}))()
    if cols[3].button("Pause / resume", key=f"tp_{intel_id}"):
        res = _guard(lambda: api.post(f"/timers/{intel_id}/pause"))()
        if res is None:
            _guard(lambda: api.post(f"/timers/{intel_id}/resume"))()
    if cols[4].button("Stop", key=f"tx_{intel_id}"):
        res = _guard(lambda: api.post(f"/timers/{intel_id}/stop"))()
        if res:
            st.success(f"Recorded {res['active_seconds'] / 60:.1f} active minutes")


def _evidence_tab(api: ApiClient, intel_id: str) -> None:
    item = api.get(f"/intelligence/{intel_id}")
    text = api.get(f"/intelligence/{intel_id}/text")["text"]
    spans = [(c["evidence"]["start"], c["evidence"]["end"]) for c in item["claims"]
             if c["evidence"]["verified"]]
    st.markdown(highlight(text, spans), unsafe_allow_html=True)
    if item["sanitisation_stripped"]:
        st.warning("Removed before any model saw the text: "
                   + ", ".join(map(str, item["sanitisation_stripped"])))
    st.subheader("Claims")
    st.dataframe([{"claim": c["claim_id"], "kind": c["kind"], "type": c["type"],
                   "value": c["value"] or c["description"], "attack": c["attack_id"],
                   "context": c["context"], "verified": c["evidence"]["verified"],
                   "usable": c["usable"]} for c in item["claims"]],
                 use_container_width=True, hide_index=True)
    st.subheader("Priority")
    pr = item["priority"]
    st.write(f"**{pr.get('score')}** ({pr.get('band')}); independent sources "
             f"{pr.get('independent_sources')}")
    if pr.get("components"):
        st.dataframe(pr["components"], use_container_width=True, hide_index=True)
    st.subheader("Opportunities")
    for o in item["opportunities"]:
        st.markdown(f"**{o['decision']}** (opportunity {o['opportunity_id']}): {o['reason']}"
                    + (f"  \n_Override: {o['override_reason']}_" if o["override_applied"] else ""))


def _gates(rule: dict[str, Any]) -> None:
    st.dataframe([{"": ICON.get(g["status"], ""), "gate": g["gate"], "status": g["status"],
                   "tier": g["tier"], "why": g["message"][:300]} for g in rule["gates"]],
                 use_container_width=True, hide_index=True)


def workbench_page(api: ApiClient) -> None:
    st.header("Rule workbench and approval")
    rules = api.get("/rules")
    if not rules:
        st.info("No rules yet. Process an item, then generate a rule from an opportunity.")
        _generate_form(api)
        return
    rid = st.selectbox("Rule", [r["rule_id"] for r in rules], format_func=lambda x: next(
        f"{x} · {r['kind']} · {r['state']} · score {r['quality_score']}" for r in rules
        if r["rule_id"] == x))
    rule = api.get(f"/rules/{rid}")
    _timer_controls(api, rule["intel_id"])
    st.markdown(f"**State:** `{rule['state']}` · **version** {rule['version']} · **content "
                f"hash** `{rule['content_sha256'][:16]}…`")
    tabs = st.tabs(["Rule", "Gates", "Evidence", "History", "Actions"])
    with tabs[0]:
        edited = st.text_area("Sigma rule / indicator bundle", rule["content"], height=380,
                              key=f"edit_{rid}_{rule['version']}")
        if st.button("Save as a new version (voids validation and approval)") \
                and edited != rule["content"]:
            _guard(lambda: st.json(api.put(f"/rules/{rid}/content", {"content": edited})))()
        if rule["assumptions"]:
            st.subheader("Declared assumptions")
            st.dataframe(rule["assumptions"], use_container_width=True, hide_index=True)
        if rule["use_case"]:
            with st.expander("Use case"):
                st.json(rule["use_case"])
    with tabs[1]:
        if rule["gates"]:
            _gates(rule)
        else:
            st.info("Not validated yet.")
        if st.button("Run the gates (G1 to G11)"):
            with st.spinner("Validating…"):
                _guard(lambda: st.json(api.post(f"/rules/{rid}/validate")))()
        if st.button("Re-run the event tests (tier 1, nothing is stored)"):
            _guard(lambda: st.json(api.post(f"/rules/{rid}/test", json={"tier": 1})))()
    with tabs[2]:
        _evidence_tab(api, rule["intel_id"])
    with tabs[3]:
        st.dataframe(rule["versions"], use_container_width=True, hide_index=True)
        st.dataframe(rule["approvals"], use_container_width=True, hide_index=True)
        st.dataframe(rule["deployments"], use_container_width=True, hide_index=True)
    with tabs[4]:
        _actions(api, rid, rule)
    with st.expander("Generate another rule"):
        _generate_form(api)


def _actions(api: ApiClient, rid: str, rule: dict[str, Any]) -> None:
    state = rule["state"]
    if state == "validated" and st.button("Submit for approval"):
        _guard(lambda: st.json(api.post(f"/rules/{rid}/submit")))()
    if state == "pending_approval":
        st.warning(f"You are approving exactly this content: SHA-256 `{rule['content_sha256']}`")
        comment = st.text_input("Comment", key=f"cm_{rid}")
        c1, c2 = st.columns(2)
        if c1.button("Approve"):
            _guard(lambda: st.json(api.post(f"/rules/{rid}/approve", json={"comment": comment})))()
        if c2.button("Reject"):
            _guard(lambda: st.json(api.post(f"/rules/{rid}/reject", json={"comment": comment})))()
    if state in ("validated", "pending_approval", "approved", "deployed", "monitored"):
        if st.button("Export package"):
            _guard(lambda: st.json(api.post(f"/rules/{rid}/package")))()
    if state in ("approved", "deployed", "monitored"):
        if st.button("Dry run on the lab manager (tier 2a)"):
            _guard(lambda: st.json(api.post(f"/rules/{rid}/deploy-lab", json={"dry_run": True})))()
        confirm = st.checkbox("I understand this changes the lab manager and restarts it",
                              key=f"cf_{rid}")
        if st.button("Deploy to the lab", disabled=not confirm):
            _guard(lambda: st.json(api.post(f"/rules/{rid}/deploy-lab",
                                            json={"dry_run": False})))()
    if state in ("draft", "blocked", "rejected"):
        st.caption("This rule cannot be deployed in its current state.")


def _generate_form(api: ApiClient) -> None:
    opps = api.get("/opportunities")
    generating = [o for o in opps if o["decision"] in ("ioc_based", "behavioral")]
    if not generating:
        st.caption("No opportunity that generates a rule.")
        return
    pick = st.selectbox("Opportunity", [o["opportunity_id"] for o in generating],
                        format_func=lambda x: next(
                            f"{x} · {o['intel_id']} · {o['decision']}" for o in generating
                            if o["opportunity_id"] == x), key="gen_pick")
    if st.button("Generate"):
        with st.spinner("Generating…"):
            _guard(lambda: st.json(api.post(f"/opportunities/{pick}/generate-rule", json={})))()


# ---- page 3 ----------------------------------------------------------------------
def results_page(api: ApiClient) -> None:
    st.header("Results and cost")
    cost = api.get("/costs/summary")
    st.subheader("Cost")
    st.json({k: cost[k] for k in ("currency", "cost", "items", "accepted_rules",
                                  "analyst_active_minutes")})
    st.dataframe([{"agent": a, **v} for a, v in cost["agents"].items()],
                 use_container_width=True, hide_index=True)
    st.caption(cost["note"])
    st.subheader("Detections")
    dets = api.get("/detections")
    if dets:
        st.dataframe([{"id": d["id"], "rule": d["wazuh_rule"], "time": d["event_time"],
                       "disposition": d["disposition"], "analyst": d["analyst"]} for d in dets],
                     use_container_width=True, hide_index=True)
        pick = st.selectbox("Alert", [d["id"] for d in dets], key="det_pick")
        disp = st.selectbox("Disposition", ["true_positive", "false_positive",
                                            "benign_true_positive", "unknown"])
        if st.button("Record disposition"):
            _guard(lambda: st.json(api.post(f"/detections/{pick}/feedback",
                                            json={"disposition": disp})))()
    else:
        st.info("No alerts recorded yet.")
    live = [r for r in api.get("/rules") if r["state"] in ("deployed", "monitored")]
    if live:
        st.subheader("Improvement recommendations")
        rid = st.selectbox("Live rule", [r["rule_id"] for r in live])
        st.json(api.get(f"/rules/{rid}/stats"))
        if st.button("Ask the Improvement Agent"):
            with st.spinner("Thinking…"):
                _guard(lambda: st.json(api.post(f"/rules/{rid}/improve")))()
    st.subheader("Audit trail")
    audit = api.get("/audit", limit=25)
    (st.success if audit["chain_ok"] else st.error)(
        f"Hash chain {'intact' if audit['chain_ok'] else 'BROKEN'} ({audit['checked']} events)")
    st.dataframe([{k: e[k] for k in ("id", "ts", "actor", "action", "entity_id")}
                  for e in audit["events"]], use_container_width=True, hide_index=True)
