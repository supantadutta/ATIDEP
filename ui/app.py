"""Streamlit entry point: ``streamlit run ui/app.py`` (after ``python -m app serve``)."""

from __future__ import annotations

import os

import streamlit as st

from ui.client import ApiClient
from ui.pages import overview_page, results_page, workbench_page

st.set_page_config(page_title="ATIDEP", layout="wide")
st.sidebar.title("ATIDEP")
who = st.sidebar.text_input("Your name (recorded with every action)",
                            os.environ.get("ATIDEP_ANALYST", ""))
page = st.sidebar.radio("Page", ["Overview and queue", "Rule workbench", "Results and cost"])
if not who.strip():
    st.info("Enter your name in the sidebar. Approvals are recorded against a person.")
    st.stop()
client = ApiClient(os.environ.get("ATIDEP_API_URL", "http://127.0.0.1:8000"),
                   os.environ.get("ATIDEP_API_KEY", ""), who.strip())
{"Overview and queue": overview_page, "Rule workbench": workbench_page,
 "Results and cost": results_page}[page](client)
