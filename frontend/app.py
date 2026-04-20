"""TriageOne — Streamlit application entry point."""
import streamlit as st
from pathlib import Path

st.set_page_config(page_title="TriageOne", page_icon="🛡️", layout="wide", initial_sidebar_state="expanded")

css_path = Path(__file__).parent / "styles" / "custom.css"
if css_path.exists():
    st.markdown(f"<style>{css_path.read_text()}</style>", unsafe_allow_html=True)

with st.sidebar:
    st.markdown("""<div style="text-align:center;padding:1rem 0 0.5rem;">
        <span style="font-size:2.2rem;">🛡️</span>
        <h2 style="margin:0.3rem 0 0;font-size:1.5rem;font-weight:700;">TriageOne</h2>
        <p style="color:rgba(255,255,255,0.45);font-size:0.8rem;margin:0;">v1.3 — IOC Triage & Cyber-Risk Monitor</p>
    </div><hr style="border-color:rgba(255,255,255,0.06);margin:1rem 0;">""", unsafe_allow_html=True)
    page = st.radio("Navigation", ["🔍 IOC Triage", "📊 Monitoring Dashboard", "📜 History"], label_visibility="collapsed")
    st.markdown("---")
    st.caption("Backend: FastAPI · Frontend: Streamlit")

if page == "🔍 IOC Triage":
    from frontend.pages.triage_page import render
    render()
elif page == "📊 Monitoring Dashboard":
    from frontend.pages.dashboard_page import render
    render()
elif page == "📜 History":
    from frontend.pages.history_page import render
    render()
