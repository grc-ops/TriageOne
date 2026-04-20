"""TriageOne — History page."""
from __future__ import annotations
import json
from datetime import datetime
import httpx, pandas as pd, streamlit as st

API = "http://127.0.0.1:8000"

def render():
    st.markdown("## 📜 Triage History")
    try:
        sr = httpx.get(f"{API}/api/triage/stats", timeout=5); sr.raise_for_status(); stats = sr.json()
    except: stats = {"total":0,"by_verdict":{},"by_type":{}}
    c1,c2,c3,c4 = st.columns(4)
    bv = stats.get("by_verdict",{})
    c1.metric("Total", stats.get("total",0)); c2.metric("Malicious", bv.get("malicious",0))
    c3.metric("Suspicious", bv.get("suspicious",0)); c4.metric("Clean", bv.get("low_risk",0)+bv.get("unknown",0))
    if stats.get("total",0) == 0: st.info("No history yet."); return
    st.markdown("---")
    try:
        hr = httpx.get(f"{API}/api/triage/history", params={"limit":100}, timeout=10); hr.raise_for_status()
        history = hr.json().get("results",[])
    except Exception as e: st.error(f"Failed: {e}"); return
    rows = []
    for h in history:
        try: dt = datetime.fromtimestamp(h.get("queried_at",0)).strftime("%Y-%m-%d %H:%M")
        except: dt = "—"
        rows.append({"Time":dt, "IOC":h.get("ioc_value",""), "Type":h.get("ioc_type","").upper(),
                     "Score":h.get("risk_score",0), "Verdict":h.get("verdict","unknown").replace("_"," ").capitalize()})
    df = pd.DataFrame(rows)
    search = st.text_input("Search", placeholder="Filter...", label_visibility="collapsed")
    if search: df = df[df["IOC"].str.contains(search, case=False, na=False)]
    st.dataframe(df, use_container_width=True, hide_index=True,
                column_config={"Score": st.column_config.ProgressColumn("Score", min_value=0, max_value=100, format="%.0f")})
    c1,c2 = st.columns(2)
    c1.download_button("Export CSV", df.to_csv(index=False), file_name="triageone_history.csv", mime="text/csv")
    c2.download_button("Export JSON", json.dumps(history, indent=2, default=str), file_name="triageone_history.json", mime="application/json")
