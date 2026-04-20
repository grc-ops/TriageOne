"""TriageOne — Monitoring Dashboard page."""
from __future__ import annotations
import time
import httpx, pandas as pd, streamlit as st
from frontend.components.charts import country_choropleth, sector_bar_chart, severity_donut, source_pie, timeline_chart

API = "http://127.0.0.1:8000"

def _sev_badge(s):
    c = {"critical":"#dc2626","high":"#d97706","medium":"#2563eb","low":"#059669"}.get(s,"#6b7280")
    return f'<span style="background:{c};color:#fff;padding:3px 10px;border-radius:5px;font-size:11px;font-weight:600;">{s.capitalize()}</span>'

def _time_ago(ts):
    if not ts: return "Unknown"
    d = time.time() - ts
    if d < 3600: return f"{int(d/60)}m ago"
    if d < 86400: return f"{int(d/3600)}h ago"
    return f"{int(d/86400)}d ago"

def render():
    st.markdown("## 📊 Monitoring Dashboard")
    _, col_r = st.columns([4,1])
    with col_r: refresh = st.button("🔄 Refresh feeds", use_container_width=True)
    ep = "refresh" if refresh else "stats"
    try:
        with st.spinner("Loading..."):
            resp = httpx.get(f"{API}/api/dashboard/{ep}", timeout=30); resp.raise_for_status(); stats = resp.json()
    except httpx.ConnectError: st.error("Cannot connect to backend."); return
    except Exception as e: st.error(f"Failed: {e}"); return
    if not stats or stats.get("total_advisories",0) == 0:
        st.info("No advisories. Click **Refresh feeds**."); return
    c1,c2,c3,c4,c5 = st.columns(5)
    c1.metric("Total", stats.get("total_advisories",0)); c2.metric("Critical", stats.get("critical_count",0))
    c3.metric("High", stats.get("high_count",0)); c4.metric("Medium", stats.get("medium_count",0))
    c5.metric("Sectors", stats.get("sectors_affected",0))
    st.markdown("---")
    t1,t2,t3,t4 = st.tabs(["Overview","Sector risk","Geo risk map","Advisory feed"])
    with t1:
        co1,co2 = st.columns(2)
        with co1: st.plotly_chart(severity_donut({"critical":stats.get("critical_count",0),"high":stats.get("high_count",0),"medium":stats.get("medium_count",0),"low":stats.get("low_count",0)}), use_container_width=True)
        with co2:
            src = stats.get("by_source",{})
            if src: st.plotly_chart(source_pie(src), use_container_width=True)
        advs = stats.get("recent_advisories",[])
        if advs: st.plotly_chart(timeline_chart(advs), use_container_width=True)
    with t2:
        sd = stats.get("by_sector",{})
        if sd:
            st.plotly_chart(sector_bar_chart(sd), use_container_width=True)
            cols = st.columns(3)
            for i,(s,d) in enumerate(sorted(sd.items(), key=lambda x:-x[1].get("total",0))):
                with cols[i%3]:
                    crit = d.get("critical",0); high = d.get("high",0); total = d.get("total",0)
                    sev = "critical" if crit>=5 else "high" if crit>=2 or high>=5 else "medium"
                    pct = min(100, int((crit*3+high*2+total)/max(total,1)*25))
                    bc = {"critical":"#dc2626","high":"#d97706","medium":"#2563eb"}.get(sev,"#2563eb")
                    st.markdown(f"""<div style="background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.06);border-radius:10px;padding:16px;margin-bottom:10px;">
                    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;"><span style="font-weight:600;font-size:14px;">{s.capitalize()}</span>{_sev_badge(sev)}</div>
                    <div style="font-size:12px;color:rgba(255,255,255,0.45);margin-bottom:8px;">{total} advisories · {crit} critical</div>
                    <div style="height:4px;background:rgba(255,255,255,0.06);border-radius:2px;overflow:hidden;"><div style="width:{pct}%;height:100%;background:{bc};border-radius:2px;"></div></div></div>""", unsafe_allow_html=True)
    with t3:
        cd = stats.get("by_country",{})
        if cd:
            st.plotly_chart(country_choropleth(cd), use_container_width=True)
            st.dataframe(pd.DataFrame(sorted(cd.items(), key=lambda x:-x[1])[:15], columns=["Country","Advisories"]), use_container_width=True, hide_index=True)
    with t4:
        advs = stats.get("recent_advisories",[])
        fc1,fc2,fc3 = st.columns(3)
        all_sec = sorted(set(s for a in advs for s in a.get("sectors",[])))
        fs = fc1.selectbox("Sector",["All"]+all_sec); fv = fc2.selectbox("Severity",["All","critical","high","medium","low"])
        all_co = sorted(set(c for a in advs for c in a.get("countries",[])))
        fc_ = fc3.selectbox("Country",["All"]+all_co)
        f = advs
        if fs != "All": f = [a for a in f if fs in a.get("sectors",[])]
        if fv != "All": f = [a for a in f if a.get("severity")==fv]
        if fc_ != "All": f = [a for a in f if fc_ in a.get("countries",[])]
        for adv in f[:50]:
            sv = adv.get("severity","medium")
            bc = {"critical":"#dc2626","high":"#d97706","medium":"#2563eb","low":"#059669"}.get(sv,"#6b7280")
            meta = " · ".join(filter(None, [adv.get("source",""), _time_ago(adv.get("published_at")),
                                            ", ".join(s.capitalize() for s in adv.get("sectors",[])[:3])]))
            st.markdown(f"""<div style="background:rgba(255,255,255,0.02);border:1px solid rgba(255,255,255,0.06);border-left:3px solid {bc};border-radius:0 8px 8px 0;padding:12px 16px;margin-bottom:8px;">
            <div style="display:flex;justify-content:space-between;align-items:start;"><div style="flex:1;">
            <div style="font-size:13px;font-weight:600;margin-bottom:4px;">{adv.get('title','')[:200]}</div>
            <div style="font-size:11px;color:rgba(255,255,255,0.4);">{meta}</div></div>{_sev_badge(sv)}</div></div>""", unsafe_allow_html=True)
