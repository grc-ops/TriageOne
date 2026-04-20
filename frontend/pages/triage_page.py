"""TriageOne — IOC Triage page v1.3 with full analyst report."""
from __future__ import annotations
import json, time
import httpx, pandas as pd, streamlit as st
from datetime import datetime
from frontend.components.charts import risk_score_gauge, VERDICT_COLORS

API = "http://127.0.0.1:8000"


def _badge(verdict):
    c = {"malicious":"#dc2626","suspicious":"#d97706","low_risk":"#059669","unknown":"#6b7280"}
    return f'<span style="background:{c.get(verdict,"#6b7280")};color:#fff;padding:4px 14px;border-radius:6px;font-weight:600;font-size:13px;">{verdict.replace("_"," ").capitalize()}</span>'


def _sev_color(s):
    if s >= 70: return "#dc2626"
    if s >= 40: return "#d97706"
    if s >= 15: return "#2563eb"
    return "#059669"


def _card(label, value, sub, color=None):
    c = color or "rgba(255,255,255,0.8)"
    return f"""<div style="background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.06);
    border-radius:10px;padding:16px;text-align:center;">
    <div style="font-size:12px;color:rgba(255,255,255,0.5);">{label}</div>
    <div style="font-size:28px;font-weight:700;color:{c};margin:4px 0;">{value}</div>
    <div style="font-size:12px;color:rgba(255,255,255,0.4);">{sub}</div></div>"""


def render():
    st.markdown("## 🔍 IOC Triage")
    st.markdown('<p style="color:rgba(255,255,255,0.5);margin-top:-10px;">Investigate IOCs across multiple threat intelligence providers</p>', unsafe_allow_html=True)

    tab_single, tab_bulk = st.tabs(["Single IOC", "Bulk Input"])

    with tab_single:
        col_in, col_deep, col_btn = st.columns([5, 1, 1])
        with col_in:
            ioc_value = st.text_input("IOC", placeholder="IP, domain, URL, file hash, or filename...", label_visibility="collapsed")
        with col_deep:
            deep = st.checkbox("Deep scan", help="Fetch VT relations & community comments (uses extra API calls)")
        with col_btn:
            submit = st.button("Triage", type="primary", use_container_width=True)

        if ioc_value:
            try:
                det = httpx.get(f"{API}/api/triage/detect", params={"value": ioc_value}, timeout=5)
                st.markdown(f'<p style="font-size:13px;color:rgba(255,255,255,0.5);">Auto-detected: <strong style="color:#60a5fa;">{det.json().get("ioc_type","unknown").upper()}</strong></p>', unsafe_allow_html=True)
            except: pass

        if submit and ioc_value:
            with st.spinner("Querying threat intelligence providers..." + (" (deep scan enabled — this may take 15-30s)" if deep else "")):
                try:
                    resp = httpx.post(f"{API}/api/triage/single", json={"value": ioc_value, "deep_scan": deep}, timeout=60)
                    resp.raise_for_status()
                    result = resp.json()
                except httpx.ConnectError:
                    st.error("Cannot connect to backend. Make sure FastAPI is running on port 8000."); return
                except Exception as e:
                    st.error(f"Triage failed: {e}"); return

            # ── Header ─────────────────────────────────────────────────
            st.markdown("---")
            col_ioc, col_score = st.columns([3, 2])
            with col_ioc:
                st.markdown(f"### `{result['ioc_value']}`")
                st.markdown(f"**Type:** {result['ioc_type'].upper()} · **Providers:** {result.get('providers_responded',0)}/{result.get('providers_queried',0)} · **Time:** {result.get('query_time_ms',0)}ms")
            with col_score:
                score = result.get("risk_score", 0)
                verdict = result.get("verdict", "unknown")
                st.plotly_chart(risk_score_gauge(score, verdict), use_container_width=True, key="gauge_single")
                st.markdown(f'<div style="text-align:center;">{_badge(verdict)}</div>', unsafe_allow_html=True)

            # ── Analyst Brief (always shown at top) ─────────────────────
            brief = result.get("analyst_brief", "")
            if brief:
                st.markdown("#### 📋 Analyst brief")
                st.markdown(f"""<div style="background:rgba(37,99,235,0.06);border:1px solid rgba(37,99,235,0.15);
                border-radius:10px;padding:16px 20px;font-size:13px;line-height:1.7;color:rgba(255,255,255,0.85);">
                {brief}</div>""", unsafe_allow_html=True)
                st.markdown("")
                col_copy, _ = st.columns([1, 4])
                with col_copy:
                    st.download_button("📋 Copy brief as text", brief, file_name=f"triageone_brief_{result['ioc_value']}.txt", mime="text/plain")

            # ── Tabbed report ───────────────────────────────────────────
            tab_det, tab_dtl, tab_rel, tab_comm, tab_raw = st.tabs(
                ["🔍 Detection", "📄 Details", "🔗 Relations", "💬 Community", "📦 Raw JSON"]
            )

            # ── Detection tab ───────────────────────────────────────────
            with tab_det:
                provider_results = result.get("provider_results", [])
                if provider_results:
                    cols = st.columns(min(len(provider_results), 4))
                    for i, pr in enumerate(provider_results):
                        with cols[i % len(cols)]:
                            err = pr.get("error")
                            ps = pr.get("score")
                            if err:
                                st.markdown(_card(pr["provider"], "—", err[:40], "#6b7280"), unsafe_allow_html=True)
                            elif ps is not None:
                                st.markdown(_card(pr["provider"], ps, pr.get("raw_score","—"), _sev_color(ps)), unsafe_allow_html=True)
                            else:
                                st.markdown(_card(pr["provider"], "N/A", "Not queried", "#6b7280"), unsafe_allow_html=True)

                # Crowdsourced context
                details = result.get("details", {})
                crowd = details.get("crowdsourced_context", [])
                if crowd:
                    st.markdown("##### Crowdsourced context")
                    for ctx in crowd:
                        sev = ctx.get("severity","info")
                        bc = {"high":"#dc2626","medium":"#d97706","low":"#2563eb","info":"#6b7280"}.get(sev,"#6b7280")
                        st.markdown(f"""<div style="background:rgba(255,255,255,0.02);border:1px solid rgba(255,255,255,0.06);
                        border-left:3px solid {bc};border-radius:0 8px 8px 0;padding:10px 14px;margin-bottom:6px;">
                        <div style="font-size:13px;font-weight:600;">{ctx.get('title','')}</div>
                        <div style="font-size:11px;color:rgba(255,255,255,0.4);">{ctx.get('source','')} {('— '+ctx['timestamp']) if ctx.get('timestamp') else ''}</div>
                        {f'<div style="font-size:12px;color:rgba(255,255,255,0.6);margin-top:6px;">{ctx["details"][:300]}</div>' if ctx.get('details') else ''}
                        </div>""", unsafe_allow_html=True)

                ids_rules = details.get("crowdsourced_ids", [])
                if ids_rules:
                    st.markdown("##### IDS rule matches")
                    for ids in ids_rules:
                        st.markdown(f"""<div style="background:rgba(220,38,38,0.06);border:1px solid rgba(220,38,38,0.15);
                        border-radius:8px;padding:8px 12px;margin-bottom:4px;font-size:12px;">
                        <span style="color:#f87171;font-weight:600;">[{ids.get('alert_severity','')}]</span> {ids.get('rule_msg','')}
                        <span style="color:rgba(255,255,255,0.3);"> — {ids.get('rule_source','')}</span></div>""", unsafe_allow_html=True)

                yara = details.get("yara_rules", [])
                if yara:
                    st.markdown("##### YARA rule matches")
                    for y in yara:
                        st.markdown(f"""<div style="background:rgba(124,58,237,0.06);border:1px solid rgba(124,58,237,0.15);
                        border-radius:8px;padding:8px 12px;margin-bottom:4px;font-size:12px;">
                        <span style="color:#a78bfa;font-weight:600;">{y.get('rule_name','')}</span>
                        <span style="color:rgba(255,255,255,0.5);"> ({y.get('ruleset_name','')})</span>
                        {f'<div style="color:rgba(255,255,255,0.4);margin-top:2px;">{y["description"][:200]}</div>' if y.get('description') else ''}</div>""", unsafe_allow_html=True)

                sigma = details.get("sigma_rules", [])
                if sigma:
                    st.markdown("##### Sigma rule matches")
                    for s in sigma:
                        lc = {"critical":"#dc2626","high":"#d97706","medium":"#2563eb","low":"#059669"}.get(s.get("rule_level",""),"#6b7280")
                        st.markdown(f"""<div style="background:rgba(255,255,255,0.02);border:1px solid rgba(255,255,255,0.06);
                        border-radius:8px;padding:8px 12px;margin-bottom:4px;font-size:12px;">
                        <span style="color:{lc};font-weight:600;">[{s.get('rule_level','')}]</span> {s.get('rule_title','')}
                        {f'<div style="color:rgba(255,255,255,0.4);margin-top:2px;">{s["rule_description"][:200]}</div>' if s.get('rule_description') else ''}</div>""", unsafe_allow_html=True)

            # ── Details tab ─────────────────────────────────────────────
            with tab_dtl:
                details = result.get("details", {})
                tags = details.get("tags", [])
                if tags:
                    tag_html = " ".join(f'<span style="background:rgba(37,99,235,0.15);color:#60a5fa;padding:3px 10px;border-radius:5px;font-size:12px;margin:2px;">{t}</span>' for t in tags[:15])
                    st.markdown(tag_html, unsafe_allow_html=True)
                    st.markdown("")

                # Community reputation
                cv = details.get("community_votes")
                cr = details.get("community_reputation")
                if cv or cr is not None:
                    st.markdown("##### Community reputation")
                    rc = st.columns(3)
                    if cr is not None: rc[0].metric("Reputation score", cr)
                    if cv: rc[1].metric("Harmless votes", cv.get("harmless",0)); rc[2].metric("Malicious votes", cv.get("malicious",0))

                # Threat classification
                tl = details.get("threat_label")
                ts = details.get("threat_severity")
                if tl or ts:
                    st.markdown("##### Threat classification")
                    tc = st.columns(3)
                    if tl: tc[0].metric("Threat label", tl)
                    if ts: tc[1].metric("Severity", ts.get("level","").replace("SEVERITY_",""))

                # DNS records
                dns = details.get("last_dns_records", [])
                if dns:
                    st.markdown("##### DNS records")
                    dns_df = pd.DataFrame(dns)
                    st.dataframe(dns_df, use_container_width=True, hide_index=True)

                # WHOIS
                whois = details.get("whois_snippet")
                if whois:
                    st.markdown("##### WHOIS")
                    st.code(whois, language=None)

                # SSL
                ssl_subj = details.get("ssl_subject")
                ssl_iss = details.get("ssl_issuer")
                if ssl_subj or ssl_iss:
                    st.markdown("##### SSL certificate")
                    sc = st.columns(2)
                    if ssl_subj: sc[0].metric("Subject", ssl_subj)
                    if ssl_iss: sc[1].metric("Issuer", ssl_iss)

                # Flat key-value details
                skip = {"tags","crowdsourced_context","crowdsourced_ids","yara_rules","sigma_rules",
                        "community_votes","community_reputation","threat_label","threat_severity",
                        "analysis_stats","last_dns_records","whois_snippet","ssl_subject","ssl_issuer","known_filenames"}
                dc = st.columns(2)
                idx = 0
                for k, v in details.items():
                    if k in skip or not v or isinstance(v, (dict, list)): continue
                    with dc[idx % 2]:
                        st.markdown(f'<div style="display:flex;justify-content:space-between;padding:6px 0;border-bottom:1px solid rgba(255,255,255,0.04);"><span style="color:rgba(255,255,255,0.5);font-size:13px;">{k.replace("_"," ").title()}</span><span style="font-size:13px;">{v}</span></div>', unsafe_allow_html=True)
                        idx += 1

            # ── Relations tab ───────────────────────────────────────────
            with tab_rel:
                rels = result.get("vt_relations", {})
                if not rels:
                    if not deep:
                        st.info("Enable **Deep scan** to fetch VirusTotal relations (resolutions, communicating files, downloaded files, etc.)")
                    else:
                        st.info("No relations found for this IOC.")
                else:
                    for rel_type, items in rels.items():
                        label = rel_type.replace("_", " ").title()
                        st.markdown(f"##### {label} ({len(items)})")
                        if rel_type == "resolutions":
                            df = pd.DataFrame([{"Host": i.get("host_name",""), "IP": i.get("ip_address",""),
                                                "Date": i.get("date","")} for i in items])
                            st.dataframe(df, use_container_width=True, hide_index=True)
                        else:
                            rows = []
                            for i in items:
                                name = i.get("meaningful_name") or i.get("id","")[:20]
                                mal = i.get("malicious", 0)
                                tot = i.get("total", 0)
                                td = i.get("type_description", "")
                                rows.append({"Name": name, "Type": td, "Detections": f"{mal}/{tot}" if tot else "—",
                                            "ID": i.get("id","")[:16]+"..."})
                            if rows:
                                df = pd.DataFrame(rows)
                                st.dataframe(df, use_container_width=True, hide_index=True)

            # ── Community tab ───────────────────────────────────────────
            with tab_comm:
                comments = result.get("vt_comments", [])
                if not comments:
                    if not deep:
                        st.info("Enable **Deep scan** to fetch VirusTotal community comments.")
                    else:
                        st.info("No community comments found.")
                else:
                    st.markdown(f"##### VirusTotal community ({len(comments)} comments)")
                    for c in comments:
                        text = c.get("text", "")[:500]
                        votes = c.get("votes", {})
                        pos = votes.get("positive", 0)
                        neg = votes.get("negative", 0)
                        ts = c.get("date", 0)
                        try: dt = datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M") if ts else ""
                        except: dt = ""
                        st.markdown(f"""<div style="background:rgba(255,255,255,0.02);border:1px solid rgba(255,255,255,0.06);
                        border-radius:8px;padding:12px 16px;margin-bottom:8px;">
                        <div style="font-size:12px;color:rgba(255,255,255,0.7);white-space:pre-wrap;">{text}</div>
                        <div style="font-size:11px;color:rgba(255,255,255,0.3);margin-top:6px;">
                        {dt} · 👍 {pos} · 👎 {neg}</div></div>""", unsafe_allow_html=True)

            # ── Raw JSON tab ────────────────────────────────────────────
            with tab_raw:
                st.json(result)
                st.download_button("Export full report JSON", json.dumps(result, indent=2, default=str),
                                   file_name=f"triageone_{result['ioc_value']}.json", mime="application/json")

    # ── Bulk tab ────────────────────────────────────────────────────────
    with tab_bulk:
        st.markdown("Paste one IOC per line (max 100)")
        bulk_text = st.text_area("Bulk", height=200, placeholder="185.220.101.34\nevil-domain.xyz\nd41d8cd98f00b204e9800998ecf8427e", label_visibility="collapsed")
        uploaded = st.file_uploader("Or upload CSV", type=["csv","txt"])
        if uploaded: bulk_text = uploaded.read().decode("utf-8", errors="ignore")
        if st.button("Triage All", type="primary", key="bulk_btn") and bulk_text:
            values = [l.strip() for l in bulk_text.strip().splitlines() if l.strip()][:100]
            with st.spinner(f"Triaging {len(values)} IOCs..."):
                try:
                    resp = httpx.post(f"{API}/api/triage/bulk", json={"values": values}, timeout=120)
                    resp.raise_for_status(); results = resp.json()
                except httpx.ConnectError: st.error("Cannot connect to backend."); return
                except Exception as e: st.error(f"Bulk triage failed: {e}"); return
            rows = [{"IOC": r["ioc_value"], "Type": r["ioc_type"].upper(), "Score": r["risk_score"],
                     "Verdict": r["verdict"].replace("_"," ").capitalize(),
                     "Providers": f"{r.get('providers_responded',0)}/{r.get('providers_queried',0)}",
                     "Brief": r.get("analyst_brief","")[:100]+"..."} for r in results]
            df = pd.DataFrame(rows)
            c1,c2,c3,c4 = st.columns(4)
            c1.metric("Total", len(results))
            c2.metric("Malicious", sum(1 for r in results if r.get("verdict")=="malicious"))
            c3.metric("Suspicious", sum(1 for r in results if r.get("verdict")=="suspicious"))
            c4.metric("Clean", sum(1 for r in results if r.get("verdict") in ("low_risk","unknown")))
            st.dataframe(df, use_container_width=True, hide_index=True,
                        column_config={"Score": st.column_config.ProgressColumn("Score", min_value=0, max_value=100, format="%.0f")})
            st.download_button("Export CSV", df.to_csv(index=False), file_name="triageone_bulk.csv", mime="text/csv")
