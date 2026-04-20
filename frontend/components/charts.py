"""TriageOne — Plotly chart helpers."""
from __future__ import annotations
import plotly.graph_objects as go

VERDICT_COLORS = {"malicious":"#dc2626","suspicious":"#d97706","low_risk":"#059669","unknown":"#6b7280"}
DARK_LAYOUT = dict(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                   font=dict(color="#e2e8f0", family="Inter, sans-serif"),
                   margin=dict(l=40,r=20,t=40,b=40),
                   xaxis=dict(gridcolor="rgba(255,255,255,0.06)"),
                   yaxis=dict(gridcolor="rgba(255,255,255,0.06)"))

def _apply(fig, h=400):
    fig.update_layout(**DARK_LAYOUT, height=h); return fig

def risk_score_gauge(score, verdict):
    color = VERDICT_COLORS.get(verdict, "#6b7280")
    fig = go.Figure(go.Indicator(mode="gauge+number", value=score,
        number=dict(font=dict(size=48, color=color)),
        gauge=dict(axis=dict(range=[0,100]), bar=dict(color=color), bgcolor="rgba(255,255,255,0.03)", borderwidth=0,
                   steps=[dict(range=[0,15],color="rgba(5,150,105,0.15)"),dict(range=[15,40],color="rgba(5,150,105,0.08)"),
                          dict(range=[40,70],color="rgba(217,119,6,0.12)"),dict(range=[70,100],color="rgba(220,38,38,0.15)")],
                   threshold=dict(line=dict(color=color,width=3),thickness=0.8,value=score))))
    fig.update_layout(height=250, margin=dict(l=30,r=30,t=30,b=10))
    return _apply(fig, 250)

def severity_donut(counts):
    colors_map = {"critical":"#dc2626","high":"#d97706","medium":"#2563eb","low":"#059669"}
    labels, values = list(counts.keys()), list(counts.values())
    fig = go.Figure(go.Pie(labels=[l.capitalize() for l in labels], values=values, hole=0.55,
                           marker=dict(colors=[colors_map.get(l,"#6b7280") for l in labels], line=dict(width=0)),
                           textinfo="label+value", textfont=dict(size=12)))
    fig.update_layout(title="Severity distribution"); return _apply(fig, 350)

def sector_bar_chart(sector_data):
    sectors = sorted(sector_data.keys(), key=lambda s: sector_data[s].get("total",0), reverse=True)
    fig = go.Figure()
    fig.add_trace(go.Bar(x=[s.capitalize() for s in sectors], y=[sector_data[s].get("total",0) for s in sectors], name="Total", marker_color="#2563eb"))
    fig.add_trace(go.Bar(x=[s.capitalize() for s in sectors], y=[sector_data[s].get("critical",0) for s in sectors], name="Critical", marker_color="#dc2626"))
    fig.update_layout(title="Advisories by sector", barmode="overlay", xaxis_tickangle=-45); return _apply(fig)

def country_choropleth(country_counts):
    code_map = {"US":"USA","UK":"GBR","DE":"DEU","FR":"FRA","CN":"CHN","RU":"RUS","IN":"IND","AU":"AUS","JP":"JPN","KR":"KOR","IL":"ISR","EU":"FRA"}
    iso3 = {code_map.get(c,c): v for c,v in country_counts.items() if c != "GLOBAL"}
    if not iso3:
        fig = go.Figure(); fig.add_annotation(text="No geographic data", showarrow=False); return _apply(fig)
    fig = go.Figure(go.Choropleth(locations=list(iso3.keys()), z=list(iso3.values()),
                                  colorscale=[[0,"#1e3a5f"],[0.5,"#d97706"],[1,"#dc2626"]], showscale=True,
                                  colorbar=dict(title="Count",thickness=12,len=0.6), marker_line_width=0.5))
    fig.update_geos(showcountries=True, countrycolor="rgba(255,255,255,0.1)", showcoastlines=False, showframe=False,
                    bgcolor="rgba(0,0,0,0)", landcolor="#0f1923", oceancolor="#080e14", projection_type="natural earth")
    fig.update_layout(title="Geographic risk heatmap"); return _apply(fig, 450)

def source_pie(source_counts):
    fig = go.Figure(go.Pie(labels=list(source_counts.keys()), values=list(source_counts.values()), hole=0.4,
                           textinfo="label+percent", textfont=dict(size=11), marker=dict(line=dict(width=0))))
    fig.update_layout(title="By source"); return _apply(fig, 320)

def timeline_chart(advisories):
    from collections import Counter
    from datetime import datetime
    dates = []
    for a in advisories:
        ts = a.get("published_at")
        if ts:
            try: dates.append(datetime.fromtimestamp(ts).strftime("%Y-%m-%d"))
            except: pass
    if not dates:
        fig = go.Figure(); fig.add_annotation(text="No timeline data", showarrow=False); return _apply(fig, 300)
    counts = Counter(dates)
    sd = sorted(counts.keys())
    fig = go.Figure(go.Scatter(x=sd, y=[counts[d] for d in sd], mode="lines+markers",
                               line=dict(color="#2563eb",width=2), fill="tozeroy", fillcolor="rgba(37,99,235,0.1)"))
    fig.update_layout(title="Advisory volume over time"); return _apply(fig, 300)
