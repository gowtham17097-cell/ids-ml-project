"""KPI cards, threat bar, FP rate — all metric components."""

import streamlit as st


def render_kpis(df, uptime):
    total   = len(df)
    attacks = len(df[df["prediction"] == "attack"]) if not df.empty else 0
    normals = len(df[df["prediction"] == "normal"]) if not df.empty else 0
    avg_conf = round(df["confidence"].astype(float).mean() * 100, 1) if total > 0 else 0
    unacked  = len(df[(df["prediction"] == "attack") & (df["acked"] == False)]) if ("acked" in df.columns and not df.empty) else attacks

    c1, c2, c3, c4, c5 = st.columns(5)
    cards = [
        (c1, total,          "Total Flows",    "kpi-blue",   "📡", "this session"),
        (c2, attacks,        "Threats",         "kpi-red",    "⚡", f"{unacked} unacknowledged"),
        (c3, normals,        "Clean Traffic",   "kpi-green",  "✓",  "verified safe"),
        (c4, f"{avg_conf}%", "Avg Confidence",  "kpi-amber",  "◎", "model certainty"),
        (c5, uptime,         "Uptime",          "kpi-cyan",   "⏱", "hh:mm:ss"),
    ]
    for col, val, label, cls, icon, note in cards:
        with col:
            st.markdown(f"""
            <div class="kpi-card">
                <div style="font-size:1rem;opacity:0.45;margin-bottom:3px">{icon}</div>
                <div class="kpi-value {cls}">{val}</div>
                <div class="kpi-label">{label}</div>
                <div class="kpi-note">{note}</div>
            </div>""", unsafe_allow_html=True)


def render_threat_bar(df):
    total   = len(df)
    attacks = len(df[df["prediction"] == "attack"]) if not df.empty else 0
    pct     = (attacks / total * 100) if total > 0 else 0
    label   = "HIGH THREAT" if pct > 35 else "ELEVATED" if pct > 15 else "NOMINAL"
    color   = "#ff4444"  if pct > 35 else "#ffaa22" if pct > 15 else "#22ee66"
    shadow  = "#ff444488" if pct > 35 else "#ffaa2288" if pct > 15 else "#22ee6688"
    cls     = "threat-high" if pct > 35 else "threat-mid" if pct > 15 else "threat-low"

    st.markdown(f"""
    <div class="threat-wrap">
        <div style="display:flex;justify-content:space-between;margin-bottom:4px">
            <span style="font-size:0.59rem;color:#2a5080;text-transform:uppercase;letter-spacing:0.1em">Threat Level</span>
            <span style="font-size:0.59rem;color:{color};font-weight:700;font-family:monospace;text-shadow:0 0 10px {shadow}">{label} · {pct:.1f}%</span>
        </div>
        <div class="threat-track">
            <div class="{cls}" style="width:{pct}%"></div>
        </div>
    </div>""", unsafe_allow_html=True)


def render_fp_card(df):
    attacks = df[df["prediction"] == "attack"] if not df.empty else df
    acked   = len(attacks[attacks["acked"] == True]) if ("acked" in df.columns and not attacks.empty) else 0
    total_a = len(attacks)
    fp      = round(acked / total_a * 100) if total_a > 0 else 0

    st.markdown(f"""
    <div class="kpi-card" style="height:100%;display:flex;flex-direction:column;align-items:center;justify-content:center;padding:16px 20px">
        <div class="kpi-value kpi-amber">{fp}%</div>
        <div class="kpi-label">FP Estimate</div>
        <div class="kpi-note">acked / total attacks</div>
    </div>""", unsafe_allow_html=True)
