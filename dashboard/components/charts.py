"""All chart and panel components for the IDS dashboard."""

import streamlit as st
import pandas as pd
import plotly.graph_objects as go

# ── Plotly dark theme base ────────────────────────────────
BG    = "#060d1c"
GRID  = "#0d2040"
MUTED = "#2a5080"

def _fig(h=165):
    fig = go.Figure()
    fig.update_layout(
        height=h,
        margin=dict(l=0, r=0, t=4, b=0),
        paper_bgcolor=BG, plot_bgcolor=BG,
        font=dict(color=MUTED, size=9, family="monospace"),
        legend=dict(font=dict(size=8, color=MUTED), bgcolor="rgba(0,0,0,0)"),
        xaxis=dict(gridcolor=GRID, linecolor=GRID, tickfont=dict(size=8, color=MUTED)),
        yaxis=dict(gridcolor=GRID, linecolor=GRID, tickfont=dict(size=8, color=MUTED)),
    )
    return fig

CFG = {"displayModeBar": False}


# ── Traffic Timeline ──────────────────────────────────────
def render_timeline(df):
    st.markdown('<div class="sec-label">Traffic Timeline · Conn/min</div>', unsafe_allow_html=True)
    if df.empty:
        st.info("No data yet — run the IDS capture first.")
        return

    df2 = df.copy()
    df2["timestamp"] = pd.to_datetime(df2["timestamp"], errors="coerce")
    df2 = df2.dropna(subset=["timestamp"])
    df2["minute"] = df2["timestamp"].dt.floor("min")

    tl = df2.groupby(["minute", "prediction"]).size().unstack(fill_value=0).reset_index()
    if "attack" not in tl.columns: tl["attack"] = 0
    if "normal" not in tl.columns: tl["normal"] = 0

    fig = _fig(165)
    fig.add_trace(go.Scatter(
        x=tl["minute"], y=tl["normal"], name="Normal",
        line=dict(color="#22ee66", width=1.5), mode="lines",
        fill="tozeroy", fillcolor="rgba(34,238,102,0.08)",
    ))
    fig.add_trace(go.Scatter(
        x=tl["minute"], y=tl["attack"], name="Attack",
        line=dict(color="#ff4444", width=1.5), mode="lines",
        fill="tozeroy", fillcolor="rgba(255,68,68,0.12)",
    ))
    st.plotly_chart(fig, use_container_width=True, config=CFG)


# ── Connection Rate ───────────────────────────────────────
def render_conn_rate(df):
    st.markdown('<div class="sec-label">Connection Rate · /min</div>', unsafe_allow_html=True)
    if df.empty:
        st.info("No data yet.")
        return

    df2 = df.copy()
    df2["timestamp"] = pd.to_datetime(df2["timestamp"], errors="coerce")
    df2 = df2.dropna(subset=["timestamp"])
    df2["minute"] = df2["timestamp"].dt.floor("min")
    rate = df2.groupby("minute").size().reset_index(name="count")

    fig = _fig(165)
    fig.add_trace(go.Scatter(
        x=rate["minute"], y=rate["count"], name="Rate",
        line=dict(color="#ffaa22", width=1.5), mode="lines",
        fill="tozeroy", fillcolor="rgba(255,170,34,0.1)",
    ))
    st.plotly_chart(fig, use_container_width=True, config=CFG)


# ── Top IPs ───────────────────────────────────────────────
def render_top_ips(df):
    st.markdown('<div class="sec-label">Top Attacking IPs</div>', unsafe_allow_html=True)
    attacks = df[df["prediction"] == "attack"] if not df.empty else df
    if attacks.empty:
        st.info("No attacks detected yet.")
        return

    top = attacks["src_ip"].value_counts().head(6).reset_index()
    top.columns = ["ip", "hits"]
    max_hits = top["hits"].max()

    for _, row in top.iterrows():
        local = any(row["ip"].startswith(p) for p in ("127.", "10.", "192.168."))
        flag  = "🖥" if local else "🌐"
        bar_w = int((row["hits"] / max_hits) * 100)
        st.markdown(f"""
        <div class="ip-row">
            <span style="font-size:0.9rem">{flag}</span>
            <div style="flex:1">
                <div style="font-size:0.65rem;color:#a0c8e8;font-family:monospace">{row['ip']}</div>
                <div class="mini-track"><div class="mini-fill-red" style="width:{bar_w}%"></div></div>
            </div>
            <span style="font-size:0.62rem;color:#ff4444;font-family:monospace;font-weight:700;text-shadow:0 0 8px #ff4444">{row['hits']}</span>
        </div>""", unsafe_allow_html=True)


# ── Top Ports ─────────────────────────────────────────────
def render_top_ports(df):
    st.markdown('<div class="sec-label">Targeted Services</div>', unsafe_allow_html=True)
    attacks = df[df["prediction"] == "attack"] if not df.empty else df
    if attacks.empty:
        st.info("No attacks detected yet.")
        return

    top = attacks["service"].value_counts().head(6).reset_index()
    top.columns = ["service", "hits"]
    max_hits = top["hits"].max()

    for _, row in top.iterrows():
        bar_w = int((row["hits"] / max_hits) * 100)
        st.markdown(f"""
        <div class="port-row">
            <div style="display:flex;justify-content:space-between;margin-bottom:3px">
                <span style="font-size:0.65rem;color:#a0c8e8;font-family:monospace">{row['service']}</span>
                <span style="font-size:0.62rem;color:#ff4444;font-family:monospace;font-weight:700">{row['hits']} hits</span>
            </div>
            <div class="mini-track"><div class="mini-fill-red" style="width:{bar_w}%"></div></div>
        </div>""", unsafe_allow_html=True)


# ── Attack Types ──────────────────────────────────────────
def render_attack_types(df):
    st.markdown('<div class="sec-label">Attack Classification</div>', unsafe_allow_html=True)
    attacks = df[df["prediction"] == "attack"] if not df.empty else df
    if attacks.empty or "attack_class" not in df.columns:
        st.info("No classified attacks yet.")
        return

    top = attacks["attack_class"].value_counts().reset_index()
    top.columns = ["type", "count"]
    max_c = top["count"].max()

    COLORS = {"portsweep": ("#ff4444", "mini-fill-red"),
              "probe":     ("#ffaa22", "mini-fill-amber"),
              "r2l":       ("#aa55ff", "mini-fill-purple"),
              "dos":       ("#ff4444", "mini-fill-red")}

    for _, row in top.iterrows():
        color, cls = COLORS.get(row["type"], ("#4488ff", "mini-fill-red"))
        bar_w = int((row["count"] / max_c) * 100)
        st.markdown(f"""
        <div class="atk-row">
            <div style="display:flex;justify-content:space-between;margin-bottom:3px">
                <span style="font-size:0.65rem;color:{color};font-weight:700;text-transform:uppercase;text-shadow:0 0 8px {color}">{row['type']}</span>
                <span style="font-size:0.62rem;color:#2a5080;font-family:monospace">{row['count']}</span>
            </div>
            <div class="mini-track"><div class="{cls}" style="width:{bar_w}%"></div></div>
        </div>""", unsafe_allow_html=True)

    st.markdown("""
    <div style="margin-top:10px;background:#091220;border:1px solid #1a3a6e;border-radius:6px;padding:8px 10px">
        <div style="font-size:0.56rem;color:#2a5080;margin-bottom:5px;text-transform:uppercase;letter-spacing:0.1em">Legend</div>
        <div style="font-size:0.58rem;color:#2a5080;margin-bottom:3px"><span style="color:#ffaa22">portsweep</span> · Many ports, one host</div>
        <div style="font-size:0.58rem;color:#2a5080;margin-bottom:3px"><span style="color:#ffaa22">probe</span> · Scan / fingerprinting</div>
        <div style="font-size:0.58rem;color:#2a5080"><span style="color:#ffaa22">r2l</span> · Remote-to-local exploit</div>
    </div>""", unsafe_allow_html=True)


# ── Alert Feed ────────────────────────────────────────────
def render_alert_feed(df):
    st.markdown('<div class="sec-label">Live Alert Feed</div>', unsafe_allow_html=True)
    if df.empty:
        st.info("No connections logged yet.")
        return

    recent = df.tail(40).iloc[::-1]

    for _, row in recent.iterrows():
        is_atk = row["prediction"] == "attack"
        acked  = bool(row.get("acked", False))
        conf   = int(float(row["confidence"]) * 100)
        ts     = str(row["timestamp"])[11:19]
        proto  = str(row["protocol"]).upper()

        # severity
        if "severity" in df.columns:
            sev = str(row.get("severity", "info"))
        else:
            sev = "critical" if is_atk and conf > 60 else "high" if is_atk else "info"

        badge_map = {"critical":"badge-crit","high":"badge-high","medium":"badge-med","info":"badge-info"}
        badge = badge_map.get(sev, "badge-info")

        atk_class = f'<span style="color:#ffaa22;font-size:0.58rem;font-style:italic">&nbsp;{row["attack_class"]}</span>' if "attack_class" in df.columns and pd.notna(row.get("attack_class")) else ""
        label     = f'<b style="color:#ff4444;text-shadow:0 0 8px #ff4444">⚡ ATK</b>' if is_atk else '<span style="color:#22ee66;text-shadow:0 0 8px #22ee66">✓ OK</span>'
        div_cls   = "alert-atk" + (" alert-acked" if acked else "")

        st.markdown(f"""
        <div class="{div_cls}">
            <span class="{badge}">{sev[:4].upper()}</span>&nbsp;
            <span style="color:#2a5080;font-size:0.6rem">{ts}</span>&nbsp;
            <span style="background:#0d2040;color:#4488ff;padding:0 4px;border-radius:2px;font-size:0.58rem;font-weight:700;border:1px solid #1a3a6e44">{proto}</span>&nbsp;
            <span style="color:#2a5080;font-size:0.6rem">{row['src_ip']}</span>
            <span style="color:#2a5080;font-size:0.56rem"> ▶ </span>
            <span style="font-size:0.6rem">{row['dst_ip']}</span>&nbsp;
            <span style="color:#2a5080;font-size:0.58rem">[{row['service']}]</span>
            {atk_class}
            <span style="float:right;font-weight:700;font-size:0.62rem">{label} {conf}%</span>
            {"&nbsp;<span style='font-size:0.54rem;color:#2a5080'>✓ reviewed</span>" if acked else ""}
        </div>""", unsafe_allow_html=True)
