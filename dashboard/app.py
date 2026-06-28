"""
IDS Dashboard — Streamlit wrapper around a full HTML/JS dashboard.
Run: streamlit run dashboard/app.py
"""

import streamlit as st
import streamlit.components.v1 as components
import pandas as pd
import os
import time
import json

st.set_page_config(
    page_title="IDS · Threat Monitor",
    page_icon="⬡",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ── Hide all Streamlit chrome ─────────────────────────────
st.markdown("""
<style>
#MainMenu, footer, header, [data-testid="stToolbar"],
[data-testid="stDecoration"], [data-testid="stSidebar"] { display: none !important; }
.block-container { padding: 0 !important; margin: 0 !important; max-width: 100% !important; }
body, [data-testid="stAppViewContainer"] { background: #010306 !important; }
</style>""", unsafe_allow_html=True)

# ── Paths ─────────────────────────────────────────────────
_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
_LOG  = os.path.join(_ROOT, "logs", "alerts.csv")
_ACK  = os.path.join(_ROOT, "logs", "acked.txt")

# ── Load data from CSV ────────────────────────────────────
def load_data():
    if not os.path.exists(_LOG):
        return []
    df = pd.read_csv(_LOG)
    acked_ids = set()
    if os.path.exists(_ACK):
        with open(_ACK) as f:
            acked_ids = set(f.read().splitlines())
    df["acked"] = df.index.astype(str).isin(acked_ids)
    df["confidence"] = df["confidence"].astype(float)
    records = df.tail(200).to_dict(orient="records")
    for i, r in enumerate(records):
        r["id"]  = i
        r["ack"] = bool(r.get("acked", False))
        r["time"] = str(r.get("timestamp",""))[-8:][:8]
        r["src"]  = str(r.get("src_ip",""))
        r["dst"]  = str(r.get("dst_ip",""))
        r["proto"]= str(r.get("protocol","tcp"))
        r["conf"] = float(r.get("confidence", 0))
        r["type"] = str(r.get("prediction","normal"))
        sev = str(r.get("severity",""))
        if not sev or sev == "nan":
            r["severity"] = "critical" if r["type"]=="attack" and r["conf"]>0.6 else "high" if r["type"]=="attack" else "info"
        r["atk"] = str(r.get("attack_class","")) if "attack_class" in r and str(r.get("attack_class","")) != "nan" else ""
    return records

alerts_data = load_data()
alerts_json = json.dumps(alerts_data)

# ── The full dashboard as one HTML file ───────────────────
HTML = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<script src="https://cdnjs.cloudflare.com/ajax/libs/recharts/2.8.0/Recharts.min.js"></script>
<style>
  * {{ margin:0; padding:0; box-sizing:border-box; cursor:none !important; }}
  body {{ background:#010306; color:#7ab0d8; font-family:'Inter',system-ui,sans-serif; font-size:13px; overflow-x:hidden; }}

  ::-webkit-scrollbar {{ width:3px; }}
  ::-webkit-scrollbar-track {{ background:#010306; }}
  ::-webkit-scrollbar-thumb {{ background:#1a3a6e; border-radius:2px; }}

  #cursor-ring {{ position:fixed; width:32px; height:32px; border-radius:50%; border:1px solid #00ddff88; pointer-events:none; z-index:9999; transform:translate(-50%,-50%); transition:left 0.04s,top 0.04s; box-shadow:0 0 16px #00ddff40; }}
  #cursor-dot  {{ position:fixed; width:4px; height:4px; border-radius:50%; background:#00ddff; pointer-events:none; z-index:9999; transform:translate(-50%,-50%); box-shadow:0 0 8px #00ddff; transition:left 0.02s,top 0.02s; }}
  #cursor-h    {{ position:fixed; height:1px; width:24px; pointer-events:none; z-index:9999; transform:translate(-50%,-50%); background:linear-gradient(90deg,transparent,#00ddff88,transparent); }}
  #cursor-v    {{ position:fixed; width:1px; height:24px; pointer-events:none; z-index:9999; transform:translate(-50%,-50%); background:linear-gradient(180deg,transparent,#00ddff88,transparent); }}
  .trail       {{ position:fixed; width:5px; height:5px; border-radius:50%; background:#00ddff; pointer-events:none; z-index:9998; transform:translate(-50%,-50%); }}

  .layout {{ display:flex; height:100vh; }}
  .sidebar {{ width:200px; background:#040a14; border-right:1px solid #0d2040; padding:18px 12px; display:flex; flex-direction:column; flex-shrink:0; overflow-y:auto; }}
  .main    {{ flex:1; display:flex; flex-direction:column; overflow:hidden; }}
  .topbar  {{ background:#040a14; border-bottom:1px solid #0d2040; padding:10px 20px; display:flex; align-items:center; justify-content:space-between; flex-shrink:0; }}
  .content {{ flex:1; overflow-y:auto; padding:16px 20px; }}

  .logo     {{ font-family:monospace; font-size:0.9rem; font-weight:800; color:#00ddff; text-shadow:0 0 16px #00ddff; letter-spacing:0.04em; }}
  .logo-sub {{ font-size:0.56rem; color:#2a5080; letter-spacing:0.12em; margin-top:1px; }}

  .status-card {{ background:#060d1c; border:1px solid #0d2040; border-radius:8px; padding:10px; margin-bottom:14px; }}
  .status-row  {{ display:flex; align-items:center; margin-bottom:5px; font-size:0.7rem; color:#a0c8e8; }}
  .dot {{ display:inline-block; width:6px; height:6px; border-radius:50%; margin-right:6px; flex-shrink:0; }}
  .dot-green  {{ background:#22ee66; box-shadow:0 0 8px #22ee66,0 0 16px #22ee6644; }}
  .dot-cyan   {{ background:#00ddff; box-shadow:0 0 8px #00ddff,0 0 16px #00ddff44; }}
  .dot-red    {{ background:#ff4444; box-shadow:0 0 8px #ff4444,0 0 16px #ff444444; animation:pulse-red 1s infinite; }}
  .dot-muted  {{ background:#2a5080; }}
  @keyframes pulse-red {{ 0%,100%{{box-shadow:0 0 8px #ff4444}} 50%{{box-shadow:0 0 16px #ff4444,0 0 30px #ff444488}} }}

  .sec-label {{ font-size:0.56rem; color:#2a5080; text-transform:uppercase; letter-spacing:0.14em; margin-bottom:10px; display:flex; align-items:center; gap:7px; }}
  .sec-bar   {{ width:2px; height:12px; border-radius:1px; box-shadow:0 0 6px currentColor; }}

  .ctrl-section {{ margin-bottom:14px; }}
  .ctrl-title   {{ font-size:0.56rem; color:#2a5080; text-transform:uppercase; letter-spacing:0.12em; margin-bottom:8px; }}
  .toggle-row   {{ display:flex; justify-content:space-between; align-items:center; margin-bottom:8px; cursor:pointer; padding:2px 0; }}
  .toggle-label {{ font-size:0.72rem; color:#a0c8e8; transition:color 0.2s; }}
  .toggle-track {{ width:28px; height:15px; border-radius:8px; position:relative; transition:background 0.25s; cursor:pointer; flex-shrink:0; }}
  .toggle-thumb {{ width:11px; height:11px; border-radius:50%; background:#fff; position:absolute; top:2px; transition:all 0.22s; }}

  .sev-row {{ display:flex; align-items:center; gap:6px; margin-bottom:6px; cursor:pointer; }}
  .sev-dot {{ width:5px; height:5px; border-radius:50%; transition:all 0.2s; flex-shrink:0; }}

  .tip-row {{ display:flex; justify-content:space-between; padding:3px 0; border-bottom:1px solid #0d2040; }}
  .tip-k   {{ font-size:0.62rem; color:#2a5080; }}
  .tip-v   {{ font-size:0.62rem; color:#00ddff; font-family:monospace; font-weight:600; }}

  .kpi-grid {{ display:flex; gap:10px; margin-bottom:14px; }}
  .kpi-card {{ background:#060d1c; border:1px solid #0d2040; border-radius:10px; padding:14px 10px; text-align:center; flex:1; transition:all 0.25s; position:relative; overflow:hidden; }}
  .kpi-card:hover {{ background:#091220; }}
  .kpi-card::before {{ content:''; position:absolute; top:0;left:0;right:0; height:1px; background:linear-gradient(90deg,transparent,var(--ac,#00ddff)88,transparent); opacity:0; transition:opacity 0.3s; }}
  .kpi-card:hover::before {{ opacity:1; }}
  .kpi-icon {{ font-size:1rem; opacity:0.45; margin-bottom:3px; }}
  .kpi-val  {{ font-size:1.7rem; font-weight:800; font-family:monospace; line-height:1; letter-spacing:-0.02em; }}
  .kpi-lbl  {{ font-size:0.58rem; color:#2a5080; text-transform:uppercase; letter-spacing:0.12em; margin-top:5px; }}
  .kpi-note {{ font-size:0.56rem; color:#2a5080; margin-top:2px; opacity:0.7; }}
  .c-red    {{ color:#ff4444; text-shadow:0 0 16px #ff444488; }}
  .c-green  {{ color:#22ee66; text-shadow:0 0 16px #22ee6688; }}
  .c-blue   {{ color:#4488ff; text-shadow:0 0 16px #4488ff88; }}
  .c-amber  {{ color:#ffaa22; text-shadow:0 0 16px #ffaa2288; }}
  .c-cyan   {{ color:#00ddff; text-shadow:0 0 16px #00ddff88; }}
  .c-purple {{ color:#aa55ff; text-shadow:0 0 16px #aa55ff88; }}

  .threat-wrap  {{ background:#060d1c; border:1px solid #0d2040; border-radius:10px; padding:12px 16px; flex:1; }}
  .threat-track {{ background:#0a1828; border-radius:3px; height:5px; margin:6px 0 3px; overflow:hidden; }}
  .threat-fill  {{ height:100%; border-radius:3px; transition:width 0.7s ease; }}

  .fp-card {{ background:#060d1c; border:1px solid #0d2040; border-radius:10px; padding:14px 18px; display:flex; flex-direction:column; align-items:center; justify-content:center; min-width:110px; }}

  .charts-row {{ display:grid; grid-template-columns:2fr 1fr; gap:10px; margin-bottom:14px; }}
  .card {{ background:#060d1c; border:1px solid #0d2040; border-radius:10px; padding:16px; transition:border-color 0.25s,box-shadow 0.25s; }}
  .card:hover {{ border-color:#1a3a6e; box-shadow:0 0 20px #00ddff14; }}

  canvas {{ max-width:100%; }}

  .bottom-row {{ display:grid; grid-template-columns:1fr 2fr; gap:10px; }}

  .tab-bar {{ display:flex; border-bottom:1px solid #0d2040; }}
  .tab     {{ flex:1; padding:7px 2px; text-align:center; font-size:0.56rem; font-weight:700; text-transform:uppercase; letter-spacing:0.08em; cursor:pointer; color:#2a5080; border-bottom:1px solid transparent; background:transparent; transition:all 0.2s; }}
  .tab.active {{ color:#00ddff; text-shadow:0 0 8px #00ddff; border-bottom:1px solid #00ddff; background:#091220; }}
  .tab-content {{ padding:12px; max-height:240px; overflow-y:auto; }}

  .ip-row   {{ display:flex; align-items:center; gap:7px; padding:5px 0; border-bottom:1px solid #0d2040; }}
  .port-row {{ padding:5px 0; border-bottom:1px solid #0d2040; }}
  .atk-row  {{ padding:5px 0; border-bottom:1px solid #0d2040; }}
  .mini-track {{ background:#0a1828; border-radius:2px; height:3px; margin-top:3px; }}
  .mini-fill  {{ height:100%; border-radius:2px; }}

  .feed-header {{ padding:10px 12px; border-bottom:1px solid #0d2040; display:flex; justify-content:space-between; align-items:center; }}
  .feed-body   {{ padding:8px 10px; max-height:260px; overflow-y:auto; }}

  .alert-row {{ border-radius:0 5px 5px 0; padding:5px 8px; margin-bottom:2px; font-family:monospace; font-size:0.67rem; display:flex; align-items:center; gap:5px; transition:background 0.15s; }}
  .alert-atk {{ background:#1c060622; border-left:2px solid #ff444466; }}
  .alert-atk:hover {{ background:#1c060644; }}
  .alert-ok  {{ border-left:2px solid #22ee6633; opacity:0.5; }}
  .alert-acked {{ opacity:0.3 !important; }}

  .badge {{ font-size:0.56rem; font-weight:800; padding:1px 5px; border-radius:3px; font-family:monospace; border:1px solid; }}
  .badge-crit {{ background:#200808; border-color:#6b1818; color:#ff4444; text-shadow:0 0 8px #ff4444; }}
  .badge-high {{ background:#1c0e04; border-color:#7a3008; color:#ff8822; text-shadow:0 0 8px #ff8822; }}
  .badge-med  {{ background:#141200; border-color:#6b5c00; color:#ddcc00; text-shadow:0 0 8px #ddcc00; }}
  .badge-info {{ background:#04101e; border-color:#1a3a6e; color:#4488ff; text-shadow:0 0 8px #4488ff; }}

  .proto-tag {{ padding:0 4px; border-radius:2px; font-size:0.58rem; font-weight:700; border:1px solid; }}
  .proto-tcp {{ background:#0d2040; color:#4488ff; border-color:#1a3a6e44; }}
  .proto-udp {{ background:#1a0e40; color:#aa55ff; border-color:#4a18b044; }}
  .proto-icmp{{ background:#0e1400; color:#aacc00; border-color:#5a6c0044; }}

  .ack-btn {{ background:#0a1828; border:1px solid #1a3a6e; color:#2a5080; font-size:0.55rem; padding:1px 6px; border-radius:3px; cursor:pointer; font-family:monospace; transition:all 0.2s; }}
  .ack-btn:hover {{ border-color:#ff4444; color:#ff4444; box-shadow:0 0 8px #ff444440; }}

  .unacked-badge {{ background:#1c060688; border:1px solid #ff444466; border-radius:5px; padding:3px 10px; font-size:0.62rem; font-family:monospace; font-weight:700; color:#ff4444; text-shadow:0 0 10px #ff4444; box-shadow:0 0 12px #ff444440; }}
  .nominal-badge {{ background:#040a14; border:1px solid #1a3a6e; border-radius:5px; padding:3px 10px; font-size:0.62rem; font-family:monospace; font-weight:700; color:#2a5080; }}

  .footer {{ margin-top:12px; display:flex; justify-content:space-between; font-size:0.53rem; color:#0d2040; font-family:monospace; }}

  @keyframes typing-blink {{ 0%,100%{{opacity:1}} 50%{{opacity:0}} }}
  .blink {{ animation:typing-blink 0.7s step-end infinite; }}

  .chart-container {{ width:100%; height:155px; position:relative; }}
  svg text {{ font-family:monospace !important; }}
</style>
</head>
<body>

<!-- Cursor -->
<div id="cursor-ring"></div>
<div id="cursor-dot"></div>
<div id="cursor-h"></div>
<div id="cursor-v"></div>

<div class="layout">

  <!-- Sidebar -->
  <div class="sidebar">
    <div style="margin-bottom:20px">
      <div class="logo">⬡ IDS·ML</div>
      <div class="logo-sub">THREAT MONITOR</div>
    </div>

    <div class="status-card">
      <div class="ctrl-title">System Status</div>
      <div class="status-row"><span class="dot dot-green"></span>IDS ACTIVE</div>
      <div class="status-row"><span class="dot dot-cyan" id="live-dot"></span><span id="live-label">LIVE</span></div>
      <div class="status-row"><span class="dot dot-red" id="unacked-dot"></span><span id="unacked-label" style="color:#ff4444;text-shadow:0 0 8px #ff4444">0 UNACKED</span></div>
      <div style="font-family:monospace;font-size:0.6rem;color:#00ddff;text-shadow:0 0 8px #00ddff;margin-top:8px" id="uptime-display">UP 01:09:44</div>
    </div>

    <div class="ctrl-section">
      <div class="ctrl-title">Controls</div>
      <div class="toggle-row" onclick="toggleAutoRefresh()">
        <span class="toggle-label">Auto Refresh</span>
        <div class="toggle-track" id="ar-track" style="background:#1a40a0">
          <div class="toggle-thumb" id="ar-thumb" style="left:15px;background:#4488ff;box-shadow:0 0 6px #4488ff"></div>
        </div>
      </div>
      <div class="toggle-row" onclick="toggleNormal()">
        <span class="toggle-label">Show Normal</span>
        <div class="toggle-track" id="sn-track" style="background:#1a40a0">
          <div class="toggle-thumb" id="sn-thumb" style="left:15px;background:#4488ff;box-shadow:0 0 6px #4488ff"></div>
        </div>
      </div>
    </div>

    <div class="ctrl-section">
      <div class="ctrl-title">Severity</div>
      <div id="sev-filters"></div>
    </div>

    <div style="margin-top:auto">
      <div class="ctrl-title">Model</div>
      <div class="tip-row"><span class="tip-k">Algorithm</span><span class="tip-v">Random Forest</span></div>
      <div class="tip-row"><span class="tip-k">Trees</span><span class="tip-v">100</span></div>
      <div class="tip-row"><span class="tip-k">Features</span><span class="tip-v">122</span></div>
      <div class="tip-row"><span class="tip-k">Dataset</span><span class="tip-v">NSL-KDD</span></div>
      <div class="tip-row"><span class="tip-k">Accuracy</span><span class="tip-v">99.9%</span></div>
      <div class="tip-row"><span class="tip-k">Train</span><span class="tip-v">2.01s</span></div>
    </div>
  </div>

  <!-- Main -->
  <div class="main">

    <!-- Topbar -->
    <div class="topbar">
      <div>
        <div style="font-family:monospace;font-size:0.82rem;font-weight:700;color:#00ddff;text-shadow:0 0 14px #00ddff">
          <span id="typed-header"></span><span class="blink">_</span>
        </div>
        <div style="font-size:0.57rem;color:#2a5080;margin-top:1px">9 interfaces · WiFi + Ethernet + Loopback · 10.28.219.26</div>
      </div>
      <div style="display:flex;gap:10px;align-items:center">
        <div style="font-size:0.58rem;color:#2a5080;font-family:monospace" id="clock"></div>
        <div id="status-badge" class="nominal-badge">● NOMINAL</div>
      </div>
    </div>

    <!-- Content -->
    <div class="content">

      <!-- KPIs -->
      <div class="kpi-grid" id="kpi-grid"></div>

      <!-- Threat + FP -->
      <div style="display:grid;grid-template-columns:1fr auto;gap:10px;margin-bottom:14px">
        <div class="threat-wrap">
          <div style="display:flex;justify-content:space-between;margin-bottom:4px">
            <span style="font-size:0.59rem;color:#2a5080;text-transform:uppercase;letter-spacing:0.1em">Threat Level</span>
            <span id="threat-label" style="font-size:0.59rem;font-weight:700;font-family:monospace"></span>
          </div>
          <div class="threat-track"><div class="threat-fill" id="threat-fill"></div></div>
        </div>
        <div class="fp-card">
          <div class="kpi-val c-amber" id="fp-val">0%</div>
          <div class="kpi-lbl">FP Estimate</div>
          <div class="kpi-note">acked / attacks</div>
        </div>
      </div>

      <!-- Charts -->
      <div class="charts-row">
        <div class="card">
          <div class="sec-label"><div class="sec-bar" style="background:#4488ff;color:#4488ff"></div>Traffic Timeline · Conn/min</div>
          <div class="chart-container"><canvas id="chart-timeline"></canvas></div>
        </div>
        <div class="card">
          <div class="sec-label"><div class="sec-bar" style="background:#ffaa22;color:#ffaa22"></div>Connection Rate · /min</div>
          <div class="chart-container"><canvas id="chart-rate"></canvas></div>
        </div>
      </div>

      <!-- Bottom row -->
      <div class="bottom-row">

        <!-- Left tabs -->
        <div class="card" style="padding:0;overflow:hidden">
          <div class="tab-bar">
            <div class="tab active" onclick="switchTab('feed',this)">Feed</div>
            <div class="tab" onclick="switchTab('ips',this)">Top IPs</div>
            <div class="tab" onclick="switchTab('ports',this)">Ports</div>
            <div class="tab" onclick="switchTab('types',this)">Types</div>
          </div>
          <div class="tab-content" id="tab-feed"></div>
          <div class="tab-content" id="tab-ips"   style="display:none"></div>
          <div class="tab-content" id="tab-ports" style="display:none"></div>
          <div class="tab-content" id="tab-types" style="display:none"></div>
        </div>

        <!-- Alert Feed -->
        <div class="card" style="padding:0;overflow:hidden">
          <div class="feed-header">
            <div class="sec-label" style="margin:0"><div class="sec-bar" style="background:#00ddff;color:#00ddff"></div>Live Alert Feed</div>
            <div style="display:flex;align-items:center;gap:5px">
              <span class="dot dot-green" id="feed-dot"></span>
              <span style="font-size:0.56rem;color:#2a5080" id="feed-status">LIVE</span>
            </div>
          </div>
          <div class="feed-body" id="alert-feed"></div>
        </div>
      </div>

      <div class="footer">
        <span>IDS-ML-PROJECT · NSL-KDD · Random Forest · 99.9% accuracy · Gowtham · 2026</span>
        <span id="footer-tick">tick#0 · auto-refresh 5s</span>
      </div>
    </div>
  </div>
</div>

<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
<script>
// ── Data from Python ──────────────────────────────────────
const RAW_ALERTS = {alerts_json};

// ── State ────────────────────────────────────────────────
let alerts      = RAW_ALERTS.length ? RAW_ALERTS : getMockAlerts();
let autoRefresh = true;
let showNormal  = true;
let sevFilter   = "all";
let tick        = 0;
let uptimeSecs  = 4211;
let activeTab   = "feed";

// ── Mock data fallback ────────────────────────────────────
function getMockAlerts() {{
  return [
    {{id:1,time:"10:06:01",src:"10.28.219.26",dst:"52.168.117.170",proto:"tcp",service:"http_443",type:"normal",severity:"info",conf:0.91,ack:false}},
    {{id:2,time:"10:06:03",src:"10.28.219.26",dst:"10.28.219.24",  proto:"udp",service:"domain",  type:"normal",severity:"info",conf:0.97,ack:false}},
    {{id:3,time:"10:06:05",src:"127.0.0.1",   dst:"127.0.0.1",    proto:"tcp",service:"klogin",  type:"attack",severity:"high",conf:0.62,ack:false,atk:"portsweep"}},
    {{id:4,time:"10:06:07",src:"10.28.219.26",dst:"40.79.141.153", proto:"tcp",service:"http_443",type:"normal",severity:"info",conf:0.94,ack:true}},
    {{id:5,time:"10:06:09",src:"127.0.0.1",   dst:"127.0.0.1",    proto:"tcp",service:"bgp",     type:"attack",severity:"critical",conf:0.53,ack:false,atk:"probe"}},
    {{id:6,time:"10:06:11",src:"10.28.219.26",dst:"10.28.219.24",  proto:"udp",service:"domain",  type:"normal",severity:"info",conf:0.95,ack:true}},
    {{id:7,time:"10:06:13",src:"127.0.0.1",   dst:"127.0.0.1",    proto:"tcp",service:"private", type:"attack",severity:"high",conf:0.56,ack:false,atk:"portsweep"}},
    {{id:8,time:"10:06:15",src:"10.28.219.26",dst:"20.42.73.31",   proto:"tcp",service:"http_443",type:"normal",severity:"info",conf:0.92,ack:false}},
    {{id:9,time:"10:06:17",src:"127.0.0.1",   dst:"127.0.0.1",    proto:"tcp",service:"pop_2",   type:"attack",severity:"medium",conf:0.52,ack:false,atk:"probe"}},
    {{id:10,time:"10:06:19",src:"10.28.219.26",dst:"10.28.219.24", proto:"udp",service:"domain",  type:"normal",severity:"info",conf:0.98,ack:true}},
    {{id:11,time:"10:06:21",src:"127.0.0.1",  dst:"127.0.0.1",    proto:"tcp",service:"irc",     type:"attack",severity:"medium",conf:0.50,ack:false,atk:"probe"}},
    {{id:12,time:"10:06:23",src:"10.28.219.26",dst:"140.82.112.21",proto:"tcp",service:"http_443",type:"normal",severity:"info",conf:0.88,ack:false}},
    {{id:13,time:"10:06:25",src:"127.0.0.1",  dst:"127.0.0.1",    proto:"tcp",service:"finger",  type:"attack",severity:"high",conf:0.52,ack:false,atk:"portsweep"}},
    {{id:14,time:"10:06:27",src:"10.28.219.26",dst:"10.28.219.24", proto:"udp",service:"domain",  type:"normal",severity:"info",conf:0.96,ack:true}},
    {{id:15,time:"10:06:29",src:"127.0.0.1",  dst:"127.0.0.1",    proto:"tcp",service:"kerberos",type:"attack",severity:"critical",conf:0.51,ack:false,atk:"probe"}},
    {{id:16,time:"10:06:31",src:"10.28.219.26",dst:"54.214.191.184",proto:"tcp",service:"http_443",type:"normal",severity:"info",conf:0.85,ack:false}},
    {{id:17,time:"10:06:33",src:"44.224.93.14",dst:"10.28.219.26", proto:"tcp",service:"private", type:"attack",severity:"critical",conf:0.62,ack:false,atk:"r2l"}},
    {{id:18,time:"10:06:35",src:"10.28.219.26",dst:"10.28.219.24", proto:"udp",service:"domain",  type:"normal",severity:"info",conf:0.94,ack:false}},
    {{id:19,time:"10:06:37",src:"127.0.0.1",  dst:"127.0.0.1",    proto:"tcp",service:"bgp",     type:"attack",severity:"high",conf:0.51,ack:false,atk:"portsweep"}},
    {{id:20,time:"10:06:39",src:"10.28.219.26",dst:"57.144.211.32",proto:"tcp",service:"private", type:"normal",severity:"info",conf:0.84,ack:true}},
  ];
}}

// ── Cursor ────────────────────────────────────────────────
const ring=document.getElementById("cursor-ring"),dot=document.getElementById("cursor-dot"),
      ch=document.getElementById("cursor-h"),cv=document.getElementById("cursor-v");
const trails=[]; const TRAIL_COUNT=12;
for(let i=0;i<TRAIL_COUNT;i++){{
  const t=document.createElement("div"); t.className="trail"; t.style.opacity=0;
  document.body.appendChild(t); trails.push(t);
}}
let mx=-300,my=-300,trailIdx=0;
document.addEventListener("mousemove",e=>{{
  mx=e.clientX; my=e.clientY;
  ring.style.left=mx+"px"; ring.style.top=my+"px";
  dot.style.left=mx+"px";  dot.style.top=my+"px";
  ch.style.left=mx+"px";   ch.style.top=my+"px";
  cv.style.left=mx+"px";   cv.style.top=my+"px";
  const t=trails[trailIdx%TRAIL_COUNT];
  t.style.left=mx+"px"; t.style.top=my+"px"; t.style.opacity=0.4;
  setTimeout(()=>{{t.style.opacity=0;}},300);
  trailIdx++;
}});

// ── Uptime ────────────────────────────────────────────────
setInterval(()=>{{
  uptimeSecs++;
  const h=Math.floor(uptimeSecs/3600), m=Math.floor((uptimeSecs%3600)/60), s=uptimeSecs%60;
  document.getElementById("uptime-display").textContent=
    "UP "+String(h).padStart(2,"0")+":"+String(m).padStart(2,"0")+":"+String(s).padStart(2,"0");
}},1000);

// ── Clock ────────────────────────────────────────────────
function updateClock(){{ document.getElementById("clock").textContent=new Date().toLocaleTimeString(); }}
updateClock(); setInterval(updateClock,1000);

// ── Typing header ─────────────────────────────────────────
const HEADER_TEXT="IDS · NEURAL THREAT MONITOR v2.1";
let headerIdx=0;
const headerEl=document.getElementById("typed-header");
const headerTimer=setInterval(()=>{{
  headerEl.textContent=HEADER_TEXT.slice(0,++headerIdx);
  if(headerIdx>=HEADER_TEXT.length) clearInterval(headerTimer);
}},40);

// ── Severity filter buttons ───────────────────────────────
const SEVS=[["all","#00ddff"],["critical","#ff4444"],["high","#ff8822"],["medium","#ddcc00"],["info","#4488ff"]];
const sevEl=document.getElementById("sev-filters");
SEVS.forEach(([s,c])=>{{
  const row=document.createElement("div"); row.className="sev-row";
  row.innerHTML=`<div class="sev-dot" id="sev-dot-${{s}}" style="background:${{s===sevFilter?c:"#2a5080"}};${{s===sevFilter?"box-shadow:0 0 8px "+c:""}};"></div><span style="font-size:0.7rem;color:${{s===sevFilter?c:"#2a5080"}};text-transform:capitalize;transition:color 0.2s" id="sev-lbl-${{s}}">${{s}}</span>`;
  row.onclick=()=>{{ sevFilter=s; renderAll(); updateSevUI(); }};
  sevEl.appendChild(row);
}});
function updateSevUI(){{
  SEVS.forEach(([s,c])=>{{
    const dot=document.getElementById("sev-dot-"+s),lbl=document.getElementById("sev-lbl-"+s);
    if(!dot||!lbl) return;
    const active=s===sevFilter;
    dot.style.background=active?c:"#2a5080";
    dot.style.boxShadow=active?"0 0 8px "+c:"none";
    lbl.style.color=active?c:"#2a5080";
  }});
}}

// ── Toggle handlers ───────────────────────────────────────
function setToggle(trackId,thumbId,on){{
  document.getElementById(trackId).style.background=on?"#1a40a0":"#0d2040";
  const th=document.getElementById(thumbId);
  th.style.left=on?"15px":"2px";
  th.style.background=on?"#4488ff":"#2a5080";
  th.style.boxShadow=on?"0 0 6px #4488ff":"none";
}}
function toggleAutoRefresh(){{ autoRefresh=!autoRefresh; setToggle("ar-track","ar-thumb",autoRefresh); renderAll(); }}
function toggleNormal(){{ showNormal=!showNormal; setToggle("sn-track","sn-thumb",showNormal); renderAll(); }}

// ── Filter ────────────────────────────────────────────────
function getFiltered(){{
  return alerts.filter(a=>
    (showNormal||a.type==="attack")&&
    (sevFilter==="all"||a.severity===sevFilter)
  );
}}

// ── Stats ─────────────────────────────────────────────────
function getStats(){{
  const f=getFiltered();
  const atk=f.filter(a=>a.type==="attack");
  const norm=f.filter(a=>a.type==="normal");
  const unacked=atk.filter(a=>!a.ack);
  const avgConf=f.length?Math.round(f.reduce((s,a)=>s+a.conf,0)/f.length*100):0;
  const fp=atk.length?Math.round(atk.filter(a=>a.ack).length/atk.length*100):0;
  const threatPct=f.length?(atk.length/f.length*100):0;
  return {{f,atk,norm,unacked,avgConf,fp,threatPct}};
}}

// ── KPIs ─────────────────────────────────────────────────
function renderKPIs(s){{
  const upEl=document.getElementById("uptime-display");
  const uptime=upEl?upEl.textContent.replace("UP ",""):"00:00:00";
  const cards=[
    {{icon:"📡",val:s.f.length,  lbl:"Total Flows",   note:"this session",  cls:"c-blue",  ac:"#4488ff"}},
    {{icon:"⚡",val:s.atk.length, lbl:"Threats",       note:s.unacked.length+" unacked", cls:"c-red",   ac:"#ff4444"}},
    {{icon:"✓", val:s.norm.length,lbl:"Clean Traffic", note:"verified safe", cls:"c-green", ac:"#22ee66"}},
    {{icon:"◎", val:s.avgConf+"%",lbl:"Avg Confidence",note:"model certainty",cls:"c-amber",ac:"#ffaa22"}},
    {{icon:"⏱", val:uptime,       lbl:"Uptime",        note:"hh:mm:ss",      cls:"c-cyan",  ac:"#00ddff"}},
  ];
  document.getElementById("kpi-grid").innerHTML=cards.map(c=>`
    <div class="kpi-card" style="--ac:${{c.ac}}">
      <div class="kpi-icon">${{c.icon}}</div>
      <div class="kpi-val ${{c.cls}}">${{c.val}}</div>
      <div class="kpi-lbl">${{c.lbl}}</div>
      <div class="kpi-note">${{c.note}}</div>
    </div>`).join("");
}}

// ── Threat bar ────────────────────────────────────────────
function renderThreat(s){{
  const pct=s.threatPct;
  const color=pct>35?"#ff4444":pct>15?"#ffaa22":"#22ee66";
  const label=pct>35?"HIGH THREAT":pct>15?"ELEVATED":"NOMINAL";
  document.getElementById("threat-label").style.color=color;
  document.getElementById("threat-label").style.textShadow="0 0 10px "+color;
  document.getElementById("threat-label").textContent=label+" · "+pct.toFixed(1)+"%";
  const fill=document.getElementById("threat-fill");
  fill.style.width=pct+"%";
  fill.style.background=`linear-gradient(90deg,${{color}}66,${{color}})`;
  fill.style.boxShadow="0 0 12px "+color+"88";
  document.getElementById("fp-val").textContent=s.fp+"%";
  const unEl=document.getElementById("unacked-label");
  const udot=document.getElementById("unacked-dot");
  unEl.textContent=s.unacked.length+" UNACKED";
  if(s.unacked.length>0){{
    unEl.style.color="#ff4444"; unEl.style.textShadow="0 0 8px #ff4444";
    udot.className="dot dot-red";
    document.getElementById("status-badge").className="unacked-badge";
    document.getElementById("status-badge").textContent="⚡ "+s.unacked.length+" UNACKED";
  }}else{{
    unEl.style.color="#2a5080"; unEl.style.textShadow="none";
    udot.className="dot dot-muted";
    document.getElementById("status-badge").className="nominal-badge";
    document.getElementById("status-badge").textContent="● NOMINAL";
  }}
}}

// ── Charts ────────────────────────────────────────────────
let tlChart=null, rateChart=null;
const CHART_OPTS={{
  responsive:true, maintainAspectRatio:false,
  plugins:{{legend:{{labels:{{color:"#2a5080",font:{{size:9,family:"monospace"}},boxWidth:12}}}},tooltip:{{backgroundColor:"#060d1c",borderColor:"#1a3a6e",borderWidth:1,titleColor:"#2a5080",bodyColor:"#7ab0d8",bodyFont:{{family:"monospace",size:10}}}}}},
  scales:{{x:{{grid:{{color:"#0d2040"}},ticks:{{color:"#2a5080",font:{{size:8,family:"monospace"}}}}}},y:{{grid:{{color:"#0d2040"}},ticks:{{color:"#2a5080",font:{{size:8,family:"monospace"}}}}}}}},
}};

function buildTimelineData(f){{
  const groups={{}};
  f.forEach(a=>{{
    const t=String(a.time||a.timestamp||"").slice(0,5)||"00:00";
    if(!groups[t]) groups[t]={{normal:0,attack:0}};
    groups[t][a.type]++;
  }});
  const labels=Object.keys(groups).sort();
  return {{labels,normal:labels.map(l=>groups[l].normal),attack:labels.map(l=>groups[l].attack)}};
}}

function initCharts(f){{
  const tld=buildTimelineData(f);
  const tlCtx=document.getElementById("chart-timeline").getContext("2d");
  if(tlChart) tlChart.destroy();
  tlChart=new Chart(tlCtx,{{
    type:"line", data:{{
      labels:tld.labels,
      datasets:[
        {{label:"Normal",data:tld.normal,borderColor:"#22ee66",backgroundColor:"rgba(34,238,102,0.08)",borderWidth:1.5,fill:true,tension:0.4,pointRadius:0}},
        {{label:"Attack",data:tld.attack,borderColor:"#ff4444",backgroundColor:"rgba(255,68,68,0.12)",borderWidth:1.5,fill:true,tension:0.4,pointRadius:0}},
      ]
    }}, options:CHART_OPTS
  }});

  const rate=tld.labels.map((_,i)=>tld.normal[i]+tld.attack[i]);
  const rCtx=document.getElementById("chart-rate").getContext("2d");
  if(rateChart) rateChart.destroy();
  rateChart=new Chart(rCtx,{{
    type:"line", data:{{
      labels:tld.labels,
      datasets:[{{label:"Rate",data:rate,borderColor:"#ffaa22",backgroundColor:"rgba(255,170,34,0.1)",borderWidth:1.5,fill:true,tension:0.4,pointRadius:0}}]
    }}, options:CHART_OPTS
  }});
}}

// ── Tabs ─────────────────────────────────────────────────
function switchTab(name,el){{
  activeTab=name;
  document.querySelectorAll(".tab").forEach(t=>t.classList.remove("active"));
  el.classList.add("active");
  ["feed","ips","ports","types"].forEach(t=>{{
    document.getElementById("tab-"+t).style.display=t===name?"block":"none";
  }});
  renderTabs();
}}

function renderTabs(){{
  const atk=getFiltered().filter(a=>a.type==="attack");

  // Feed tab — open threats summary
  const feedTab=document.getElementById("tab-feed");
  feedTab.innerHTML=`<div class="sec-label"><div class="sec-bar" style="background:#00ddff;color:#00ddff"></div>Open Threats</div>`+
    (atk.length?atk.map(a=>`
      <div style="display:flex;justify-content:space-between;align-items:center;padding:4px 0;border-bottom:1px solid #0d2040">
        <div style="display:flex;align-items:center;gap:5px">
          <span class="badge badge-${{a.severity}}">${{a.severity.slice(0,4).toUpperCase()}}</span>
          <span style="font-size:0.62rem;color:#2a5080">${{a.service}}</span>
        </div>
        <span style="font-size:0.6rem;color:${{a.ack?"#2a5080":"#ff4444"}};font-family:monospace;text-shadow:${{a.ack?"none":"0 0 8px #ff4444"}}">${{a.ack?"acked":"OPEN"}}</span>
      </div>`).join(""):"<div style='font-size:0.7rem;color:#2a5080;padding:8px'>No attacks detected</div>");

  // Top IPs
  const ipCounts={{}};
  atk.forEach(a=>{{ ipCounts[a.src]=(ipCounts[a.src]||0)+1; }});
  const topIPs=Object.entries(ipCounts).sort((a,b)=>b[1]-a[1]).slice(0,5);
  const maxIP=topIPs[0]?.[1]||1;
  document.getElementById("tab-ips").innerHTML=
    `<div class="sec-label"><div class="sec-bar" style="background:#00ddff;color:#00ddff"></div>Attacking IPs</div>`+
    (topIPs.length?topIPs.map(([ip,h])=>`
      <div class="ip-row">
        <span style="font-size:0.85rem">${{ip.startsWith("127.")||ip.startsWith("10.")?"🖥":"🌐"}}</span>
        <div style="flex:1">
          <div style="font-size:0.65rem;color:#a0c8e8;font-family:monospace">${{ip}}</div>
          <div class="mini-track"><div class="mini-fill" style="width:${{(h/maxIP*100)}}%;background:#ff444480;box-shadow:0 0 4px #ff444444"></div></div>
        </div>
        <span style="font-size:0.62rem;color:#ff4444;font-family:monospace;font-weight:700;text-shadow:0 0 8px #ff4444">${{h}}</span>
      </div>`).join(""):"<div style='font-size:0.7rem;color:#2a5080;padding:8px'>No attack IPs</div>");

  // Ports
  const svcCounts={{}};
  atk.forEach(a=>{{ svcCounts[a.service]=(svcCounts[a.service]||0)+1; }});
  const topSvcs=Object.entries(svcCounts).sort((a,b)=>b[1]-a[1]).slice(0,5);
  const maxSvc=topSvcs[0]?.[1]||1;
  document.getElementById("tab-ports").innerHTML=
    `<div class="sec-label"><div class="sec-bar" style="background:#00ddff;color:#00ddff"></div>Targeted Services</div>`+
    (topSvcs.length?topSvcs.map(([s,h])=>`
      <div class="port-row">
        <div style="display:flex;justify-content:space-between;margin-bottom:3px">
          <span style="font-size:0.65rem;color:#a0c8e8;font-family:monospace">${{s}}</span>
          <span style="font-size:0.62rem;color:#ff4444;font-family:monospace;font-weight:700">${{h}}</span>
        </div>
        <div class="mini-track"><div class="mini-fill" style="width:${{(h/maxSvc*100)}}%;background:#ff444480"></div></div>
      </div>`).join(""):"<div style='font-size:0.7rem;color:#2a5080;padding:8px'>No data</div>");

  // Types
  const atkTypes=[
    {{type:"portsweep",count:atk.filter(a=>a.atk==="portsweep").length,color:"#ff4444"}},
    {{type:"probe",    count:atk.filter(a=>a.atk==="probe").length,    color:"#ffaa22"}},
    {{type:"r2l",      count:atk.filter(a=>a.atk==="r2l").length,      color:"#aa55ff"}},
  ].filter(a=>a.count>0);
  const maxT=Math.max(...atkTypes.map(a=>a.count),1);
  document.getElementById("tab-types").innerHTML=
    `<div class="sec-label"><div class="sec-bar" style="background:#00ddff;color:#00ddff"></div>Attack Classification</div>`+
    (atkTypes.length?atkTypes.map(a=>`
      <div class="atk-row">
        <div style="display:flex;justify-content:space-between;margin-bottom:3px">
          <span style="font-size:0.65rem;color:${{a.color}};font-weight:700;text-transform:uppercase;text-shadow:0 0 8px ${{a.color}}">${{a.type}}</span>
          <span style="font-size:0.62rem;color:#2a5080;font-family:monospace">${{a.count}}</span>
        </div>
        <div class="mini-track"><div class="mini-fill" style="width:${{(a.count/maxT*100)}}%;background:${{a.color}}80"></div></div>
      </div>`).join("")+`
      <div style="margin-top:10px;background:#091220;border:1px solid #1a3a6e;border-radius:6px;padding:8px 10px">
        <div style="font-size:0.56rem;color:#2a5080;margin-bottom:5px;text-transform:uppercase">Legend</div>
        <div style="font-size:0.58rem;color:#2a5080;margin-bottom:3px"><span style="color:#ffaa22">portsweep</span> · Many ports, one host</div>
        <div style="font-size:0.58rem;color:#2a5080;margin-bottom:3px"><span style="color:#ffaa22">probe</span> · Scan/fingerprint</div>
        <div style="font-size:0.58rem;color:#2a5080"><span style="color:#ffaa22">r2l</span> · Remote-to-local exploit</div>
      </div>`:"<div style='font-size:0.7rem;color:#2a5080;padding:8px'>No classified attacks</div>");
}}

// ── Alert Feed ────────────────────────────────────────────
function renderFeed(f){{
  const feed=document.getElementById("alert-feed");
  const rows=[...f].reverse().slice(0,40);
  feed.innerHTML=rows.map(a=>{{
    const isAtk=a.type==="attack";
    const conf=Math.round(a.conf*100);
    const ts=(a.time||String(a.timestamp||"")).slice(0,8);
    const badgeCls="badge-"+(a.severity||"info");
    const sevLbl=(a.severity||"info").slice(0,4).toUpperCase();
    const protoCls="proto-"+(a.proto||"tcp");
    const atkSpan=a.atk?`<span style="color:#ffaa22;font-size:0.58rem;font-style:italic">${{a.atk}}</span>`:"";
    const confColor=isAtk?"#ff4444":"#22ee66";
    const confLabel=isAtk?"⚡ATK":"✓OK";
    const ackBtn=isAtk&&!a.ack?`<button class="ack-btn" onclick="ackAlert(${{a.id}})">ACK</button>`:"";
    const acked=a.ack?`<span style="font-size:0.54rem;color:#2a5080">✓ reviewed</span>`:"";
    const rowCls="alert-row "+(isAtk?"alert-atk":"alert-ok")+(a.ack?" alert-acked":"");
    return `<div class="${{rowCls}}">
      <span class="badge ${{badgeCls}}">${{sevLbl}}</span>
      <span style="color:#2a5080;min-width:52px;font-size:0.6rem">${{ts}}</span>
      <span class="proto-tag ${{protoCls}}">${{(a.proto||"tcp").toUpperCase()}}</span>
      <span style="color:#2a5080;font-size:0.6rem">${{a.src}}</span>
      <span style="color:#2a5080;font-size:0.56rem">▶</span>
      <span style="font-size:0.6rem">${{a.dst}}</span>
      <span style="color:#2a5080;font-size:0.58rem">[${{a.service}}]</span>
      ${{atkSpan}}
      <span style="margin-left:auto;color:${{confColor}};font-weight:700;font-size:0.62rem;text-shadow:0 0 8px ${{confColor}}">${{confLabel}} ${{conf}}%</span>
      ${{ackBtn}}${{acked}}
    </div>`;
  }}).join("");
}}

// ── ACK ───────────────────────────────────────────────────
function ackAlert(id){{
  alerts=alerts.map(a=>a.id===id?{{...a,ack:true}}:a);
  renderAll();
}}

// ── Master render ─────────────────────────────────────────
function renderAll(){{
  const s=getStats();
  renderKPIs(s);
  renderThreat(s);
  initCharts(s.f);
  renderTabs();
  renderFeed(s.f);
  tick++;
  document.getElementById("footer-tick").textContent=
    "tick#"+tick+" · "+(autoRefresh?"auto-refresh 5s":"manual mode");
}}

// ── Auto refresh ──────────────────────────────────────────
let refreshTimer=null;
function startRefresh(){{
  if(refreshTimer) clearInterval(refreshTimer);
  refreshTimer=setInterval(()=>{{
    if(autoRefresh) renderAll();
  }},5000);
}}

// ── Init ─────────────────────────────────────────────────
renderAll();
startRefresh();
</script>
</body>
</html>"""

# ── Render via Streamlit ──────────────────────────────────
components.html(HTML, height=900, scrolling=False)
