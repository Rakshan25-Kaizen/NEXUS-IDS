"""Page 3 — Threat Analytics

Panels:
  1. Threat Activity Trends (line chart)
  2. Attack Type Distribution (radar)
  3. Network Behavior Clustering (t-SNE)
  4. Incident Alerts (alert feed)
"""
import streamlit as st
import sys
from pathlib import Path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))
sys.path.insert(0, str(PROJECT_ROOT / "graph_engine"))
sys.path.insert(0, str(PROJECT_ROOT / "dashboard" / "components"))
from theme import inject_theme
from header import render_header, render_nav
from timeline import render_timeline
from radar_chart import render_radar_chart
from anomaly_scatter import render_anomaly_scatter
from alert_feed import render_alert_feed

st.set_page_config(page_title="NEXUS-IDS | Threat Analytics", page_icon="🛡️", layout="wide", initial_sidebar_state="collapsed")
inject_theme()
render_header()
render_nav(current_page="Threats")

if 'pipeline_result' not in st.session_state:
    st.warning("Run the analysis from the Overview page first.")
    st.stop()
pr = st.session_state.pipeline_result

# ── Panel 1: Threat Activity Trends ──
st.markdown('<div class="soc-panel-title">THREAT ACTIVITY TRENDS</div>', unsafe_allow_html=True)
st.plotly_chart(render_timeline(pr["predictions"]), use_container_width=True)

st.markdown('<div style="height:24px;"></div>', unsafe_allow_html=True)

# ── Panel 2 + 3: Attack Distribution | Network Behavior Clustering ──
c1, c2 = st.columns(2, gap="large")
with c1:
    st.markdown('<div class="soc-panel-title">ATTACK TYPE DISTRIBUTION</div>', unsafe_allow_html=True)
    st.plotly_chart(render_radar_chart(pr["predictions"]), use_container_width=True)
with c2:
    st.markdown('<div class="soc-panel-title">NETWORK BEHAVIOR CLUSTERING</div>', unsafe_allow_html=True)
    st.plotly_chart(render_anomaly_scatter(
        pr["X"], pr["predictions"], pr["anomaly_scores"]
    ), use_container_width=True)

st.markdown('<div style="height:24px;"></div>', unsafe_allow_html=True)

# ── Panel 4: Incident Alerts ──
st.markdown('<div class="soc-panel-title">INCIDENT ALERTS</div>', unsafe_allow_html=True)
render_alert_feed(pr["verdicts"])
