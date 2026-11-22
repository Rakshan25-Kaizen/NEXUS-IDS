"""Page 5 — Threat Prediction"""
import streamlit as st
import numpy as np
import sys
from pathlib import Path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))
sys.path.insert(0, str(PROJECT_ROOT / "graph_engine"))
sys.path.insert(0, str(PROJECT_ROOT / "dashboard" / "components"))
from theme import inject_theme
from header import render_header, render_nav
from prediction_panels import render_threat_forecast, render_risk_gauge, render_prediction_table

st.set_page_config(page_title="NEXUS-IDS | Threat Prediction", page_icon="🛡️", layout="wide", initial_sidebar_state="collapsed")
inject_theme()
render_header()
render_nav(current_page="Threat Prediction")

if 'pipeline_result' not in st.session_state:
    st.warning("Run the analysis from the Overview page first.")
    st.stop()
pr = st.session_state.pipeline_result
total = pr["stats"].get("total_records", 1)
attacks = total - pr["stats"].get("normal_count", 0)
ar = attacks / max(total, 1)

c1, c2 = st.columns([2, 1])
with c1:
    st.plotly_chart(render_threat_forecast(pr["predictions"], pr["anomaly_scores"]), use_container_width=True)
with c2:
    st.plotly_chart(render_risk_gauge(pr["anomaly_scores"], attack_rate=ar, avg_trust=pr["avg_trust"]),
                    use_container_width=True)

st.markdown('<div class="soc-panel-title">ATTACK PROBABILITY MATRIX</div>', unsafe_allow_html=True)
render_prediction_table(pr["predictions"], pr["anomaly_scores"])
