"""Page 2 — Network Intelligence"""
import streamlit as st
import sys
from pathlib import Path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))
sys.path.insert(0, str(PROJECT_ROOT / "graph_engine"))
sys.path.insert(0, str(PROJECT_ROOT / "dashboard" / "components"))
from theme import inject_theme
from header import render_header, render_nav
from topology_map import render_topology_map, render_attack_propagation
from heatmap import render_risk_heatmap, render_connection_matrix

st.set_page_config(page_title="NEXUS-IDS | Network Intelligence", page_icon="🛡️", layout="wide", initial_sidebar_state="collapsed")
inject_theme()
render_header()
render_nav(current_page="Network Intelligence")

if 'pipeline_result' not in st.session_state:
    st.warning("Run the analysis from the Overview page first.")
    st.stop()
pr = st.session_state.pipeline_result
ti = pr["ti"]

st.markdown('<div class="soc-panel-title">NETWORK TOPOLOGY</div>', unsafe_allow_html=True)
st.plotly_chart(render_topology_map(ti.graph, ti.trust_data), use_container_width=True)

c1, c2 = st.columns(2)
with c1:
    st.plotly_chart(render_risk_heatmap(ti.trust_data), use_container_width=True)
with c2:
    st.plotly_chart(render_connection_matrix(ti.graph), use_container_width=True)

st.markdown('<div class="soc-panel-title">ATTACK PROPAGATION PATH</div>', unsafe_allow_html=True)
st.plotly_chart(render_attack_propagation(ti.graph, ti.trust_data), use_container_width=True)

st.markdown('<div class="soc-panel-title">NODE DETAIL</div>', unsafe_allow_html=True)
nodes = list(ti.trust_data.keys())
if nodes:
    selected = st.selectbox("Select Node", nodes, label_visibility="collapsed")
    data = ti.trust_data[selected]
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Trust Score", f"{data['trust_score']:.3f}")
    c2.metric("Risk Level", data['level'])
    c3.metric("Connections", data['connection_count'])
    c4.metric("Anomaly", f"{data['anomaly_norm']:.4f}")
    if data['attack_types']:
        st.markdown(f"**Attack Types:** {', '.join(data['attack_types'])}")
