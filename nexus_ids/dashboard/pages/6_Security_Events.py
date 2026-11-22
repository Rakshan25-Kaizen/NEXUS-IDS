"""Page 6 — Security Events"""
import streamlit as st
import numpy as np
import pandas as pd
import sys
from pathlib import Path
from datetime import datetime, timedelta
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))
sys.path.insert(0, str(PROJECT_ROOT / "graph_engine"))
sys.path.insert(0, str(PROJECT_ROOT / "dashboard" / "components"))
from theme import inject_theme
from header import render_header, render_nav

st.set_page_config(page_title="NEXUS-IDS | Security Events", page_icon="🛡️", layout="wide", initial_sidebar_state="collapsed")
inject_theme()
render_header()
render_nav(current_page="Security Events")

if 'pipeline_result' not in st.session_state:
    st.warning("Run the analysis from the Overview page first.")
    st.stop()
pr = st.session_state.pipeline_result
np.random.seed(42)
verdicts = pr["verdicts"]
subnets = ["192.168.1", "192.168.2", "192.168.9", "10.0.3", "10.0.7"]
action_map = {'CRITICAL': 'Isolate Node', 'HIGH': 'Quarantine', 'MEDIUM': 'Monitor', 'LOW': 'Log Only'}
status_opts = ['Open', 'Investigating', 'Mitigated', 'Closed']
base_time = datetime.now()
incidents = []
for i, v in enumerate(verdicts[:200]):
    if v['severity'] == 'LOW':
        continue
    ts = base_time - timedelta(seconds=np.random.randint(0, 7200))
    node = f"{subnets[np.random.randint(0, len(subnets))]}.{np.random.randint(1, 254)}"
    incidents.append({"ID": f"INC-{1000+i:04d}", "Timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
        "Node": node, "Threat": v.get("attack_type", "Unknown").upper(), "Severity": v["severity"],
        "Trust Score": round(np.random.uniform(0.05, 0.45), 2),
        "Status": status_opts[np.random.randint(0, 4)], "Action": action_map.get(v["severity"], "Log")})
df = pd.DataFrame(incidents)
c1, c2 = st.columns(2)
with c1:
    sev_f = st.multiselect("Severity", ["CRITICAL", "HIGH", "MEDIUM"], default=["CRITICAL", "HIGH"])
with c2:
    sta_f = st.multiselect("Status", status_opts, default=["Open", "Investigating"])
mask = df["Severity"].isin(sev_f) & df["Status"].isin(sta_f)
st.dataframe(df[mask].sort_values("Timestamp", ascending=False), use_container_width=True, height=400)

st.markdown('<div class="soc-panel-title">INCIDENT DETAIL</div>', unsafe_allow_html=True)
if not df.empty:
    sel = st.selectbox("Select Incident", df["ID"].tolist(), label_visibility="collapsed")
    row = df[df["ID"] == sel].iloc[0]
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Node", row["Node"])
    c2.metric("Threat", row["Threat"])
    c3.metric("Trust", f"{row['Trust Score']:.2f}")
    c4.metric("Severity", row["Severity"])
    st.markdown(f"**Action:** {row['Action']} | **Status:** {row['Status']}")
