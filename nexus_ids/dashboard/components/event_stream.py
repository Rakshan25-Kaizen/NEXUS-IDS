"""
event_stream.py — NEXUS-IDS SOC: Security Event Stream
"""
import streamlit as st
import pandas as pd
import numpy as np
from datetime import datetime, timedelta

def render_event_stream(verdicts: list, trust_data: dict = None):
    np.random.seed(42)
    n = min(len(verdicts), 200)
    rows = []
    base_time = datetime.now()
    subnets = ["192.168.1", "192.168.2", "192.168.9", "10.0.3", "10.0.7"]
    action_map = {'CRITICAL': 'ISOLATE', 'HIGH': 'QUARANTINE', 'MEDIUM': 'MONITOR', 'LOW': 'LOG'}
    for i in range(n):
        v = verdicts[i]
        ts = base_time - timedelta(seconds=np.random.randint(0, 3600))
        node = f"{subnets[np.random.randint(0, len(subnets))]}.{np.random.randint(1, 254)}"
        rows.append({"Time": ts.strftime("%H:%M:%S"), "Node": node,
            "Threat": v.get("attack_type", "Unknown").upper(), "Level": v["severity"],
            "Trust": round(np.random.uniform(0.05, 0.95), 2),
            "Action": action_map.get(v["severity"], "LOG")})
    df = pd.DataFrame(rows)
    sev_f = st.multiselect("Filter Risk Level", ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                            default=["CRITICAL", "HIGH", "MEDIUM"], key="event_stream_filter")
    st.dataframe(df[df["Level"].isin(sev_f)].sort_values("Time", ascending=False),
                 use_container_width=True, height=350)
