"""Page 8 — Data Management"""
import streamlit as st
import numpy as np
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
import sys
from pathlib import Path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))
sys.path.insert(0, str(PROJECT_ROOT / "graph_engine"))
sys.path.insert(0, str(PROJECT_ROOT / "dashboard" / "components"))
from theme import inject_theme, BG, PANEL, PRIMARY, SAFE, WARNING, CRITICAL
from header import render_header, render_nav

st.set_page_config(page_title="NEXUS-IDS | Data Management", page_icon="🛡️", layout="wide", initial_sidebar_state="collapsed")
inject_theme()
render_header()
render_nav(current_page="Data Management")

tab1, tab2, tab3 = st.tabs(["Dataset Upload", "Dataset Quality", "Threat Simulation"])

with tab1:
    st.markdown('<div class="soc-panel-title">UPLOAD DATASET</div>', unsafe_allow_html=True)
    uploaded = st.file_uploader("Upload CSV", type=["csv"])
    if uploaded:
        df = pd.read_csv(uploaded)
        st.success(f"Loaded {df.shape[0]:,} rows x {df.shape[1]} columns")
        st.dataframe(df.head(20), use_container_width=True, height=300)
        st.markdown(f"**Shape:** {df.shape}")
    elif 'pipeline_result' in st.session_state:
        st.info("Using pipeline data for preview.")
        pr = st.session_state.pipeline_result
        st.markdown(f"**Records:** {pr['stats'].get('total_records', 0):,}")

with tab2:
    st.markdown('<div class="soc-panel-title">DATASET QUALITY ANALYZER</div>', unsafe_allow_html=True)
    if 'pipeline_result' in st.session_state:
        pr = st.session_state.pipeline_result
        X = pr["X"]
        y = pr["y"]
        c1, c2 = st.columns(2)
        with c1:
            # Missing values
            missing = X.isnull().sum()
            fig = go.Figure(go.Bar(x=missing.values[:15], y=missing.index[:15], orientation='h',
                marker=dict(color=PRIMARY)))
            fig.update_layout(plot_bgcolor=BG, paper_bgcolor=BG, font=dict(color='#FFF', family="Inter"),
                margin=dict(l=10, r=20, t=40, b=20), height=300,
                xaxis=dict(gridcolor='#2A2D35'), yaxis=dict(tickfont=dict(size=9)),
                title=dict(text="MISSING VALUES", font=dict(color=PRIMARY, size=11), x=0.01))
            st.plotly_chart(fig, use_container_width=True)

        with c2:
            # Class balance
            class_names = ['Normal', 'DoS', 'Probe', 'R2L', 'U2R']
            counts = [int(np.sum(y == i)) for i in range(5)]
            colors = [SAFE, CRITICAL, WARNING, '#A855F7', '#EC4899']
            fig = go.Figure(go.Bar(x=class_names, y=counts, marker=dict(color=colors)))
            fig.update_layout(plot_bgcolor=BG, paper_bgcolor=BG, font=dict(color='#FFF', family="Inter"),
                margin=dict(l=40, r=20, t=40, b=20), height=300,
                xaxis=dict(gridcolor='#2A2D35'), yaxis=dict(gridcolor='#2A2D35', title="Count"),
                title=dict(text="CLASS DISTRIBUTION", font=dict(color=PRIMARY, size=11), x=0.01))
            st.plotly_chart(fig, use_container_width=True)

        # Feature distributions
        st.markdown('<div class="soc-panel-title">TOP FEATURE DISTRIBUTIONS</div>', unsafe_allow_html=True)
        top_feats = list(X.columns[:6])
        cols = st.columns(3)
        for i, feat in enumerate(top_feats):
            with cols[i % 3]:
                vals = X[feat].values[:2000]
                fig = go.Figure(go.Histogram(x=vals, nbinsx=40, marker=dict(color=PRIMARY, line=dict(width=0))))
                fig.update_layout(plot_bgcolor=BG, paper_bgcolor=BG, font=dict(color='#FFF', size=9),
                    margin=dict(l=20, r=10, t=30, b=20), height=200,
                    xaxis=dict(gridcolor='#2A2D35'), yaxis=dict(gridcolor='#2A2D35'),
                    title=dict(text=feat.upper(), font=dict(color='#8892A0', size=10), x=0.01))
                st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("Run analysis from Overview first.")

with tab3:
    st.markdown('<div class="soc-panel-title">THREAT SIMULATION</div>', unsafe_allow_html=True)
    st.markdown("Simulate network traffic events for live demonstration.")
    sim_type = st.selectbox("Simulation Type", ["Normal Traffic", "DoS Spike", "Probe Sweep", "Mixed Attack"])
    c1, c2 = st.columns(2)
    with c1:
        n_events = st.slider("Number of Events", 50, 1000, 200, 50)
    with c2:
        intensity = st.slider("Attack Intensity", 0.0, 1.0, 0.7, 0.1)

    if st.button("Simulate Network Traffic", use_container_width=True):
        np.random.seed(42)
        sim_data = []
        for i in range(n_events):
            if sim_type == "Normal Traffic":
                cls = 0
            elif sim_type == "DoS Spike":
                cls = 1 if np.random.random() < intensity else 0
            elif sim_type == "Probe Sweep":
                cls = 2 if np.random.random() < intensity else 0
            else:
                cls = np.random.choice([0, 1, 2, 3, 4], p=[1-intensity, intensity*0.5, intensity*0.3, intensity*0.1, intensity*0.1])
            sim_data.append(cls)

        sim_arr = np.array(sim_data)
        class_names = ['Normal', 'DoS', 'Probe', 'R2L', 'U2R']
        counts = [int(np.sum(sim_arr == i)) for i in range(5)]
        colors = [SAFE, CRITICAL, WARNING, '#A855F7', '#EC4899']

        fig = go.Figure(go.Bar(x=class_names, y=counts, marker=dict(color=colors)))
        fig.update_layout(plot_bgcolor=BG, paper_bgcolor=BG, font=dict(color='#FFF', family="Inter"),
            margin=dict(l=40, r=20, t=40, b=20), height=300,
            xaxis=dict(gridcolor='#2A2D35'), yaxis=dict(gridcolor='#2A2D35', title="Events"),
            title=dict(text="SIMULATION RESULTS", font=dict(color=PRIMARY, size=11), x=0.01))
        st.plotly_chart(fig, use_container_width=True)
        st.success(f"Simulated {n_events} events: {counts[0]} normal, {sum(counts[1:])} attacks")
