"""Page 4 — AI Model Insights"""
import streamlit as st
import numpy as np
import plotly.graph_objects as go
import sys
from pathlib import Path
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))
sys.path.insert(0, str(PROJECT_ROOT / "graph_engine"))
sys.path.insert(0, str(PROJECT_ROOT / "dashboard" / "components"))
from theme import inject_theme, BG, PANEL, PRIMARY
from header import render_header, render_nav
from shap_panel import render_shap_panel
from prediction_panels import render_model_history

st.set_page_config(page_title="NEXUS-IDS | AI Model Insights", page_icon="🛡️", layout="wide", initial_sidebar_state="collapsed")
inject_theme()
render_header()
render_nav(current_page="AI Model Insights")

if 'pipeline_result' not in st.session_state:
    st.warning("Run the analysis from the Overview page first.")
    st.stop()
pr = st.session_state.pipeline_result

c1, c2 = st.columns(2)
with c1:
    st.plotly_chart(render_shap_panel(pr["shap_df"]), use_container_width=True)
with c2:
    fi = pr["clf"].get_feature_importance()
    if fi is not None:
        top_fi = fi.head(15).sort_values("Importance", ascending=True)
        fig = go.Figure(go.Bar(x=top_fi["Importance"], y=top_fi["Feature"], orientation='h',
            marker=dict(color=top_fi["Importance"], colorscale=[[0, PANEL], [1, PRIMARY]])))
        fig.update_layout(plot_bgcolor=BG, paper_bgcolor=BG, font=dict(color='#FFF', family="Inter"),
            margin=dict(l=10, r=20, t=40, b=20), height=400,
            xaxis=dict(showgrid=True, gridcolor='#2A2D35', linecolor='#3A3F4B', title="Importance"),
            yaxis=dict(showgrid=False, tickfont=dict(size=10)),
            title=dict(text="FEATURE IMPORTANCE", font=dict(color=PRIMARY, size=11), x=0.01))
        st.plotly_chart(fig, use_container_width=True)

st.markdown('<div class="soc-panel-title">MODEL PERFORMANCE</div>', unsafe_allow_html=True)
predictions, y_true = pr["predictions"], pr["y"]
acc = accuracy_score(y_true, predictions)
prec = precision_score(y_true, predictions, average='weighted', zero_division=0)
rec = recall_score(y_true, predictions, average='weighted', zero_division=0)
f1 = f1_score(y_true, predictions, average='weighted', zero_division=0)
mc = st.columns(4)
mc[0].metric("Accuracy", f"{acc:.4f}")
mc[1].metric("Precision", f"{prec:.4f}")
mc[2].metric("Recall", f"{rec:.4f}")
mc[3].metric("F1 Score", f"{f1:.4f}")

c1, c2 = st.columns(2)
with c1:
    class_names = ['Normal', 'DoS', 'Probe', 'R2L', 'U2R']
    cm = confusion_matrix(y_true, predictions, labels=[0, 1, 2, 3, 4])
    fig = go.Figure(data=go.Heatmap(z=cm, x=class_names, y=class_names,
        colorscale=[[0, BG], [0.5, PRIMARY], [1, '#FFC107']],
        text=cm, texttemplate="%{text}", textfont=dict(size=11, color="#FFF"),
        hovertemplate="True: %{y}<br>Pred: %{x}<br>Count: %{z}<extra></extra>"))
    fig.update_layout(plot_bgcolor=BG, paper_bgcolor=BG, font=dict(color='#FFF', family="Inter"),
        margin=dict(l=60, r=20, t=40, b=60), height=380,
        xaxis=dict(title="Predicted"), yaxis=dict(title="True", autorange="reversed"),
        title=dict(text="CONFUSION MATRIX", font=dict(color=PRIMARY, size=11), x=0.01))
    st.plotly_chart(fig, use_container_width=True)
with c2:
    st.plotly_chart(render_model_history(), use_container_width=True)
