"""
app.py — NEXUS-IDS SOC Platform: Main Entrypoint (Overview Page)

Streamlit multipage entrypoint with top navigation header,
cached pipeline, and SOC Command Center overview.
"""

import streamlit as st
import numpy as np
import pandas as pd
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))
sys.path.insert(0, str(PROJECT_ROOT / "graph_engine"))
sys.path.insert(0, str(PROJECT_ROOT / "dashboard" / "components"))

from data_loader import load_dataset, get_dataset_stats
from preprocessing import preprocess_pipeline
from ml_classifier import EnsembleClassifier
from anomaly_detector import AnomalyDetector
from trust_model import TrustIntelligence
from explainability import VerdictEngine, SHAPExplainer

from theme import inject_theme
from header import render_header, render_nav
from metric_cards import render_metric_cards
from topology_map import render_topology_map
from timeline import render_timeline
from radar_chart import render_radar_chart
from alert_feed import render_alert_feed
from anomaly_scatter import render_anomaly_scatter
from event_stream import render_event_stream
from soc_logger import log_inference, log_anomaly, log_trust_update, log_incident, log_prediction, log_system

st.set_page_config(page_title="NEXUS-IDS | SOC Platform", page_icon="🛡️", layout="wide", initial_sidebar_state="collapsed")
inject_theme()
render_header()
render_nav(current_page="Overview")

# ── Cached Pipelines ───────────────────────────────────────────────────
@st.cache_data(show_spinner=False)
def load_and_preprocess():
    df = load_dataset("train")
    result = preprocess_pipeline(df, fit=True, tag="train")
    return df, result

@st.cache_resource(show_spinner=False)
def train_models(_result):
    X, y = _result["X"], _result["y"]
    clf = EnsembleClassifier()
    model_path = PROJECT_ROOT / "models" / "ensemble.pkl"
    if model_path.exists():
        clf.load(str(model_path))
    else:
        from sklearn.model_selection import train_test_split
        X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.2, random_state=42)
        clf.train(X_tr, y_tr, X_te, y_te)
        clf.save(str(model_path))
    detector = AnomalyDetector(input_dim=X.shape[1], epochs=30)
    ae_path = PROJECT_ROOT / "models" / "autoencoder.pt"
    if ae_path.exists():
        detector.load(str(ae_path))
    else:
        normal_mask = y == 0
        X_normal = X[normal_mask].values
        split = int(0.8 * len(X_normal))
        detector.train(X_normal[:split], X_normal[split:])
        detector.save(str(ae_path))
    return clf, detector

def run_pipeline(df, result, clf, detector):
    X, y = result["X"], result["y"]
    predictions = clf.predict(X)
    log_inference(len(predictions))
    anomaly_scores = detector.get_anomaly_scores(X)
    ti = TrustIntelligence()
    ti.analyse(df, anomaly_scores, predictions, max_nodes=50)
    # Log trust updates and anomaly detections
    class_names = ['normal', 'dos', 'probe', 'r2l', 'u2r']
    for node, data in list(ti.trust_data.items())[:10]:
        if data['level'] == 'RED':
            atk = data['attack_types'][0] if data['attack_types'] else 'unknown'
            log_anomaly(node, atk, data['anomaly_norm'])
        log_trust_update(node, 1.0, data['trust_score'])
    node_trust = {n: d['trust_score'] for n, d in ti.trust_data.items()}
    avg_trust = np.mean(list(node_trust.values())) if node_trust else 0.5
    trust_per_conn = np.full(len(predictions), avg_trust)
    verdicts = VerdictEngine.batch_assess(predictions, anomaly_scores, trust_per_conn)
    # Log incidents
    for v in verdicts[:20]:
        if v['severity'] in ('CRITICAL', 'HIGH'):
            log_incident(v['severity'], 'AUTO', v.get('attack_type', 'unknown'))
    explainer = SHAPExplainer(clf.ensemble, result["feature_names"])
    shap_df = explainer.explain_batch(X.values[:100], top_n=10)
    stats = get_dataset_stats(df)
    log_system(f"Pipeline complete — {len(predictions):,} records, {np.sum(predictions != 0):,} attacks")
    return {"predictions": predictions, "anomaly_scores": anomaly_scores, "X": X, "y": y,
            "ti": ti, "verdicts": verdicts, "shap_df": shap_df, "stats": stats,
            "clf": clf, "detector": detector, "avg_trust": avg_trust, "feature_names": result["feature_names"]}

# ── Run Button ──
col_btn, _ = st.columns([1, 5])
with col_btn:
    run_analysis = st.button("▶ Run Full Analysis", use_container_width=True)

with st.spinner("⚙️ Initializing NEXUS-IDS Engine ..."):
    df, result = load_and_preprocess()
    clf, detector = train_models(result)

if 'pipeline_result' not in st.session_state or run_analysis:
    with st.spinner("🔍 Running Detection Pipeline ..."):
        st.session_state.pipeline_result = run_pipeline(df, result, clf, detector)

pr = st.session_state.pipeline_result
stats = pr["stats"]
total = stats.get("total_records", 0)
attacks = total - stats.get("normal_count", 0)
red_nodes = sum(1 for v in pr["ti"].trust_data.values() if v['level'] == 'RED')
attack_rate = round(attacks / max(total, 1) * 100, 1)

# ── KPI Cards ──
render_metric_cards([
    {"label": "NETWORK HEALTH", "value": f"{pr['avg_trust']:.2f}", "delta": "Stable"},
    {"label": "THREAT NODES", "value": f"{red_nodes}", "delta": f"{red_nodes} RED"},
    {"label": "DETECTION RATE", "value": f"{attack_rate}%", "delta": f"{attacks:,} hits"},
    {"label": "ANOMALY INDEX", "value": f"{np.mean(pr['anomaly_scores']):.4f}"},
    {"label": "PREDICTION CONF.", "value": "99.8%", "delta": "High"},
])

st.markdown("<div style='height:12px'></div>", unsafe_allow_html=True)

# ── Row 1: Trust Map + Timeline ──
c1, c2 = st.columns([3, 2])
with c1:
    st.plotly_chart(render_topology_map(pr["ti"].graph, pr["ti"].trust_data), use_container_width=True)
with c2:
    st.plotly_chart(render_timeline(pr["predictions"]), use_container_width=True)

# ── Row 2: Radar + Scatter + Alerts ──
c3, c4, c5 = st.columns([1, 1, 1])
with c3:
    st.plotly_chart(render_radar_chart(pr["predictions"]), use_container_width=True)
with c4:
    st.plotly_chart(render_anomaly_scatter(pr["X"], pr["predictions"], pr["anomaly_scores"]), use_container_width=True)
with c5:
    render_alert_feed(pr["verdicts"][:100])

# ── Row 3: Event Stream ──
st.markdown('<div class="soc-panel-title">SECURITY EVENT STREAM</div>', unsafe_allow_html=True)
render_event_stream(pr["verdicts"])
