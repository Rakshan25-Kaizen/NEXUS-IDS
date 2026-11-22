"""
test_pipeline.py — NEXUS-IDS End-to-End Integration Test

Loads 10 records from the test dataset and runs them through the entire
pipeline (Preprocessing → ML Predict → DL Anomaly → Graph Trust → SHAP → Verdict)
using the loaded models.
"""

import sys
import os
from pathlib import Path
import pandas as pd
import numpy as np
import joblib
import warnings

# Suppress sklearn/xgboost warnings for clean output
warnings.filterwarnings("ignore")

# ── Path Setup ──────────────────────────────────────────────────────────
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))
sys.path.insert(0, str(PROJECT_ROOT / "graph_engine"))

MODELS_DIR = PROJECT_ROOT / "models"
RAW_DIR = PROJECT_ROOT / "data" / "raw"

# Import Pipeline Components
from data_loader import load_dataset
from ml_classifier import EnsembleClassifier
from anomaly_detector import AnomalyDetector
from trust_model import TrustIntelligence
from explainability import VerdictEngine, SHAPExplainer


def main():
    print("="*60)
    print(" NEXUS-IDS: END-TO-END PIPELINE INTEGRATION TEST")
    print("="*60)

    # 1. Load the raw test data (first 10 rows)
    print("[*] 1. Loading KDDTest+ Data (10 records)...")
    try:
        df_raw = load_dataset("test").head(10)
        # Drop difficulty if present
        if 'difficulty' in df_raw.columns:
            df_raw = df_raw.drop(columns=['difficulty'])
        # Separate true labels for comparison
        y_true = df_raw['label'].values
        df_features = df_raw.drop(columns=['label'])
    except Exception as e:
        print(f"[!] Errored loading data: {e}")
        return

    # 2. Load Preprocessors
    print("[*] 2. Loading Preprocessing Artifacts...")
    try:
        scaler = joblib.load(MODELS_DIR / "scaler.pkl")
        encoders = joblib.load(MODELS_DIR / "encoders.pkl")
    except Exception as e:
        print(f"[!] Errored loading artifacts. Did you run dashboard first? {e}")
        return

    # 3. Load Models
    print("[*] 3. Loading ML and DL Models...")
    clf = EnsembleClassifier()
    detector = AnomalyDetector(input_dim=41)
    
    if not (clf.load(str(MODELS_DIR / "ensemble.pkl")) and 
            detector.load(str(MODELS_DIR / "autoencoder.pt"))):
        print("[!] Errored loading models.")
        return

    # Initialize SHAP and Trust Engine
    explainer = SHAPExplainer(clf.ensemble, clf.feature_names)
    ti = TrustIntelligence()

    print("\n" + "="*60)
    print(" EXECUTING PIPELINE PER RECORD")
    print("="*60)

    # Process each record entirely end-to-end
    for i in range(10):
        print(f"\n--- RECORD #{i+1} : True Label = [{y_true[i].upper()}] ---")
        
        # --- PREPROCESSING ---
        raw_row = df_features.iloc[i:i+1].copy()
        
        # Encode categoricals using the unseen guard
        for col in ["protocol_type", "service", "flag"]:
            le = encoders[col]
            raw_row[col] = raw_row[col].astype(str).apply(
                lambda x: le.transform([x])[0] if x in le.classes_ 
                else le.transform([le.classes_[0]])[0]
            )
            
        # Scale
        X_scaled = scaler.transform(raw_row.astype(float))
        X_scaled_df = pd.DataFrame(X_scaled, columns=clf.feature_names)

        # --- ML CLASSIFICATION ---
        pred_class = int(clf.predict(X_scaled_df)[0])
        pred_name = VerdictEngine.CLASS_NAMES[pred_class]
        proba = clf.predict_proba(X_scaled_df)[0]
        max_proba = np.max(proba)
        
        print(f"ML Predict  : {pred_name.upper()} (Confidence: {max_proba:.2%})")

        # --- DL ANOMALY SCORE ---
        anomaly_score = float(detector.get_anomaly_scores(X_scaled)[0])
        print(f"DL Anomaly  : {anomaly_score:.4f} [Scale 0-1]")

        # --- GRAPH TRUST SCORE ---
        # To test the graph, we need to pass a batch (at least 2 nodes) to build a topology.
        # We will trick it by pretending this connection happened 5 times to form a mini-graph.
        mock_df = pd.DataFrame([raw_row.iloc[0]] * 5)
        mock_anomaly = np.array([anomaly_score] * 5)
        mock_preds = np.array([pred_class] * 5)
        
        ti_result = ti.analyse(mock_df, mock_anomaly, mock_preds, max_nodes=10)
        
        # Grab trust of the first generated node in the graph
        first_node = list(ti.trust_data.keys())[0]
        node_trust_info = ti.trust_data[first_node]
        trust_score = node_trust_info['trust_score']
        trust_level = node_trust_info['level']
        
        print(f"Graph Trust : {trust_score:.4f} [{trust_level}] (Centralities: Bet={node_trust_info['betweenness_norm']:.2f}, InDeg={node_trust_info['in_degree_norm']:.2f})")

        # --- SHAP EXPLAINABILITY ---
        impacts = explainer.explain_instance(X_scaled_df, top_n=3)
        print("Top Drivers : ", end="")
        for feat, val in impacts.items():
            print(f"{feat}({val:+.2f}) ", end="")
        print("")

        # --- VERDICT ENGINE ---
        verdict = VerdictEngine.assess(pred_class, anomaly_score, trust_score)
        print(f"Verdict     : [{verdict['severity']}] {verdict['reason']}")


if __name__ == "__main__":
    main()
