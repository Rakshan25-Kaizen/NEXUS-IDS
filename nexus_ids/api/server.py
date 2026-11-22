"""
server.py — NEXUS-IDS FastAPI Inference Server

Provides a REST API for real-time intrusion detection:
  POST /detect — classify a single network connection
  GET  /health — system health check
"""

import numpy as np
import pandas as pd
import sys
from pathlib import Path
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Union, Any
import joblib
import uvicorn

PROJECT_ROOT = Path(__file__).resolve().parent.parent
MODELS_DIR = PROJECT_ROOT / "models"
sys.path.insert(0, str(PROJECT_ROOT / "src"))
sys.path.insert(0, str(PROJECT_ROOT / "graph_engine"))

from ml_classifier import EnsembleClassifier
from anomaly_detector import AnomalyDetector
from explainability import VerdictEngine

CLASS_NAMES = ['normal', 'dos', 'probe', 'r2l', 'u2r']

# ── App Setup ───────────────────────────────────────────────────────────
app = FastAPI(
    title="NEXUS-IDS API",
    description="AI-Powered Network Intrusion Detection API",
    version="2.0.0"
)

# ── Load Models & Artifacts on Startup ──────────────────────────────────
clf = EnsembleClassifier()
detector = AnomalyDetector(input_dim=41)

models_loaded = False
scaler = None
encoders = None

try:
    clf_ok = clf.load(str(MODELS_DIR / "ensemble.pkl"))
    ae_ok = detector.load(str(MODELS_DIR / "autoencoder.pt"))
    scaler = joblib.load(MODELS_DIR / "scaler.pkl")
    encoders = joblib.load(MODELS_DIR / "encoders.pkl")
    
    models_loaded = clf_ok and ae_ok and (scaler is not None) and (encoders is not None)
    if models_loaded:
        print("[✓] API models and scaler/encoders loaded successfully.")
    else:
        print("[!] One or more models/artifacts not found. Run the dashboard first to train.")
except Exception as e:
    print(f"[!] Error loading models or artifacts: {e}")


# ── Request/Response Schemas ────────────────────────────────────────────
class DetectRequest(BaseModel):
    # Fix 2: Accept strings, ints, or floats
    features: List[Union[str, float, int]]

class DetectResponse(BaseModel):
    prediction: str
    probability: List[float]
    anomaly_score: float
    verdict_severity: str
    verdict_reason: str
    top_features: List[str]


# ── Preprocessing Logic for Inference ───────────────────────────────────
CATEGORICAL_COLS = ["protocol_type", "service", "flag"]
FEATURE_COLS = [
    "duration","protocol_type","service","flag","src_bytes","dst_bytes",
    "land","wrong_fragment","urgent","hot","num_failed_logins","logged_in",
    "num_compromised","root_shell","su_attempted","num_root",
    "num_file_creations","num_shells","num_access_files","num_outbound_cmds",
    "is_host_login","is_guest_login","count","srv_count","serror_rate",
    "srv_serror_rate","rerror_rate","srv_rerror_rate","same_srv_rate",
    "diff_srv_rate","srv_diff_host_rate","dst_host_count",
    "dst_host_srv_count","dst_host_same_srv_rate","dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate","dst_host_srv_diff_host_rate",
    "dst_host_serror_rate","dst_host_srv_serror_rate",
    "dst_host_rerror_rate","dst_host_srv_rerror_rate"
]

def preprocess_request(raw_features: list) -> np.ndarray:
    """Preprocesses a single raw incoming request correctly using trained artifacts."""
    df = pd.DataFrame([raw_features], columns=FEATURE_COLS)
    
    for col in CATEGORICAL_COLS:
        le = encoders[col]
        # Fix 4: Unseen label guard ensuring new values don't crash the decoder
        df[col] = df[col].astype(str).apply(
            lambda x: le.transform([x])[0] if x in le.classes_
            else le.transform([le.classes_[0]])[0]
        )
        
    df = df.astype(float)
    return scaler.transform(df)


# ── Endpoints ───────────────────────────────────────────────────────────
@app.get("/health")
def health_check():
    """System health check endpoint."""
    return {
        "status": "ok" if models_loaded else "degraded",
        "model": "ensemble_v2",
        "models_loaded": models_loaded,
    }


@app.post("/detect", response_model=DetectResponse)
def detect(request: DetectRequest):
    """
    Classifies a single network connection.

    Args:
        request: JSON body with 'features'.

    Returns:
        Prediction, probabilities, anomaly score, verdict, and top features.
    """
    if not models_loaded:
        raise HTTPException(status_code=503, detail="Models not loaded. Train via dashboard first.")

    if len(request.features) != 41:
        raise HTTPException(status_code=422, detail=f"Expected 41 features, got {len(request.features)}")

    try:
        # Fix 2: FIRST line scales the raw features properly
        X_scaled = preprocess_request(request.features)
        
        # We need a DataFrame to feed into clf for feature names to match correctly
        # clf.predict accepts dataframe since we trained it on dataframe
        X_scaled_df = pd.DataFrame(X_scaled, columns=clf.feature_names[:41])

        # Predict - using X_scaled_df
        pred_class = int(clf.predict(X_scaled_df)[0])
        proba = clf.predict_proba(X_scaled_df)[0].tolist()

        # Anomaly score - using X_scaled
        anomaly = float(detector.get_anomaly_scores(X_scaled)[0])

        # Verdict (use 0.5 trust as default for single-connection API)
        verdict = VerdictEngine.assess(pred_class, anomaly, 0.5)

        # Top features
        fi = clf.get_feature_importance()
        top_feats = fi.head(5)['Feature'].tolist()

        return DetectResponse(
            prediction=CLASS_NAMES[pred_class],
            probability=[round(p, 4) for p in proba],
            anomaly_score=round(anomaly, 4),
            verdict_severity=verdict['severity'],
            verdict_reason=verdict['reason'],
            top_features=top_feats,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
