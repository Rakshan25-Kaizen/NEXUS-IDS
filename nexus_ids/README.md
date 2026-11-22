# NEXUS-IDS: Trust-Intelligence Driven Network Intrusion Detection System

> AI-powered network intrusion detection with graph-based trust modelling,
> SHAP explainability, and a SOC-grade security dashboard.

---

## 🛡️ Overview

NEXUS-IDS is a 3-layer AI pipeline for detecting and classifying malicious
network traffic using the NSL-KDD dataset:

| Layer | Technology | Purpose |
|-------|-----------|---------|
| **Detection Engine** | Random Forest + XGBoost Ensemble | 5-class traffic classification |
| **Anomaly Detection** | PyTorch Autoencoder (41→64→32→16→32→64→41) | Zero-day / unknown attack detection |
| **Trust Intelligence** | NetworkX Graph + Centrality Scoring | Per-node trust assessment |
| **Explainability** | SHAP TreeExplainer + 4-Rule Verdict Engine | Human-readable threat explanations |

### Attack Classification (5 Classes)
- **Normal** — Benign traffic
- **DoS** — Denial of Service (neptune, smurf, back, teardrop, pod, land...)
- **Probe** — Reconnaissance (ipsweep, portsweep, nmap, satan)
- **R2L** — Remote to Local (ftp_write, guess_passwd, imap, spy...)
- **U2R** — User to Root (buffer_overflow, loadmodule, perl, rootkit)

---

## 📁 Project Structure

```
nexus_ids/
├── data/raw/               ← KDDTrain+.csv, KDDTest+.csv (auto-downloaded)
├── data/processed/          ← Serialized train/test splits
├── models/                  ← Saved model weights
├── src/
│   ├── data_loader.py       ← Dataset acquisition & validation
│   ├── preprocessing.py     ← Encoding, scaling, label mapping
│   ├── ml_classifier.py     ← RF + XGBoost ensemble classifier
│   ├── anomaly_detector.py  ← PyTorch autoencoder
│   ├── trust_model.py       ← Trust intelligence orchestrator
│   └── explainability.py    ← SHAP explanations + verdict engine
├── graph_engine/
│   ├── network_graph.py     ← NetworkX topology builder
│   └── trust_scoring.py     ← Trust score formula implementation
├── dashboard/
│   ├── app.py               ← Main Streamlit SOC dashboard
│   └── components/
│       ├── topology_map.py  ← Network trust visualization
│       ├── timeline.py      ← Threat activity timeline
│       ├── shap_panel.py    ← AI explanation panel
│       ├── radar_chart.py   ← Threat distribution radar
│       └── alert_feed.py    ← Colour-coded alert ticker
├── api/server.py            ← FastAPI inference endpoint
├── requirements.txt
└── README.md
```

---

## 🚀 Setup & Installation

### Prerequisites
- Python 3.10 or higher
- pip package manager

### 1. Install Dependencies
```bash
cd nexus_ids
pip install -r requirements.txt
```

### 2. Run the Dashboard
```bash
python -m streamlit run dashboard/app.py
```

The dashboard will:
1. Automatically download the NSL-KDD dataset (or generate synthetic data)
2. Train the ensemble classifier and autoencoder on first run
3. Cache all models for instant reloads on subsequent runs

### 3. Run the API Server (Optional)
```bash
python api/server.py
```
API available at `http://localhost:8000` — see `/docs` for Swagger UI.

---

## 🖥️ Dashboard Panels

| Panel | Description |
|-------|-------------|
| **Network Trust Map** | Interactive graph visualization with trust-coloured nodes (green/amber/red) |
| **Threat Timeline** | Attack activity over simulated time windows, split by class |
| **SHAP Explainability** | Top features driving each prediction, colour-coded by contribution |
| **Threat Radar** | Polar chart showing 5-class distribution |
| **Alert Feed** | Scrollable severity-coded alerts (CRITICAL → LOW) |

---

## 🔬 Trust Score Formula

```
trust(v) = 0.5 × (1 - normalized_anomaly_score)
         + 0.3 × (1 - normalized_betweenness_centrality)
         + 0.2 × (1 - normalized_in_degree_centrality)
```

| Score | Level | Meaning |
|-------|-------|---------|
| ≥ 0.6 | 🟢 GREEN | Trusted node |
| ≥ 0.3 | 🟡 AMBER | Suspicious — monitor |
| < 0.3 | 🔴 RED | Compromised — investigate |

---

## 📡 API Endpoints

### `POST /detect`
```json
{
  "features": [0.0, 0.1, 0.2, ..., 0.4]  // 41 float values
}
```
**Response:**
```json
{
  "prediction": "dos",
  "probability": [0.05, 0.85, 0.05, 0.03, 0.02],
  "anomaly_score": 0.72,
  "verdict_severity": "HIGH",
  "verdict_reason": "Detected DOS attack pattern with anomaly score 0.72.",
  "top_features": ["src_bytes", "dst_bytes", "serror_rate", "count", "srv_count"]
}
```

### `GET /health`
```json
{ "status": "ok", "model": "ensemble_v2" }
```

---

## 🧪 Running Individual Modules

```bash
# Data loader
python src/data_loader.py --dataset train

# Preprocessing (with save)
python src/preprocessing.py --save

# Train classifier
python src/ml_classifier.py --train --save

# Train anomaly detector
python src/anomaly_detector.py --train --save

# Test explainability
python src/explainability.py
```

---

## 📊 Technologies

| Category | Stack |
|----------|-------|
| ML Classification | scikit-learn, XGBoost |
| Deep Learning | PyTorch |
| Graph Analysis | NetworkX |
| Explainability | SHAP |
| Dashboard | Streamlit, Plotly |
| API | FastAPI, Uvicorn |
| Data | Pandas, NumPy |

---

*NEXUS-IDS © 2026 — Trust-Intelligence Driven Network Intrusion Detection*
