# 🛡️ NEXUS-IDS: Trust-Intelligence Driven Network Intrusion Detection System

[![Python Version](https://img.shields.io/badge/Python-3.10%20%7C%203.11-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![PyTorch](https://img.shields.io/badge/PyTorch-2.2.0-EE4C2C?logo=pytorch&logoColor=white)](https://pytorch.org/)
[![XGBoost](https://img.shields.io/badge/XGBoost-2.0.3-EB5424?logo=xgboost&logoColor=white)](https://xgboost.readthedocs.io/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.109.0-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.30.0-FF4B4B?logo=streamlit&logoColor=white)](https://streamlit.io/)
[![NetworkX](https://img.shields.io/badge/NetworkX-3.2.1-blue)](https://networkx.org/)
[![SHAP](https://img.shields.io/badge/Explainability-SHAP-brightgreen)](https://shap.readthedocs.io/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

> **Next-Generation Autonomous Intrusion Detection & Threat Intelligence Platform**  
> Blending Multi-Class Ensemble Machine Learning, PyTorch Autoencoder Anomaly Detection, Graph Topology Centrality Trust Scoring, SHAP Explainability, and a SOC-grade Streamlit Dashboard.

---

## 📌 Table of Contents
- [Executive Overview](#-executive-overview)
- [Key Features](#-key-features)
- [System Architecture](#-system-architecture)
- [Core Detection & Intelligence Layers](#-core-detection--intelligence-layers)
  - [1. Multi-Class Ensemble Detection Engine](#1-multi-class-ensemble-detection-engine)
  - [2. Deep Learning Anomaly Detection](#2-deep-learning-anomaly-detection)
  - [3. Graph Topology & Dynamic Trust Scoring](#3-graph-topology--dynamic-trust-scoring)
  - [4. SHAP Explainability & 4-Rule Verdict Engine](#4-shap-explainability--4-rule-verdict-engine)
- [Attack Classification Taxonomy](#-attack-classification-taxonomy)
- [SOC Command Center & Dashboard](#-soc-command-center--dashboard)
- [REST API Specifications](#-rest-api-specifications)
- [Project Directory Structure](#-project-directory-structure)
- [Installation & Quickstart](#-installation--quickstart)
- [CLI & Pipeline Execution](#-cli--pipeline-execution)
- [License & Acknowledgments](#-license--acknowledgments)

---

## 🛡️ Executive Overview

Modern enterprise networks face stealthy, polymorphic, and zero-day threats that bypass conventional rule-based signature detection. **NEXUS-IDS** provides defense-in-depth by synthesizing statistical machine learning, deep representation learning, and topological graph intelligence into a single unified SOC decision engine.

Instead of evaluating connections in complete isolation, NEXUS-IDS correlates connection-level anomaly scores with real-time network graph metrics (Betweenness and In-Degree centralities) to dynamically compute endpoint trust ratings, producing actionable, human-interpretable security verdicts backed by local SHAP attribution explanations.

---

## 🌟 Key Features

- **Soft-Voting Ensemble Classifier**: High-precision multi-class classification combining Random Forest (200 estimators) and XGBoost (200 estimators).
- **Dual-Model Anomaly Detection**: PyTorch symmetric deep Autoencoder (`41 → 64 → 32 → 16 → 32 → 64 → 41`) coupled with an Isolation Forest for zero-day discovery.
- **Topological Trust Intelligence**: NetworkX directed topology engine computing dynamic trust scores from centralities and anomaly signals.
- **Explainable AI (XAI)**: SHAP TreeExplainer quantifying exact feature attributions for every flagged attack.
- **Rule-Based Verdict Engine**: 4 deterministic severity rules synthesizing ML predictions, anomaly probabilities, and trust scores into incident actions (CRITICAL, HIGH, MEDIUM, LOW).
- **Enterprise SOC Dashboard**: Multi-page Streamlit security portal with real-time topology maps, threat timelines, radar plots, and interactive incident tickers.
- **Production REST API**: Scalable FastAPI inference server with input validation, unseen categorical label handling, and health probes.

---

## 🏛️ System Architecture

```text
                                  Incoming Network Traffic
                                             │
                                             ▼
                             [ Data Preprocessing & Scaling ]
                                             │
                      ┌──────────────────────┴──────────────────────┐
                      ▼                                             ▼
        [ Layer 1: Ensemble Classifier ]              [ Layer 2: Deep Anomaly Detector ]
        • Random Forest (200 trees)                   • PyTorch Symmetric Autoencoder
        • XGBoost (200 estimators)                    • Isolation Forest Outlier Scoring
        • Soft-Voting Multi-Class                     • Normalized Reconstruction Loss
                      │                                             │
                      └──────────────────────┬──────────────────────┘
                                             │
                                             ▼
                             [ Layer 3: Graph Intelligence ]
                             • NetworkX Topology Generation
                             • In-Degree & Betweenness Centrality
                             • Dynamic Trust Formulation (0.0 to 1.0)
                                             │
                                             ▼
                         [ Layer 4: Explainability & Verdict ]
                         • SHAP TreeExplainer Attributions
                         • 4-Tier Automated Security Verdicts
                                             │
                      ┌──────────────────────┴──────────────────────┐
                      ▼                                             ▼
            [ SOC Web Dashboard ]                          [ FastAPI REST Microservice ]
            • Topology Visualizer                          • POST /detect
            • Real-time Alert Feed                         • GET  /health
            • Threat Intelligence                          • High-Throughput Batch Engine
```

---

## 🔬 Core Detection & Intelligence Layers

### 1. Multi-Class Ensemble Detection Engine
- Combines `RandomForestClassifier` and `XGBClassifier` through a soft-voting ensemble (`VotingClassifier`).
- Generates 5-class class probability vectors over `[Normal, DoS, Probe, R2L, U2R]`.
- Trained on 41 standardized network connection features (protocol type, flags, service, duration, error rates, host counts).

### 2. Deep Learning Anomaly Detection
- **Autoencoder Architecture**: Symmetric compression and reconstruction:
  $$\text{Input}(41) \longrightarrow \text{Linear}(64) \longrightarrow \text{Linear}(32) \longrightarrow \text{Latent}(16) \longrightarrow \text{Linear}(32) \longrightarrow \text{Linear}(64) \longrightarrow \text{Output}(41)$$
  Equipped with `ReLU` activations and `BatchNorm1d` for stable training dynamics.
- **Isolation Forest**: Complements autoencoder reconstruction error to identify multivariate distribution outliers.
- Detects novel, zero-day patterns that traditional classifiers misclassify as benign.

### 3. Graph Topology & Dynamic Trust Scoring
Simulates endpoint communication graphs using NetworkX directed graphs ($G = (V, E)$). Each node $v$ represents an IP/endpoint profile. The trust score is dynamically formulated as:

$$\text{Trust}(v) = 0.5 \times (1 - \text{Anomaly}(v)) + 0.3 \times (1 - C_B(v)) + 0.2 \times (1 - C_{in}(v))$$

Where:
- $\text{Anomaly}(v)$: Min-max normalized reconstruction error and outlier score for node $v$.
- $C_B(v)$: Normalized Betweenness Centrality (identifies critical network bridges/chokepoints).
- $C_{in}(v)$: Normalized In-Degree Centrality (identifies heavily targeted or high-fan-in nodes).

| Trust Score | Status | Description | SOC Recommended Action |
| :---: | :---: | :---: | :--- |
| **$\ge 0.60$** | 🟢 **GREEN** | **Trusted Node** | Normal operations; routine logging. |
| **$0.30 - 0.59$** | 🟡 **AMBER** | **Suspicious Node** | Elevated telemetry; rate-limiting. |
| **$< 0.30$** | 🔴 **RED** | **Compromised Node** | Immediate quarantine; block ingress/egress. |

### 4. SHAP Explainability & 4-Rule Verdict Engine
Uses `shap.TreeExplainer` on the Random Forest ensemble component to compute local Shapley values, highlighting the exact features pushing the model towards an attack classification.

The **Verdict Engine** deterministically maps multi-model signals into operational priorities:
1. **CRITICAL**: ML detects attack **AND** ($\text{Anomaly} > 0.8$ **OR** $\text{Trust} < 0.3$). Confirmed high-impact compromise.
2. **HIGH**: ML classifies normal **BUT** $\text{Anomaly} > 0.8$. Zero-day warning; potential evasion attack.
3. **MEDIUM**: ML detects attack **AND** $\text{Anomaly} \le 0.8$ **AND** $\text{Trust} \ge 0.3$. Routine localized threat.
4. **LOW**: ML normal, low anomaly, trusted graph topology. Benign activity.

---

## 🎯 Attack Classification Taxonomy

NEXUS-IDS standardizes all NSL-KDD attack signatures into 5 canonical security classes:

| Class | Category Name | Included Attack Signatures |
| :---: | :--- | :--- |
| **0** | **Normal** | Legitimate, non-malicious network activity |
| **1** | **DoS (Denial of Service)** | `neptune`, `smurf`, `back`, `teardrop`, `pod`, `land`, `mailbomb`, `apache2`, `processtable`, `udpstorm` |
| **2** | **Probe (Reconnaissance)** | `ipsweep`, `portsweep`, `nmap`, `satan`, `mscan`, `saint` |
| **3** | **R2L (Remote to Local)** | `ftp_write`, `guess_passwd`, `imap`, `spy`, `phf`, `multihop`, `warezmaster`, `warezclient`, `snmpguess`, `snmpgetattack`, `httptunnel`, `sendmail`, `named`, `xlock`, `xsnoop`, `worm` |
| **4** | **U2R (User to Root)** | `buffer_overflow`, `loadmodule`, `perl`, `rootkit`, `sqlattack`, `xterm`, `ps` |

---

## 🖥️ SOC Command Center & Dashboard

The Streamlit-powered SOC interface is divided into modular operational workspaces:

1. **Overview / Command Center**: Real-time KPI summary cards, topological risk map, attack radar distributions, and live incident stream.
2. **Network Intelligence**: Dynamic 2D graph viewer showcasing green/amber/red nodes, degree distributions, and compromised node lists.
3. **Threat Analytics**: Granular drill-downs by attack family, protocol type breakdown (TCP, UDP, ICMP), service profiles, and flag patterns.
4. **AI Model Insights**: Global and local SHAP summary plots, confusion matrices, and ROC/PR curve analytics.
5. **Threat Prediction**: Live inference sandbox allowing analysts to inject custom connection records or upload CSVs for instant scoring.
6. **Security Events**: Historical SOC audit trail, timestamped incident logs, and filterable telemetry.
7. **System Configuration**: Fine-tune classification thresholds, trust scoring weights, and alert sensitivity limits.
8. **Data Management**: Dataset inspector for `KDDTrain+.csv` and `KDDTest+.csv`, schema validators, and data pipelines.

---

## 📡 REST API Specifications

NEXUS-IDS exposes an enterprise FastAPI service for inline microservice integration.

### `POST /detect`
Evaluates a single network connection.

**Request Schema:**
```json
{
  "features": [
    0, "tcp", "http", "SF", 181, 5450, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 8, 8, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 9, 9, 1.0, 0.0, 0.11, 0.0,
    0.0, 0.0, 0.0, 0.0
  ]
}
```

**Response Schema:**
```json
{
  "prediction": "normal",
  "probability": [0.985, 0.005, 0.004, 0.004, 0.002],
  "anomaly_score": 0.042,
  "verdict_severity": "LOW",
  "verdict_reason": "Traffic is benign. Network topology is trusted.",
  "top_features": ["src_bytes", "dst_bytes", "logged_in", "same_srv_rate", "count"]
}
```

### `GET /health`
System and model artifact status check.

**Response:**
```json
{
  "status": "ok",
  "model": "ensemble_v2",
  "models_loaded": true
}
```

---

## 📁 Project Directory Structure

```text
NEXUS-IDS/
├── .gitignore                      # Git ignore file for models, caches, and envs
├── README.md                       # Master documentation & project guide
├── KDD Train+.csv                  # NSL-KDD canonical training dataset
├── KDDTest+.csv                    # NSL-KDD canonical test dataset
└── nexus_ids/                      # Core application root
    ├── README.md                   # Module-level documentation
    ├── requirements.txt            # Pinned production dependencies
    ├── nexus_logs.log              # Real-time SOC event and audit log
    ├── nexus_report_20260314.pdf   # Generated analytical evaluation report
    ├── test_graph.png              # Rendered graph topology snapshot
    │
    ├── api/                        # FastAPI Inference Microservice
    │   └── server.py               # REST API endpoints (/detect, /health)
    │
    ├── dashboard/                  # Streamlit Multi-Page SOC Dashboard
    │   ├── app.py                  # Main entrypoint (Command Center Overview)
    │   ├── components/             # Reusable UI widgets
    │   │   ├── alert_feed.py       # Color-coded alert ticker
    │   │   ├── anomaly_scatter.py  # Anomaly score vs residual scatter
    │   │   ├── attack_fingerprint.py # Attack signature visualizer
    │   │   ├── event_stream.py     # Live socket event stream
    │   │   ├── header.py           # Top navigation bar & badges
    │   │   ├── heatmap.py          # Temporal attack correlation matrix
    │   │   ├── metric_cards.py     # SOC summary KPI cards
    │   │   ├── prediction_panels.py# Single & batch prediction cards
    │   │   ├── radar_chart.py      # 5-class threat polar distribution
    │   │   ├── shap_panel.py       # SHAP feature importance charts
    │   │   ├── sidebar_nav.py      # Collapsible navigation drawer
    │   │   ├── soc_logger.py       # Rotating log file integration
    │   │   ├── theme.py            # Dark-mode SOC CSS styles
    │   │   ├── timeline.py         # Threat activity timeline
    │   │   └── topology_map.py     # Interactive NetworkX trust topology
    │   └── pages/                  # Multipage dashboard tabs
    │       ├── 2_Network_Intelligence.py
    │       ├── 3_Threat_Analytics.py
    │       ├── 4_AI_Model_Insights.py
    │       ├── 5_Threat_Prediction.py
    │       ├── 6_Security_Events.py
    │       ├── 7_System_Configuration.py
    │       └── 8_Data_Management.py
    │
    ├── data/                       # Local dataset caches
    │   ├── raw/                    # Cached training and testing CSVs
    │   └── processed/              # Preprocessed numpy/pickle tensors
    │
    ├── demo/                       # Live presentation demonstration
    │   └── run_demo.py             # Hackathon / live evaluator runner
    │
    ├── graph_engine/               # Topological Graph & Trust Scoring
    │   ├── network_graph.py        # NetworkX directed graph builder
    │   └── trust_scoring.py        # Trust score formula and centrality logic
    │
    ├── models/                     # Serialized AI model artifacts
    │   ├── autoencoder.pt          # PyTorch trained autoencoder weights
    │   ├── ensemble.pkl            # Trained RF + XGBoost VotingClassifier
    │   ├── encoders.pkl            # LabelEncoder mappings for categoricals
    │   └── scaler.pkl              # StandardScaler parameters for 41 features
    │
    ├── src/                        # Machine Learning and Core Pipelines
    │   ├── anomaly_detector.py     # Autoencoder & Isolation Forest engines
    │   ├── data_loader.py          # NSL-KDD data ingestion & synthetic generator
    │   ├── explainability.py       # SHAP TreeExplainer & Verdict Engine
    │   ├── ml_classifier.py        # Ensemble classifier pipeline
    │   ├── preprocessing.py        # Normalization, encoding, label mapping
    │   └── trust_model.py          # Trust Intelligence orchestrator
    │
    └── tests/                      # Testing & Quality Assurance
        └── test_pipeline.py        # End-to-end integration test runner
```

---

## ⚡ Installation & Quickstart

### Prerequisites
- **Python**: 3.10, 3.11, or 3.12
- **Hardware**: CPU supported; CUDA-capable GPU recommended for high-volume Autoencoder training.

### 1. Clone the Repository
```bash
git clone https://github.com/Rakshan25-Kaizen/NEXUS-IDS.git
cd NEXUS-IDS
```

### 2. Set Up a Virtual Environment
```bash
# Windows
python -m venv venv
.\venv\Scripts\activate

# Linux / macOS
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies
```bash
cd nexus_ids
pip install --upgrade pip
pip install -r requirements.txt
```

### 4. Launch the SOC Command Center Dashboard
```bash
python -m streamlit run dashboard/app.py
```
> The dashboard will automatically launch at `http://localhost:8501`. On first run, it verifies all artifacts and caches preprocessed splits.

### 5. Launch the REST API Inference Server
```bash
python api/server.py
```
> The API server starts on `http://localhost:8000`. Navigate to `http://localhost:8000/docs` to interact with the OpenAPI / Swagger documentation.

---

## 🧪 CLI & Pipeline Execution

Every component in `nexus_ids/src/` and `nexus_ids/demo/` can be executed independently from the command line:

```bash
cd nexus_ids

# 1. Run the Live Demo (Evaluator Script)
python demo/run_demo.py

# 2. Run End-to-End Pipeline Integration Test
python tests/test_pipeline.py

# 3. Test Ingestion and Dataset Statistics
python src/data_loader.py --dataset train

# 4. Run Preprocessing Pipeline
python src/preprocessing.py --save

# 5. Train & Evaluate Ensemble Classifier
python src/ml_classifier.py --train --save

# 6. Train & Evaluate PyTorch Autoencoder
python src/anomaly_detector.py --train --save

# 7. Test SHAP Explanations & Verdict Rules
python src/explainability.py
```

---

## 📄 License & Acknowledgments

- **Dataset**: NSL-KDD dataset courtesy of the Canadian Institute for Cybersecurity (CIC), University of New Brunswick.
- **License**: Released under the [MIT License](LICENSE).

---

<p align="center">
  <b>NEXUS-IDS</b> • Developed by <a href="https://github.com/Rakshan25-Kaizen">Rakshan25-Kaizen</a> • 2026
</p>
