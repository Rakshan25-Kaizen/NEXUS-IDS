"""
soc_logger.py — NEXUS-IDS SOC: Centralized Logging Engine

Provides a singleton logger that writes structured SOC events
to nexus_logs.log and exposes them for dashboard display.
"""

import logging
import os
from pathlib import Path
from datetime import datetime

LOG_DIR = Path(__file__).resolve().parent.parent.parent  # nexus_ids/
LOG_FILE = LOG_DIR / "nexus_logs.log"

# ── Configure logger ──────────────────────────────────────────────────
_logger = logging.getLogger("NEXUS_SOC")
_logger.setLevel(logging.INFO)
_logger.propagate = False

if not _logger.handlers:
    fh = logging.FileHandler(str(LOG_FILE), mode='a', encoding='utf-8')
    fh.setLevel(logging.INFO)
    fh.setFormatter(logging.Formatter("[%(asctime)s] %(message)s", datefmt="%H:%M:%S"))
    _logger.addHandler(fh)


def log_event(message: str, level: str = "INFO"):
    """Log a SOC event."""
    if level == "WARNING":
        _logger.warning(message)
    elif level == "ERROR":
        _logger.error(message)
    elif level == "CRITICAL":
        _logger.critical(message)
    else:
        _logger.info(message)


def log_inference(n_records: int):
    log_event(f"Model inference executed on {n_records:,} records")

def log_anomaly(node: str, attack_type: str, score: float):
    log_event(f"{attack_type.upper()} anomaly detected on node {node} (score={score:.4f})", "WARNING")

def log_trust_update(node: str, old_score: float, new_score: float):
    log_event(f"Node {node} trust score updated: {old_score:.3f} → {new_score:.3f}")

def log_incident(severity: str, node: str, attack_type: str):
    log_event(f"Incident created — severity: {severity}, node: {node}, type: {attack_type}", "WARNING")

def log_dataset_upload(filename: str, n_rows: int):
    log_event(f"Dataset uploaded: {filename} ({n_rows:,} rows)")

def log_model_retrain(model_name: str, accuracy: float):
    log_event(f"Model retrained: {model_name} — accuracy: {accuracy:.4f}")

def log_prediction(horizon: str, threat_level: float):
    log_event(f"Threat prediction [{horizon}]: threat_level={threat_level:.3f}")

def log_system(message: str):
    log_event(f"SYSTEM: {message}")


def get_recent_logs(n: int = 50) -> str:
    """Read the last n lines from the log file."""
    if not LOG_FILE.exists():
        return "[No logs yet]"
    try:
        with open(LOG_FILE, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        return "".join(lines[-n:])
    except Exception as e:
        return f"[Error reading logs: {e}]"


def clear_logs():
    """Clear the log file."""
    if LOG_FILE.exists():
        with open(LOG_FILE, 'w', encoding='utf-8') as f:
            f.write("")
        log_event("Log file cleared by user")


# ── Generate bootstrap logs on first import ───────────────────────────
if not LOG_FILE.exists() or LOG_FILE.stat().st_size == 0:
    log_system("NEXUS-IDS SOC Platform initialized")
    log_system("Detection pipeline: RF + Autoencoder + Trust Engine")
    log_system("Models loaded successfully")
    log_event("System ready — awaiting analysis")
