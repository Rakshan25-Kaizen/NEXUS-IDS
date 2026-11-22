"""
anomaly_detector.py — NEXUS-IDS Deep Learning Anomaly Detection

Implements a combination of a PyTorch Autoencoder and Isolation Forest.
The Autoencoder learns normal traffic patterns (reconstruction error threshold).
Isolation Forest detects outliers based on feature distributions.
The final anomaly score combines both signals to catch zero-day attacks.
"""

import numpy as np
import pandas as pd
from pathlib import Path
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import MinMaxScaler
import joblib

PROJECT_ROOT = Path(__file__).resolve().parent.parent
MODELS_DIR = PROJECT_ROOT / "models"


class Autoencoder(nn.Module):
    """
    Symmetric autoencoder for network traffic anomaly detection.
    Architecture: Input(41) → 64 → 32 → 16 → 32 → 64 → Output(41)
    """

    def __init__(self, input_dim: int = 41):
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 64),
            nn.ReLU(),
            nn.BatchNorm1d(64),
            nn.Linear(64, 32),
            nn.ReLU(),
            nn.BatchNorm1d(32),
            nn.Linear(32, 16),
            nn.ReLU(),
        )
        self.decoder = nn.Sequential(
            nn.Linear(16, 32),
            nn.ReLU(),
            nn.BatchNorm1d(32),
            nn.Linear(32, 64),
            nn.ReLU(),
            nn.BatchNorm1d(64),
            nn.Linear(64, input_dim),
        )

    def forward(self, x):
        encoded = self.encoder(x)
        decoded = self.decoder(encoded)
        return decoded


class AnomalyDetector:
    """
    Wraps Autoencoder & Isolation Forest to create a robust,
    combined anomaly scoring engine.
    """

    def __init__(self, input_dim: int = 41, epochs: int = 50,
                 batch_size: int = 256, lr: float = 1e-3):
        # Autoencoder
        self.input_dim = input_dim
        self.epochs = epochs
        self.batch_size = batch_size
        self.lr = lr
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        self.ae_model = Autoencoder(input_dim).to(self.device)
        self.ae_threshold = 0.0

        # Isolation Forest
        self.if_model = IsolationForest(
            n_estimators=100,
            contamination=0.1,  # Assume ~10% anomalies in unlabeled data
            random_state=42,
            n_jobs=-1
        )
        
        # Scaling for the combined score
        self.score_scaler = MinMaxScaler()
        self.is_trained = False

    def train(self, X_train: np.ndarray, X_val: np.ndarray = None):
        """
        Trains both the Autoencoder and Isolation Forest.
        Autoencoder should ideally be trained on mostly normal traffic.

        Args:
            X_train: Training features.
            X_val: Validation features (used for AE threshold).
        """
        if isinstance(X_train, pd.DataFrame):
            X_train = X_train.values
        if X_val is not None and isinstance(X_val, pd.DataFrame):
            X_val = X_val.values

        print(f"[*] Training Autoencoder ({self.epochs} epochs, device={self.device}) ...")
        
        # 1. Train Autoencoder
        train_tensor = torch.FloatTensor(X_train).to(self.device)
        train_dataset = TensorDataset(train_tensor, train_tensor)
        train_loader = DataLoader(train_dataset, batch_size=self.batch_size, shuffle=True)

        criterion = nn.MSELoss()
        optimizer = torch.optim.Adam(self.ae_model.parameters(), lr=self.lr)

        self.ae_model.train()
        for epoch in range(self.epochs):
            total_loss = 0
            for batch_x, _ in train_loader:
                optimizer.zero_grad()
                output = self.ae_model(batch_x)
                loss = criterion(output, batch_x)
                loss.backward()
                optimizer.step()
                total_loss += loss.item()

            if (epoch + 1) % 10 == 0 or epoch == 0:
                avg_loss = total_loss / len(train_loader)
                print(f"    AE Epoch {epoch+1}/{self.epochs} — Loss: {avg_loss:.6f}")

        # Compute AE threshold
        if X_val is not None:
            val_errors = self._compute_reconstruction_errors(X_val)
            self.ae_threshold = float(np.mean(val_errors) + 2 * np.std(val_errors))
        else:
            train_errors = self._compute_reconstruction_errors(X_train)
            self.ae_threshold = float(np.mean(train_errors) + 2 * np.std(train_errors))
            
        print(f"[✓] Autoencoder trained. Threshold: {self.ae_threshold:.6f}")

        # 2. Train Isolation Forest
        print("[*] Training Isolation Forest...")
        self.if_model.fit(X_train)
        print("[✓] Isolation Forest trained.")

        # 3. Fit scaler for combined anomaly score
        print("[*] Calibrating combined anomaly scores...")
        train_ae_scores = self._compute_reconstruction_errors(X_train)
        train_if_scores = -self.if_model.score_samples(X_train) # Convert to positive = more anomalous
        
        combined_scores = (train_ae_scores + train_if_scores).reshape(-1, 1)
        self.score_scaler.fit(combined_scores)

        self.is_trained = True
        print("[✓] Anomaly Detector fully trained.")

    def _compute_reconstruction_errors(self, X: np.ndarray) -> np.ndarray:
        """Computes Autoencoder MSE reconstruction error."""
        self.ae_model.eval()
        with torch.no_grad():
            tensor = torch.FloatTensor(X).to(self.device)
            output = self.ae_model(tensor)
            errors = torch.mean((tensor - output) ** 2, dim=1).cpu().numpy()
        return errors

    def get_anomaly_scores(self, X: np.ndarray) -> np.ndarray:
        """
        Returns normalized combined anomaly scores in range [0, 1].
        Combines Autoencoder MSE and Isolation Forest outlier score.
        """
        if not self.is_trained:
            raise RuntimeError("AnomalyDetector must be trained first.")
            
        if isinstance(X, pd.DataFrame):
            X = X.values
            
        # AE Score (MSE)
        ae_errors = self._compute_reconstruction_errors(X)
        
        # IF Score (Invert so higher = more anomalous)
        if_scores = -self.if_model.score_samples(X)
        
        # Combine and scale
        combined = (ae_errors + if_scores).reshape(-1, 1)
        scaled_scores = self.score_scaler.transform(combined).flatten()
        
        # Clip strictly between 0 and 1
        return np.clip(scaled_scores, 0.0, 1.0)

    def predict(self, X: np.ndarray) -> np.ndarray:
        """
        Binary prediction based purely on AE threshold.
        Returns 1 for anomaly, 0 for normal.
        """
        if isinstance(X, pd.DataFrame):
            X = X.values
        errors = self._compute_reconstruction_errors(X)
        return (errors > self.ae_threshold).astype(int)

    def save(self, path: str = None):
        """Saves models and parameters."""
        MODELS_DIR.mkdir(parents=True, exist_ok=True)
        if path is None:
            path = MODELS_DIR / "anomaly_detector.pt"
            
        state = {
            'ae_state_dict': self.ae_model.state_dict(),
            'ae_threshold': self.ae_threshold,
            'input_dim': self.input_dim,
            'if_model': self.if_model,
            'score_scaler': self.score_scaler
        }
        torch.save(state, path)
        print(f"[✓] Anomaly detector saved to {path}")

    def load(self, path: str = None) -> bool:
        """Loads trained models."""
        if path is None:
            path = MODELS_DIR / "anomaly_detector.pt"
            
        if Path(path).exists():
            checkpoint = torch.load(path, map_location=self.device, weights_only=False)
            self.input_dim = checkpoint['input_dim']
            self.ae_model = Autoencoder(self.input_dim).to(self.device)
            self.ae_model.load_state_dict(checkpoint['ae_state_dict'])
            self.ae_threshold = checkpoint['ae_threshold']
            self.if_model = checkpoint['if_model']
            self.score_scaler = checkpoint['score_scaler']
            self.is_trained = True
            print(f"[✓] Anomaly detector loaded from {path}")
            return True
        return False


if __name__ == "__main__":
    import argparse
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from data_loader import load_dataset
    from preprocessing import preprocess_pipeline

    parser = argparse.ArgumentParser(description="NEXUS-IDS Anomaly Detector")
    parser.add_argument("--train", action="store_true")
    parser.add_argument("--save", action="store_true")
    args = parser.parse_args()

    if args.train:
        train_df = load_dataset("train")
        result = preprocess_pipeline(train_df, fit=True, tag="train")

        # Train on mostly normal traffic for optimal AE convergence
        normal_mask = result["y"] == 0
        X_normal = result["X"][normal_mask].values
        
        # Split normal into 80% train, 20% val
        split = int(0.8 * len(X_normal))
        X_train_ae = X_normal[:split]
        X_val_ae = X_normal[split:]

        detector = AnomalyDetector(input_dim=X_train_ae.shape[1])
        detector.train(X_train_ae, X_val_ae)

        if args.save:
            detector.save()
