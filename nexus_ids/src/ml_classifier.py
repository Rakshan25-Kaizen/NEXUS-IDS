"""
ml_classifier.py — NEXUS-IDS Machine Learning Detection Engine

Implements a RandomForest + XGBoost soft-voting ensemble classifier
for 5-class network intrusion detection.
"""

import numpy as np
import pandas as pd
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.metrics import (accuracy_score, precision_score, recall_score,
                             f1_score, confusion_matrix, classification_report)
from xgboost import XGBClassifier
import joblib

PROJECT_ROOT = Path(__file__).resolve().parent.parent
MODELS_DIR = PROJECT_ROOT / "models"
CLASS_NAMES = ['normal', 'dos', 'probe', 'r2l', 'u2r']


class EnsembleClassifier:
    """
    Soft-voting ensemble of RandomForest and XGBoost for multi-class
    network intrusion detection.
    """

    def __init__(self):
        self.rf = RandomForestClassifier(
            n_estimators=200, max_depth=20,
            n_jobs=-1, random_state=42
        )
        self.xgb = XGBClassifier(
            n_estimators=200, max_depth=8,
            learning_rate=0.1, eval_metric='mlogloss',
            random_state=42, use_label_encoder=False,
            verbosity=0
        )
        self.ensemble = VotingClassifier(
            estimators=[('rf', self.rf), ('xgb', self.xgb)],
            voting='soft'
        )
        self.is_trained = False
        self.metrics = {}
        self.feature_names = []

    def train(self, X_train: pd.DataFrame, y_train: np.ndarray,
              X_test: pd.DataFrame = None, y_test: np.ndarray = None) -> dict:
        """
        Trains the ensemble classifier and evaluates on test set if provided.

        Args:
            X_train: Training feature matrix.
            y_train: Training labels.
            X_test: Optional test feature matrix.
            y_test: Optional test labels.

        Returns:
            Dictionary of evaluation metrics.
        """
        self.feature_names = list(X_train.columns)
        print("[*] Training Ensemble Detection Engine (RF + XGBoost) ...")

        self.ensemble.fit(X_train, y_train)
        self.is_trained = True
        print("[✓] Ensemble training complete.")

        if X_test is not None and y_test is not None:
            self.metrics = self.evaluate(X_test, y_test)

        return self.metrics

    def evaluate(self, X_test: pd.DataFrame, y_test: np.ndarray) -> dict:
        """
        Evaluates the model on test data.

        Args:
            X_test: Test feature matrix.
            y_test: True labels.

        Returns:
            Metrics dictionary.
        """
        y_pred = self.ensemble.predict(X_test)
        y_proba = self.ensemble.predict_proba(X_test)

        metrics = {
            "accuracy": round(accuracy_score(y_test, y_pred) * 100, 2),
            "precision": round(precision_score(y_test, y_pred, average='weighted', zero_division=0) * 100, 2),
            "recall": round(recall_score(y_test, y_pred, average='weighted', zero_division=0) * 100, 2),
            "f1_score": round(f1_score(y_test, y_pred, average='weighted', zero_division=0) * 100, 2),
            "confusion_matrix": confusion_matrix(y_test, y_pred),
            "class_names": CLASS_NAMES,
            "y_pred": y_pred,
            "y_proba": y_proba,
            "classification_report": classification_report(y_test, y_pred, target_names=CLASS_NAMES, zero_division=0),
        }
        print(f"[✓] Evaluation — Accuracy: {metrics['accuracy']}% | F1: {metrics['f1_score']}%")
        return metrics

    def predict(self, X: pd.DataFrame) -> np.ndarray:
        """
        Predicts class labels for input features.

        Args:
            X: Feature matrix.

        Returns:
            Predicted class indices.
        """
        if not self.is_trained:
            raise RuntimeError("Model must be trained before prediction.")
        return self.ensemble.predict(X)

    def predict_proba(self, X: pd.DataFrame) -> np.ndarray:
        """
        Returns class probabilities for input features.

        Args:
            X: Feature matrix.

        Returns:
            Probability matrix (n_samples x n_classes).
        """
        if not self.is_trained:
            raise RuntimeError("Model must be trained before prediction.")
        return self.ensemble.predict_proba(X)

    def get_feature_importance(self) -> pd.DataFrame:
        """
        Extracts feature importances from the Random Forest sub-model.

        Returns:
            DataFrame sorted by importance descending.
        """
        if not self.is_trained:
            raise RuntimeError("Model must be trained first.")
        rf_model = self.ensemble.named_estimators_['rf']
        importances = rf_model.feature_importances_
        fi_df = pd.DataFrame({
            'Feature': self.feature_names,
            'Importance': importances
        }).sort_values('Importance', ascending=False).reset_index(drop=True)
        return fi_df

    def save(self, path: str = None):
        """Saves the ensemble model to disk."""
        if path is None:
            MODELS_DIR.mkdir(parents=True, exist_ok=True)
            path = MODELS_DIR / "ensemble.pkl"
        joblib.dump({
            'ensemble': self.ensemble,
            'metrics': self.metrics,
            'feature_names': self.feature_names,
        }, path)
        print(f"[✓] Ensemble model saved to {path}")

    def load(self, path: str = None) -> bool:
        """Loads a trained ensemble model from disk."""
        if path is None:
            path = MODELS_DIR / "ensemble.pkl"
        if Path(path).exists():
            data = joblib.load(path)
            self.ensemble = data['ensemble']
            self.metrics = data['metrics']
            self.feature_names = data['feature_names']
            self.is_trained = True
            print(f"[✓] Ensemble model loaded from {path}")
            return True
        return False


if __name__ == "__main__":
    import argparse
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from data_loader import load_dataset
    from preprocessing import preprocess_pipeline

    parser = argparse.ArgumentParser(description="NEXUS-IDS ML Classifier")
    parser.add_argument("--train", action="store_true")
    parser.add_argument("--save", action="store_true")
    parser.add_argument("--evaluate", action="store_true")
    args = parser.parse_args()

    if args.train or args.evaluate:
        train_df = load_dataset("train")
        train_res = preprocess_pipeline(train_df, fit=True, tag="train")

        test_df = load_dataset("test")
        test_res = preprocess_pipeline(
            test_df, fit=False,
            encoders=train_res["encoders"],
            scaler=train_res["scaler"],
            tag="test"
        )

        clf = EnsembleClassifier()
        metrics = clf.train(
            train_res["X"], train_res["y"],
            test_res["X"], test_res["y"]
        )

        print(f"\n{metrics['classification_report']}")

        if args.save:
            clf.save()
