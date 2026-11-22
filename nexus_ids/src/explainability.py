"""
explainability.py — NEXUS-IDS Explainable AI Engine

1. SHAP (SHapley Additive exPlanations): Explains which features drove
   the ML classification using TreeExplainer on the Random Forest output.
2. Verdict Engine: 4 specific threshold rules combining ML prediction,
   deep learning anomaly scores, and graph trust scores into human sentences.
"""

import numpy as np
import pandas as pd
import shap
from pathlib import Path


class SHAPExplainer:
    """
    Wraps shap.TreeExplainer to extract local feature attributions
    from the RandomForest component of the ensemble.
    """

    def __init__(self, ensemble_model, feature_names: list):
        # We must extract the Random Forest specifically as VotingClassifier
        # isn't directly supported by TreeExplainer.
        self.rf_model = ensemble_model.named_estimators_.get('rf')
        if not self.rf_model:
            raise ValueError("VotingClassifier missing 'rf' estimator for SHAP.")
        
        self.feature_names = feature_names
        # Note: TreeExplainer is fast but approximate depending on tree depth
        self.explainer = shap.TreeExplainer(self.rf_model)

    def explain_instance(self, X_instance: np.ndarray, top_n: int = 5) -> dict:
        """
        Explains a single network connection prediction.
        
        Args:
            X_instance: 1D array or 1-row DataFrame of shape (1, 41).
            top_n: Number of top contributing features to return.
            
        Returns:
            Dict mapping feature_name -> shap_value (positive = pushed toward attack).
        """
        if isinstance(X_instance, pd.DataFrame):
            X_instance = X_instance.values
        if len(X_instance.shape) == 1:
            X_instance = X_instance.reshape(1, -1)
            
        # shap_values shape for multi-class: list of arrays (one per class)
        # We look at the 'normal' class (index 0) and invert it,
        # so positive values indicate evidence OF AN ATTACK.
        shap_values = self.explainer.shap_values(X_instance)
        
        if isinstance(shap_values, list):
            # scikit-learn RF usually returns a list
            attack_contributions = -shap_values[0][0] 
        else:
            # Depending on SHAP version / model, it might be a 3D array
            attack_contributions = -shap_values[0, :, 0]

        # Pair features with their SHAP values
        feature_impacts = {
            feat: float(val) 
            for feat, val in zip(self.feature_names, attack_contributions)
        }
        
        # Sort by absolute magnitude to find most impactful
        sorted_impacts = sorted(
            feature_impacts.items(), 
            key=lambda x: abs(x[1]), 
            reverse=True
        )
        
        return dict(sorted_impacts[:top_n])

    def explain_batch(self, X_batch: np.ndarray, top_n: int = 10) -> pd.DataFrame:
        """
        Computes mean absolute SHAP values across a batch for a global view.
        Returns a DataFrame ready for the dashboard.
        """
        if isinstance(X_batch, pd.DataFrame):
            X_batch = X_batch.values
            
        shap_values = self.explainer.shap_values(X_batch)
        
        if isinstance(shap_values, list):
            # Average absolute impact on the 'normal' class
            global_impacts = np.mean(np.abs(shap_values[0]), axis=0)
        else:
            global_impacts = np.mean(np.abs(shap_values[:, :, 0]), axis=0)
            
        df = pd.DataFrame({
            'Feature': self.feature_names,
            'Mean_Absolute_SHAP': global_impacts
        }).sort_values('Mean_Absolute_SHAP', ascending=False).reset_index(drop=True)
        
        return df.head(top_n)


class VerdictEngine:
    """
    Generates human-readable severity assessments using 4 rigid rules.
    """

    CLASS_NAMES = ['normal', 'dos', 'probe', 'r2l', 'u2r']

    @staticmethod
    def assess(pred_class: int, anomaly_score: float, trust_score: float) -> dict:
        """
        Evaluates a single connection against the 4 verdict rules.
        
        Args:
            pred_class: 0 (Normal) to 4 (U2R).
            anomaly_score: Autoencoder anomaly score [0, 1].
            trust_score: Graph node trust score [0, 1].
            
        Returns:
            Dict containing 'severity' and 'reason'.
        """
        is_attack = pred_class != 0
        attack_name = VerdictEngine.CLASS_NAMES[pred_class].upper()

        # Rule 1: CRITICAL
        # ML flags attack AND (anomaly > 0.8 OR trust < 0.3)
        if is_attack and (anomaly_score > 0.8 or trust_score < 0.3):
            return {
                "severity": "CRITICAL",
                "reason": f"Confirmed {attack_name} attack with severe graph compromise (Trust: {trust_score:.2f}) or extreme anomaly ({anomaly_score:.2f})."
            }
            
        # Rule 2: HIGH
        # ML normal BUT anomaly > 0.8 (Zero-day warning)
        if not is_attack and anomaly_score > 0.8:
            return {
                "severity": "HIGH",
                "reason": f"ML reports normal, but deep learning flags severe anomaly ({anomaly_score:.2f}). Possible zero-day."
            }
            
        # Rule 3: MEDIUM
        # ML flags attack BUT anomaly and trust are acceptable
        if is_attack and anomaly_score <= 0.8 and trust_score >= 0.3:
            return {
                "severity": "MEDIUM",
                "reason": f"Routine {attack_name} detected. Graph is stable, anomaly is low."
            }
            
        # Rule 4: LOW
        # ML normal, everything stable
        return {
            "severity": "LOW",
            "reason": "Traffic is benign. Network topology is trusted."
        }

    @staticmethod
    def batch_assess(predictions: np.ndarray, anomaly_scores: np.ndarray, 
                     trust_scores: np.ndarray) -> list:
        """Runs the assessment across an entire batch of arrays."""
        verdicts = []
        for i in range(len(predictions)):
            v = VerdictEngine.assess(
                int(predictions[i]), 
                float(anomaly_scores[i]), 
                float(trust_scores[i])
            )
            v['index'] = i 
            v['attack_type'] = VerdictEngine.CLASS_NAMES[int(predictions[i])]
            verdicts.append(v)
        return verdicts


if __name__ == "__main__":
    # Demo for explainability
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from data_loader import load_dataset
    from preprocessing import preprocess_pipeline
    from ml_classifier import EnsembleClassifier
    
    # 1. Load data
    df = load_dataset("test")
    res = preprocess_pipeline(df, fit=False, tag="test_exp")
    
    # 2. Get trained model
    clf = EnsembleClassifier()
    if not clf.load():
        print("[!] Train the model first via: python src/ml_classifier.py --train --save")
        sys.exit(1)
        
    # 3. Get single attack instance
    X = res["X"]
    y = res["y"]
    attack_idx = np.where(y != 0)[0][0]
    sample = X.iloc[[attack_idx]]
    pred = int(clf.predict(sample)[0])
    
    print("\n" + "="*50)
    print(f" DEMO: EXPLAINING RECORD #{attack_idx} (True: {y[attack_idx]}, Pred: {pred})")
    print("="*50)
    
    # SHAP
    print("\nEvaluating SHAP TreeExplainer...")
    explainer = SHAPExplainer(clf.ensemble, res["feature_names"])
    impacts = explainer.explain_instance(sample)
    
    print("\nTop Features Driving Attack Prediction (SHAP Values):")
    for feat, val in impacts.items():
        print(f"  {feat:<25}: {val:+.4f}")
        
    # Verdict Engine
    print("\nEvaluating Verdict Logic...")
    # Simulate high anomaly and low trust to trigger CRITICAL
    v = VerdictEngine.assess(pred_class=pred, anomaly_score=0.85, trust_score=0.2)
    print(f"Severity : {v['severity']}")
    print(f"Reason   : {v['reason']}")
    print("="*50)
