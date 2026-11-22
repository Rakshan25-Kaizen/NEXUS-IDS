"""
trust_model.py — NEXUS-IDS Trust Intelligence Orchestrator

Ties together the graph building and trust scoring modules into a cohesive
Trust Intelligence Pipeline that can be consumed by the dashboard and API.
"""

import pandas as pd
import numpy as np
import networkx as nx
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "graph_engine"))

from network_graph import build_network_graph, get_graph_metrics
from trust_scoring import compute_trust_scores, get_compromised_nodes

class TrustIntelligence:
    """
    Orchestrates the Graph Intelligence and Trust Scoring pipeline.
    """

    def __init__(self):
        self.graph = None
        self.trust_data = {}
        self.metrics = {}

    def analyse(self, df: pd.DataFrame, anomaly_scores: np.ndarray,
                predictions: np.ndarray, max_nodes: int = 80) -> dict:
        """
        Runs the full Trust Intelligence pipeline on a batch of connections.

        Args:
            df: Raw or processed connection dataset.
            anomaly_scores: DL anomaly scores per connection.
            predictions: Ensemble ML predictions per connection.
            max_nodes: Maximum nodes to render in the graph.

        Returns:
            Dictionary containing the generated graph, trust data, and metrics.
        """
        print("[*] Initialising Trust Intelligence Engine ...")
        
        # 1. Build the network topology
        self.graph = build_network_graph(df, anomaly_scores, predictions, max_nodes=max_nodes)
        
        # 2. Compute trust scores
        self.trust_data = compute_trust_scores(self.graph)
        
        # 3. Aggregate metrics
        self.metrics = get_graph_metrics(self.graph)
        
        print("[✓] Trust Analysis Complete.")
        return {
            "graph": self.graph,
            "trust_data": self.trust_data,
            "metrics": self.metrics
        }

    def get_compromised(self) -> list:
        """Returns a list of entirely compromised nodes (RED)."""
        if not self.trust_data:
            return []
        return get_compromised_nodes(self.trust_data)

    def get_trust_summary(self) -> dict:
        """Returns counts of nodes in each trust tier."""
        if not self.trust_data:
            return {"green_count": 0, "amber_count": 0, "red_count": 0}
            
        return {
            "green_count": sum(1 for v in self.trust_data.values() if v['level'] == 'GREEN'),
            "amber_count": sum(1 for v in self.trust_data.values() if v['level'] == 'AMBER'),
            "red_count": sum(1 for v in self.trust_data.values() if v['level'] == 'RED'),
        }

if __name__ == "__main__":
    # Quick test
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from data_loader import load_dataset
    
    df = load_dataset("test").head(100)
    mock_anomaly = np.random.uniform(0, 1, 100)
    mock_preds = np.random.randint(0, 5, 100)
    
    ti = TrustIntelligence()
    res = ti.analyse(df, mock_anomaly, mock_preds)
    
    print("\nTrust Summary:", ti.get_trust_summary())
    ranks = sorted([(n, d['trust_score']) for n,d in ti.trust_data.items()], 
                   key=lambda x: x[1])
    print("\nBottom 3 Trusted Nodes:")
    for n, s in ranks[:3]:
        print(f"  {n}: {s:.4f}")
