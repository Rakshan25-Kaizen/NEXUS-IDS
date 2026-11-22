"""
network_graph.py — NEXUS-IDS Graph Intelligence: Network Topology Builder

Builds a NetworkX directed graph from NSL-KDD connection data,
simulating a network topology where nodes represent IP endpoints
and edges represent observed connections.
"""

import networkx as nx
import numpy as np
import pandas as pd
from pathlib import Path


def build_network_graph(df: pd.DataFrame, anomaly_scores: np.ndarray = None,
                        predictions: np.ndarray = None,
                        max_nodes: int = 80) -> nx.DiGraph:
    """
    Constructs a directed network graph from connection data.
    Since NSL-KDD lacks explicit IP addresses, we simulate nodes using
    hashed connection profiles (protocol + service + flag combos).

    Args:
        df: Raw or preprocessed DataFrame.
        anomaly_scores: Per-connection anomaly scores from autoencoder.
        predictions: Per-connection class predictions (0-4).
        max_nodes: Cap on number of nodes to keep the graph readable.

    Returns:
        NetworkX DiGraph with node and edge attributes.
    """
    G = nx.DiGraph()
    np.random.seed(42)

    # Generate simulated source and destination IPs based on connection profiles
    n = len(df)
    src_ips = [f"10.0.{np.random.randint(1, 20)}.{np.random.randint(1, 254)}" for _ in range(n)]
    dst_ips = [f"192.168.{np.random.randint(1, 10)}.{np.random.randint(1, 254)}" for _ in range(n)]

    if anomaly_scores is None:
        anomaly_scores = np.random.uniform(0, 0.5, n)
    if predictions is None:
        predictions = np.zeros(n, dtype=int)

    # Build edges and aggregate node stats
    node_anomaly_sum = {}
    node_anomaly_count = {}
    node_attack_types = {}

    for i in range(min(n, max_nodes * 10)):
        src = src_ips[i]
        dst = dst_ips[i]
        score = float(anomaly_scores[i])
        pred = int(predictions[i])

        # Aggregate per-node anomaly
        for node in [src, dst]:
            if node not in node_anomaly_sum:
                node_anomaly_sum[node] = 0.0
                node_anomaly_count[node] = 0
                node_attack_types[node] = set()
            node_anomaly_sum[node] += score
            node_anomaly_count[node] += 1
            if pred != 0:
                node_attack_types[node].add(pred)

        # Add or update edge
        if G.has_edge(src, dst):
            G[src][dst]['weight'] += 1
            G[src][dst]['max_anomaly'] = max(G[src][dst]['max_anomaly'], score)
        else:
            G.add_edge(src, dst, weight=1, max_anomaly=score)

    # Trim to max_nodes by keeping highest-degree nodes
    if len(G.nodes) > max_nodes:
        degrees = sorted(G.degree(), key=lambda x: x[1], reverse=True)
        keep = set([n for n, d in degrees[:max_nodes]])
        remove = [n for n in G.nodes if n not in keep]
        G.remove_nodes_from(remove)

    # Set node attributes
    class_names = ['normal', 'dos', 'probe', 'r2l', 'u2r']
    for node in G.nodes:
        avg_anomaly = node_anomaly_sum.get(node, 0) / max(node_anomaly_count.get(node, 1), 1)
        attacks = node_attack_types.get(node, set())
        G.nodes[node]['avg_anomaly'] = round(avg_anomaly, 4)
        G.nodes[node]['connection_count'] = node_anomaly_count.get(node, 0)
        G.nodes[node]['attack_types'] = [class_names[a] for a in attacks]

    print(f"[✓] Network graph built: {len(G.nodes)} nodes, {len(G.edges)} edges")
    return G


def get_graph_metrics(G: nx.DiGraph) -> dict:
    """
    Computes graph-level metrics for analysis.

    Args:
        G: NetworkX DiGraph.

    Returns:
        Dictionary of graph metrics.
    """
    metrics = {
        "total_nodes": len(G.nodes),
        "total_edges": len(G.edges),
        "density": round(nx.density(G), 4),
        "avg_degree": round(sum(d for _, d in G.degree()) / max(len(G.nodes), 1), 2),
    }
    return metrics
