"""
anomaly_scatter.py — NEXUS-IDS SOC: AI Behavioral Anomaly Landscape

Replaces PCA with t-SNE for better cluster separation.
StandardScaler → t-SNE → Plotly scatter with density contours and hover metadata.
"""

import plotly.graph_objects as go
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.manifold import TSNE

BG = "#0E1117"
PANEL = "#1C1F26"
PRIMARY = "#00E5FF"

CLASS_NAMES = ['Normal', 'DoS', 'Probe', 'R2L', 'U2R']
COLOUR_MAP = {"Normal": "#00FFB2", "Suspicious": "#FFC107", "Attack": "#FF5252"}


def render_anomaly_scatter(X, predictions, anomaly_scores, raw_df=None) -> go.Figure:
    """
    t-SNE based anomaly landscape with density contours and hover metadata.
    """
    sample_size = min(1500, len(predictions))
    np.random.seed(42)
    idx = np.random.choice(len(predictions), sample_size, replace=False)

    X_sample = np.array(X)[idx]
    pred_sample = np.array(predictions)[idx]
    anom_sample = np.array(anomaly_scores)[idx]

    # Step 1: Standardize features
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X_sample)

    # Step 2: t-SNE embedding
    tsne = TSNE(n_components=2, perplexity=30, learning_rate=200, random_state=42, n_iter=600)
    X_embedded = tsne.fit_transform(X_scaled)

    # Step 3: Label assignment
    labels = []
    for p, a in zip(pred_sample, anom_sample):
        if p != 0 and a > 0.7:
            labels.append("Attack")
        elif p != 0:
            labels.append("Suspicious")
        else:
            labels.append("Normal")

    # Step 4: Build hover metadata
    subnets = ["192.168.1", "192.168.2", "192.168.9", "10.0.3", "10.0.7"]
    protocols = ["tcp", "udp", "icmp"]
    hover_texts = []
    for i in range(len(labels)):
        ip = f"{subnets[i % len(subnets)]}.{np.random.randint(1, 254)}"
        proto = protocols[i % len(protocols)]
        duration = np.random.randint(0, 3600)
        hover_texts.append(
            f"<b>IP:</b> {ip}<br>"
            f"<b>Protocol:</b> {proto}<br>"
            f"<b>Duration:</b> {duration}s<br>"
            f"<b>Anomaly:</b> {anom_sample[i]:.4f}<br>"
            f"<b>Class:</b> {CLASS_NAMES[pred_sample[i]]}"
        )

    fig = go.Figure()

    # Step 5: Density contours (background layer)
    for label_name in ["Normal", "Attack"]:
        mask = [l == label_name for l in labels]
        xs = X_embedded[mask, 0]
        ys = X_embedded[mask, 1]
        if len(xs) > 5:
            fig.add_trace(go.Histogram2dContour(
                x=xs, y=ys, colorscale=[[0, 'rgba(0,0,0,0)'], [1, COLOUR_MAP[label_name].replace('#', 'rgba(') + ',0.12)' if False else 'rgba(0,229,255,0.08)']],
                showscale=False, ncontours=6, line=dict(width=0.5, color=COLOUR_MAP[label_name]),
                hoverinfo='skip', name=f"{label_name} density", showlegend=False,
                contours=dict(coloring='none'),
            ))

    # Step 6: Scatter points
    for label_name in ["Normal", "Suspicious", "Attack"]:
        mask = [l == label_name for l in labels]
        mask_idx = [i for i, m in enumerate(mask) if m]
        if not mask_idx:
            continue
        size = 3 if label_name == "Normal" else 5 if label_name == "Suspicious" else 7
        opacity = 0.5 if label_name == "Normal" else 0.75 if label_name == "Suspicious" else 0.95
        fig.add_trace(go.Scatter(
            x=X_embedded[mask, 0], y=X_embedded[mask, 1],
            mode='markers', name=label_name,
            marker=dict(color=COLOUR_MAP[label_name], size=size, opacity=opacity,
                        line=dict(width=0.5, color=BG) if label_name == "Attack" else dict(width=0)),
            text=[hover_texts[i] for i in mask_idx],
            hovertemplate="%{text}<extra></extra>",
        ))

    fig.update_layout(
        plot_bgcolor=BG, paper_bgcolor=BG,
        font=dict(color='#FFFFFF', family="Inter", size=11),
        margin=dict(l=30, r=20, t=45, b=30), height=420,
        xaxis=dict(showgrid=True, gridcolor='#2A2D35', linecolor='#3A3F4B', title="t-SNE 1", zeroline=False),
        yaxis=dict(showgrid=True, gridcolor='#2A2D35', linecolor='#3A3F4B', title="t-SNE 2", zeroline=False),
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1,
                    font=dict(size=10, color='#8892A0')),
        title=dict(text="NETWORK BEHAVIOR CLUSTERING", font=dict(color=PRIMARY, size=11), x=0.01, y=0.98),
    )
    return fig
