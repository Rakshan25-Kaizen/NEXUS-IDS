"""
heatmap.py — NEXUS-IDS SOC: Risk Heatmap & Connection Matrix
"""
import plotly.graph_objects as go
import numpy as np

BG = "#0E1117"
PRIMARY = "#00E5FF"

def render_risk_heatmap(trust_data: dict) -> go.Figure:
    subnets_y = ["10.0.1.x", "10.0.2.x", "10.0.5.x", "10.0.9.x", "10.0.14.x", "10.0.18.x"]
    subnets_x = ["192.168.1.x", "192.168.2.x", "192.168.3.x", "192.168.5.x", "192.168.8.x"]
    np.random.seed(42)
    scores = list(trust_data.values()) if trust_data else []
    trust_vals = [d['trust_score'] for d in scores] if scores else [0.5]
    z = np.zeros((len(subnets_y), len(subnets_x)))
    for i in range(len(subnets_y)):
        for j in range(len(subnets_x)):
            idx = (i * len(subnets_x) + j) % len(trust_vals)
            z[i][j] = round(np.clip(1.0 - trust_vals[idx] + np.random.uniform(-0.1, 0.1), 0, 1), 2)
    fig = go.Figure(data=go.Heatmap(z=z, x=subnets_x, y=subnets_y,
        colorscale=[[0, '#00FFB2'], [0.3, '#FFC107'], [0.6, '#FF5252'], [1, '#D32F2F']],
        hovertemplate="<b>Src:</b> %{y}<br><b>Dst:</b> %{x}<br><b>Risk:</b> %{z:.2f}<extra></extra>",
        colorbar=dict(title="Risk", tickfont=dict(color="#8892A0"), titlefont=dict(color="#8892A0"))))
    fig.update_layout(plot_bgcolor=BG, paper_bgcolor=BG, font=dict(color='#FFF', family="Inter"),
        margin=dict(l=80, r=20, t=40, b=60), height=350,
        xaxis=dict(title="Destination", tickfont=dict(size=10)),
        yaxis=dict(title="Source", tickfont=dict(size=10)),
        title=dict(text="NODE RISK HEATMAP", font=dict(color=PRIMARY, size=11), x=0.01))
    return fig

def render_connection_matrix(G) -> go.Figure:
    nodes = list(G.nodes())[:20]
    n = len(nodes)
    z = np.zeros((n, n))
    node_idx = {node: i for i, node in enumerate(nodes)}
    for u, v, d in G.edges(data=True):
        if u in node_idx and v in node_idx:
            z[node_idx[u]][node_idx[v]] = d.get('weight', 1)
    labels = [nd.split('.')[-1] for nd in nodes]
    fig = go.Figure(data=go.Heatmap(z=z, x=labels, y=labels,
        colorscale=[[0, BG], [0.5, PRIMARY], [1, '#FFC107']],
        hovertemplate="<b>Src:</b> %{y}<br><b>Dst:</b> %{x}<br><b>Vol:</b> %{z}<extra></extra>"))
    fig.update_layout(plot_bgcolor=BG, paper_bgcolor=BG, font=dict(color='#FFF', family="Inter", size=9),
        margin=dict(l=50, r=20, t=40, b=50), height=350,
        title=dict(text="CONNECTION MATRIX", font=dict(color=PRIMARY, size=11), x=0.01))
    return fig
