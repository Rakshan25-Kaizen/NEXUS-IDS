"""
topology_map.py — NEXUS-IDS SOC: Network Trust Topology

Enhanced force-directed graph with community clustering,
attack propagation paths, and professional styling.
"""

import plotly.graph_objects as go
import networkx as nx
import numpy as np

BG = "#0E1117"
PRIMARY = "#00E5FF"
SAFE = "#00FFB2"
WARNING = "#FFC107"
CRITICAL = "#FF5252"

def render_topology_map(G: nx.DiGraph, trust_data: dict) -> go.Figure:
    if not G or len(G.nodes) == 0:
        fig = go.Figure()
        fig.update_layout(title_text="Awaiting Data", plot_bgcolor=BG, paper_bgcolor=BG, font=dict(color='#FFFFFF'))
        return fig

    nodes_list = list(G.nodes())
    for i, node in enumerate(nodes_list):
        if G.degree(node) == 0:
            neighbor = nodes_list[(i + 1) % len(nodes_list)]
            G.add_edge(node, neighbor, max_anomaly=0.5)

    pos = nx.spring_layout(G, k=0.6, iterations=60, seed=42)

    # Edges
    edge_x, edge_y, edge_anomalies = [], [], []
    for u, v, data in G.edges(data=True):
        x0, y0 = pos[u]
        x1, y1 = pos[v]
        edge_x.extend([x0, x1, None])
        edge_y.extend([y0, y1, None])
        edge_anomalies.append((u, v, data.get('max_anomaly', 0.0)))

    edge_trace = go.Scatter(x=edge_x, y=edge_y, line=dict(width=1.2, color='rgba(0,229,255,0.25)'),
                            hoverinfo='none', mode='lines')

    colour_map = {'GREEN': SAFE, 'AMBER': WARNING, 'RED': CRITICAL}
    size_map = {'RED': 20, 'AMBER': 15, 'GREEN': 9}
    node_x, node_y, node_colours, hover_texts, node_sizes, node_borders = [], [], [], [], [], []

    for node in G.nodes():
        node_x.append(pos[node][0])
        node_y.append(pos[node][1])
        data = trust_data.get(node, {})
        level = data.get('level', 'GREEN')
        trust_score = data.get('trust_score', 0.5)
        conns = data.get('connection_count', G.degree(node))
        attacks = data.get('attack_types', [])
        attack_str = ", ".join(attacks) if attacks else "None"
        node_colours.append(colour_map.get(level, '#808080'))
        node_sizes.append(size_map.get(level, 9))
        node_borders.append(CRITICAL if level == 'RED' else '#2E3240')
        hover_texts.append(
            f"<b>{node}</b><br>Status: <b>{level}</b><br>"
            f"Trust: {trust_score:.3f}<br>Connections: {conns}<br>Attacks: {attack_str}")

    node_trace = go.Scatter(
        x=node_x, y=node_y, mode='markers', hoverinfo='text', text=hover_texts,
        marker=dict(showscale=False, color=node_colours, size=node_sizes,
                    line=dict(width=[2 if s > 15 else 1 for s in node_sizes], color=node_borders),
                    opacity=0.95))

    # Arrow annotations on top-10 anomaly edges
    top_edges = sorted(edge_anomalies, key=lambda x: x[2], reverse=True)[:10]
    annotations = [dict(x=pos[v][0], y=pos[v][1], ax=pos[u][0], ay=pos[u][1],
                        xref="x", yref="y", axref="x", ayref="y",
                        showarrow=True, arrowhead=3, arrowsize=1.2, arrowwidth=1.5,
                        arrowcolor=CRITICAL, opacity=0.6)
                   for u, v, _ in top_edges if u in pos and v in pos]

    fig = go.Figure(data=[edge_trace, node_trace], layout=go.Layout(
        title='', showlegend=False, hovermode='closest', margin=dict(b=0, l=0, r=0, t=0),
        plot_bgcolor=BG, paper_bgcolor=BG,
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        annotations=annotations))
    return fig


def render_attack_propagation(G: nx.DiGraph, trust_data: dict) -> go.Figure:
    """Renders attack propagation paths through the network — lateral movement visualization."""
    red_nodes = [n for n, d in trust_data.items() if d['level'] == 'RED']
    if not red_nodes or not G:
        fig = go.Figure()
        fig.update_layout(plot_bgcolor=BG, paper_bgcolor=BG, font=dict(color='#FFF'),
                          title=dict(text="No Attack Propagation Detected", font=dict(color=PRIMARY, size=12)))
        return fig

    pos = nx.spring_layout(G, k=0.6, iterations=60, seed=42)
    np.random.seed(42)

    fig = go.Figure()
    # Background edges (dim)
    edge_x, edge_y = [], []
    for u, v in G.edges():
        if u in pos and v in pos:
            edge_x.extend([pos[u][0], pos[v][0], None])
            edge_y.extend([pos[u][1], pos[v][1], None])
    fig.add_trace(go.Scatter(x=edge_x, y=edge_y, mode='lines',
                             line=dict(width=0.5, color='rgba(255,255,255,0.05)'), hoverinfo='none'))

    # Attack pathway
    attack_path_x, attack_path_y = [], []
    for red in red_nodes[:5]:
        if red in pos:
            neighbors = list(G.successors(red)) + list(G.predecessors(red))
            for nb in neighbors[:3]:
                if nb in pos:
                    attack_path_x.extend([pos[red][0], pos[nb][0], None])
                    attack_path_y.extend([pos[red][1], pos[nb][1], None])
    fig.add_trace(go.Scatter(x=attack_path_x, y=attack_path_y, mode='lines', name='Attack Path',
                             line=dict(width=3, color=CRITICAL, dash='dot')))

    # Nodes
    for node in G.nodes():
        if node not in pos:
            continue
        d = trust_data.get(node, {})
        level = d.get('level', 'GREEN')
        color = {'RED': CRITICAL, 'AMBER': WARNING, 'GREEN': 'rgba(0,255,178,0.3)'}.get(level, '#333')
        size = {'RED': 16, 'AMBER': 10, 'GREEN': 5}.get(level, 5)
        fig.add_trace(go.Scatter(x=[pos[node][0]], y=[pos[node][1]], mode='markers',
                                 marker=dict(color=color, size=size, line=dict(width=1, color=BG)),
                                 hoverinfo='text', text=f"{node} [{level}]", showlegend=False))

    fig.update_layout(plot_bgcolor=BG, paper_bgcolor=BG, margin=dict(l=0, r=0, t=40, b=0),
                      height=400, showlegend=False,
                      xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                      yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                      title=dict(text="ATTACK PROPAGATION PATH", font=dict(color=CRITICAL, size=12), x=0.01))
    return fig
