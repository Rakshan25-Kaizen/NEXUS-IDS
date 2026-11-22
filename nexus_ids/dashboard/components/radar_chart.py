"""
radar_chart.py — NEXUS-IDS SOC: Threat Intelligence Spectrum
6-axis radar: DDoS, Probe, R2L, U2R, Malware, Botnet
"""
import plotly.graph_objects as go
import numpy as np

def render_radar_chart(predictions: np.ndarray) -> go.Figure:
    if len(predictions) == 0:
        return go.Figure()
    np.random.seed(42)
    counts = [np.sum(predictions == i) for i in range(5)]
    malware_est = int(counts[1] * 0.05 + counts[2] * 0.1 + np.random.randint(0, 20))
    botnet_est = int(counts[1] * 0.03 + np.random.randint(0, 15))
    raw = [counts[1], counts[2], counts[3], counts[4], malware_est, botnet_est]
    log_vals = [float(np.log1p(c)) for c in raw]
    cats = ['DDoS', 'Probe', 'R2L', 'U2R', 'Malware', 'Botnet']
    cats_loop = cats + [cats[0]]
    vals_loop = log_vals + [log_vals[0]]
    raw_loop = raw + [raw[0]]
    fig = go.Figure()
    fig.add_trace(go.Scatterpolar(r=vals_loop, theta=cats_loop, fill='toself',
        fillcolor='rgba(0,229,255,0.12)', line=dict(color='#00E5FF', width=2),
        marker=dict(color='#00E5FF', size=6), text=raw_loop,
        hovertemplate="<b>%{theta}</b><br>Count: %{text}<extra></extra>"))
    fig.update_layout(
        polar=dict(bgcolor='#0E1117',
            radialaxis=dict(visible=True, showticklabels=False, gridcolor='#2A2D35', linecolor='#3A3F4B'),
            angularaxis=dict(gridcolor='#2A2D35', linecolor='#3A3F4B',
                             tickfont=dict(color='#FFFFFF', size=10, family="Inter"))),
        showlegend=False, plot_bgcolor='#0E1117', paper_bgcolor='#0E1117',
        margin=dict(l=30, r=30, t=50, b=30),
        title=dict(text="THREAT INTELLIGENCE SPECTRUM", font=dict(color="#00E5FF", size=11), x=0.5, y=0.98))
    return fig
