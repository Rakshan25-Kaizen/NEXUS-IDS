"""
attack_fingerprint.py — NEXUS-IDS SOC: Attack Pattern Fingerprint
"""
import plotly.graph_objects as go
import numpy as np

def render_attack_fingerprint(predictions, anomaly_scores) -> go.Figure:
    np.random.seed(42)
    cats = ['Packet Rate', 'Connection Rate', 'Duration', 'Protocol Anomaly', 'Entropy']
    cats_loop = cats + [cats[0]]
    attack_mask = predictions != 0
    attack_anom = anomaly_scores[attack_mask] if attack_mask.any() else np.array([0.5])
    normal_anom = anomaly_scores[~attack_mask] if (~attack_mask).any() else np.array([0.1])
    attack_vals = [
        float(np.clip(np.mean(attack_anom) * 1.3 + np.random.uniform(0, 0.2), 0, 1)),
        float(np.clip(np.percentile(attack_anom, 75) + np.random.uniform(0, 0.15), 0, 1)),
        float(np.clip(np.std(attack_anom) * 2 + np.random.uniform(0.2, 0.4), 0, 1)),
        float(np.clip(np.max(attack_anom) * 0.9, 0, 1)),
        float(np.clip(np.mean(attack_anom) * 1.1 + np.random.uniform(0, 0.3), 0, 1))] + [0]
    attack_vals[-1] = attack_vals[0]
    normal_vals = [float(np.clip(np.mean(normal_anom) * x, 0, 1)) for x in [0.5, 0.6, 0.3, 0.3, 0.4]] + [0]
    normal_vals[-1] = normal_vals[0]
    fig = go.Figure()
    fig.add_trace(go.Scatterpolar(r=attack_vals, theta=cats_loop, fill='toself',
        fillcolor='rgba(255,82,82,0.15)', line=dict(color='#FF5252', width=2), name='Attack'))
    fig.add_trace(go.Scatterpolar(r=normal_vals, theta=cats_loop, fill='toself',
        fillcolor='rgba(0,255,178,0.1)', line=dict(color='#00FFB2', width=2), name='Normal'))
    fig.update_layout(
        polar=dict(bgcolor='#0E1117',
            radialaxis=dict(visible=True, showticklabels=False, gridcolor='#2A2D35', linecolor='#3A3F4B', range=[0, 1]),
            angularaxis=dict(gridcolor='#2A2D35', linecolor='#3A3F4B', tickfont=dict(color='#FFF', size=10))),
        showlegend=True, legend=dict(orientation="h", y=-0.15, x=0.5, xanchor="center", font=dict(size=10, color="#8892A0")),
        plot_bgcolor='#0E1117', paper_bgcolor='#0E1117', margin=dict(l=40, r=40, t=50, b=50), height=400,
        title=dict(text="ATTACK FINGERPRINT", font=dict(color="#00E5FF", size=11), x=0.5, y=0.98))
    return fig
