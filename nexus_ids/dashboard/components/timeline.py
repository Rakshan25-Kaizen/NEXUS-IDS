"""
timeline.py — NEXUS-IDS SOC: Threat Activity Trends

Clean line-based trend chart — no stacked areas, no scatter dots, no spike markers.
Each attack category is a smoothed trend line with interactive zoom.
"""

import plotly.graph_objects as go
import numpy as np

CLASS_NAMES = ['normal', 'dos', 'probe', 'r2l', 'u2r']

# SOC severity colors
COLOURS = {
    'dos':   '#FF5252',
    'probe': '#FFC107',
    'r2l':   '#00E5FF',
    'u2r':   '#8BC34A',
}


def render_timeline(predictions: np.ndarray, bucket_size: int = 100) -> go.Figure:
    if len(predictions) == 0:
        return go.Figure()

    n_buckets = max(1, len(predictions) // bucket_size)
    counts = {name: np.zeros(n_buckets) for name in CLASS_NAMES}
    for i in range(n_buckets):
        chunk = predictions[i * bucket_size:min((i + 1) * bucket_size, len(predictions))]
        for ci, name in enumerate(CLASS_NAMES):
            counts[name][i] = np.sum(chunk == ci)

    fig = go.Figure()
    x_axis = list(range(n_buckets))

    # Rolling average window for smoothing
    window = min(20, max(1, n_buckets // 5))

    for name in ['dos', 'probe', 'r2l', 'u2r']:
        raw = counts[name]
        if np.sum(raw) == 0:
            continue

        # Smooth with rolling average
        if window > 1 and len(raw) > window:
            smooth = np.convolve(raw, np.ones(window) / window, mode='same')
        else:
            smooth = raw.copy()

        fig.add_trace(go.Scatter(
            x=x_axis,
            y=smooth,
            mode="lines",
            name=name.upper(),
            line=dict(color=COLOURS[name], width=2),
            hovertemplate="<b>" + name.upper() + "</b>: %{y:.1f}<extra></extra>",
        ))

    fig.update_layout(
        plot_bgcolor='#0E1117', paper_bgcolor='#0E1117',
        font=dict(color='#FFFFFF', family="Inter", size=11),
        margin=dict(l=40, r=20, t=45, b=55),
        xaxis=dict(
            showgrid=True, gridcolor='#1E2530', linecolor='#3A3F4B',
            title="Time Window",
            rangeslider=dict(visible=True, bgcolor='#1C1F26', thickness=0.05),
        ),
        yaxis=dict(showgrid=True, gridcolor='#1E2530', linecolor='#3A3F4B', title="Attack Volume"),
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1,
                    font=dict(color='#8892A0', size=10)),
        title=dict(text="THREAT ACTIVITY TRENDS",
                   font=dict(color="#00E5FF", size=11), x=0.01, y=0.98),
    )
    return fig
