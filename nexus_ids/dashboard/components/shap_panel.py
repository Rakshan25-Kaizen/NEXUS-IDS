"""
shap_panel.py — NEXUS-IDS SOC: SHAP Explainability
"""
import plotly.graph_objects as go
import pandas as pd

def render_shap_panel(shap_df: pd.DataFrame) -> go.Figure:
    if shap_df.empty:
        return go.Figure()
    df = shap_df.sort_values('Mean_Absolute_SHAP', ascending=True)
    fig = go.Figure()
    fig.add_trace(go.Bar(x=df['Mean_Absolute_SHAP'], y=df['Feature'], orientation='h',
        marker=dict(color=df['Mean_Absolute_SHAP'], colorscale=[[0, '#1C1F26'], [1, '#00E5FF']],
                    line=dict(color='#00E5FF', width=0.5)),
        hovertemplate="<b>%{y}</b>: %{x:.4f}<extra></extra>"))
    fig.update_layout(
        plot_bgcolor='#0E1117', paper_bgcolor='#0E1117',
        font=dict(color='#FFFFFF', family="Inter", size=11),
        margin=dict(l=10, r=20, t=40, b=20), height=400,
        xaxis=dict(showgrid=True, gridcolor='#2A2D35', linecolor='#3A3F4B', title="Mean |SHAP|"),
        yaxis=dict(showgrid=False, linecolor='#3A3F4B', tickfont=dict(family="Roboto Mono", size=10)),
        title=dict(text="AI DECISION EXPLAINABILITY", font=dict(color="#00E5FF", size=11), x=0.0, y=0.98))
    return fig
