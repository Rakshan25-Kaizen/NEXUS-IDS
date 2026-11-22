"""
theme.py — NEXUS-IDS SOC Platform: Professional Design System

Centralized theme with #0E1117 palette, Inter/Roboto fonts,
Lucide-inspired icon CSS, and Plotly layout factory.
"""

import streamlit as st

# ── Design Tokens ─────────────────────────────────────────────────────
BG       = "#0E1117"
PANEL    = "#1C1F26"
PRIMARY  = "#00E5FF"
WARNING  = "#FFC107"
CRITICAL = "#FF5252"
SAFE     = "#00FFB2"
TEXT     = "#FFFFFF"
TEXT_DIM = "#8892A0"
GRID     = "#2A2D35"
AXIS     = "#3A3F4B"
BORDER   = "#2E3240"

def inject_theme():
    """Injects the global SOC CSS into every Streamlit page."""
    st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
@import url('https://fonts.googleapis.com/css2?family=Roboto+Mono:wght@400;500&display=swap');
@import url('https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght@300;400;700');

/* ── Core Layout ── */
[data-testid="stAppViewContainer"] { background-color: #0E1117; }
[data-testid="stSidebar"] { display: none; }
[data-testid="stHeader"] { background-color: #0E1117; height: 0; }
[data-testid="stSidebarCollapsedControl"] { display: none; }
header[data-testid="stHeader"] { display: none; }

html, body, [class*="css"], .stMarkdown, p, span, label, .stSelectbox, .stSlider, h1, h2, h3, h4, h5 {
    font-family: 'Inter', 'Roboto', Arial, sans-serif !important;
    color: #FFFFFF !important;
}

/* ── Buttons ── */
.stButton>button {
    background: linear-gradient(135deg, #00E5FF 0%, #00B8D4 100%);
    color: #0E1117;
    font-weight: 600;
    border-radius: 8px;
    border: none;
    padding: 10px 20px;
    font-size: 13px;
    transition: all 0.3s cubic-bezier(0.4,0,0.2,1);
    box-shadow: 0 2px 8px rgba(0,229,255,0.2);
}
.stButton>button:hover {
    transform: translateY(-2px);
    box-shadow: 0 4px 16px rgba(0,229,255,0.35);
}

/* ── Metric Cards ── */
div[data-testid="metric-container"] {
    background: linear-gradient(145deg, #1C1F26 0%, #22262E 100%);
    border: 1px solid #2E3240;
    border-radius: 12px;
    padding: 16px;
    box-shadow: 0 2px 12px rgba(0,0,0,0.3);
}
div[data-testid="metric-container"] label { color: #8892A0 !important; font-size: 11px !important; letter-spacing: 0.5px; }
div[data-testid="metric-container"] [data-testid="stMetricValue"] { color: #FFFFFF !important; font-size: 28px !important; }
div[data-testid="metric-container"] [data-testid="stMetricDelta"] svg { display: none; }

/* ── Tabs ── */
.stTabs [data-baseweb="tab-list"] { gap: 4px; border-bottom: 1px solid #2E3240; }
.stTabs [data-baseweb="tab"] {
    background: transparent;
    border-radius: 6px 6px 0 0;
    color: #8892A0;
    border: none;
    padding: 8px 16px;
    font-size: 12px;
}
.stTabs [aria-selected="true"] {
    background: #1C1F26;
    color: #00E5FF !important;
    border-bottom: 2px solid #00E5FF;
}

/* ── DataFrames ── */
.stDataFrame { border-radius: 12px; overflow: hidden; }
[data-testid="stDataFrame"] > div { border-radius: 12px; }

/* ── Selectbox / Inputs ── */
.stSelectbox > div > div, .stMultiSelect > div > div {
    background-color: #1C1F26 !important;
    border-color: #2E3240 !important;
    border-radius: 8px;
}

/* ── SOC Panel ── */
.soc-panel {
    background: linear-gradient(145deg, #1C1F26 0%, #22262E 100%);
    border-radius: 12px;
    padding: 16px;
    border: 1px solid #2E3240;
    margin-bottom: 16px;
    box-shadow: 0 2px 12px rgba(0,0,0,0.25);
}
.soc-panel-title {
    color: #00E5FF;
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 2px;
    text-transform: uppercase;
    margin-bottom: 14px;
    padding-bottom: 8px;
    border-bottom: 1px solid #2E3240;
}

/* ── Scrollbar ── */
::-webkit-scrollbar { width: 5px; }
::-webkit-scrollbar-track { background: #0E1117; }
::-webkit-scrollbar-thumb { background: #00E5FF; border-radius: 3px; }

/* ── Hide Streamlit defaults ── */
#MainMenu { visibility: hidden; }
footer { visibility: hidden; }
.stDeployButton { display: none; }
</style>
""", unsafe_allow_html=True)


def plotly_layout(title="", height=400):
    """Returns a SOC-themed Plotly layout dict."""
    return dict(
        title=dict(text=title, font=dict(color=PRIMARY, size=11, family="Inter"), x=0.01, y=0.98),
        plot_bgcolor=BG,
        paper_bgcolor=BG,
        font=dict(color=TEXT, family="Inter", size=11),
        margin=dict(l=40, r=20, t=40, b=40),
        height=height,
        xaxis=dict(showgrid=True, gridcolor=GRID, linecolor=AXIS, zerolinecolor=GRID),
        yaxis=dict(showgrid=True, gridcolor=GRID, linecolor=AXIS, zerolinecolor=GRID),
    )
