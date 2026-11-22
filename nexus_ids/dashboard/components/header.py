"""
header.py — NEXUS-IDS SOC Platform: Top Navigation Header

Professional SOC header with branding, system status, and
button-based navigation using st.switch_page() (Streamlit ≥1.30).
"""

import streamlit as st
from datetime import datetime


def render_header():
    """Renders the top SOC header with branding and system status."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    html = (
        '<div style="background:linear-gradient(90deg,#1C1F26 0%,#0E1117 100%);'
        'border-bottom:1px solid #2E3240;padding:12px 24px;margin:-1rem -1rem 20px -1rem;">'
        '<div style="display:flex;justify-content:space-between;align-items:center;">'
        '<div style="display:flex;align-items:center;gap:12px;">'
        '<div style="width:36px;height:36px;background:linear-gradient(135deg,#00E5FF,#00B8D4);'
        'border-radius:8px;display:flex;align-items:center;justify-content:center;'
        'font-size:18px;box-shadow:0 2px 8px rgba(0,229,255,0.3);">🛡</div>'
        '<div>'
        '<div style="font-size:16px;font-weight:700;color:#FFFFFF;letter-spacing:1px;">NEXUS-IDS</div>'
        '<div style="font-size:10px;color:#8892A0;letter-spacing:0.5px;">AI-Driven Cyber Threat Intelligence</div>'
        '</div></div>'
        '<div style="display:flex;align-items:center;gap:24px;font-size:11px;">'
        '<div style="display:flex;align-items:center;gap:6px;">'
        '<div style="width:7px;height:7px;background:#00FFB2;border-radius:50%;'
        'box-shadow:0 0 6px #00FFB2;animation:pulse 2s infinite;"></div>'
        '<span style="color:#8892A0;">Status:</span>'
        '<span style="color:#00FFB2;font-weight:600;">ACTIVE</span></div>'
        '<div><span style="color:#8892A0;">Pipeline: </span>'
        '<span style="color:#FFFFFF;">RF + Autoencoder + Trust</span></div>'
        '<div><span style="color:#8892A0;">Updated: </span>'
        '<span style="color:#FFFFFF;">' + now + '</span></div>'
        '</div></div>'
        '<style>@keyframes pulse{0%,100%{opacity:1}50%{opacity:0.4}}</style>'
        '</div>'
    )
    st.markdown(html, unsafe_allow_html=True)


def render_nav(current_page="Overview"):
    """Renders horizontal nav bar using styled buttons + st.switch_page()."""

    # Inject compact nav button CSS
    st.markdown("""<style>
    div[data-testid="stHorizontalBlock"] .stButton > button {
        background: transparent !important;
        color: #8892A0 !important;
        border: none !important;
        box-shadow: none !important;
        font-size: 12px !important;
        font-weight: 400 !important;
        padding: 6px 8px !important;
        border-radius: 6px 6px 0 0 !important;
        border-bottom: 2px solid transparent !important;
        min-height: 0 !important;
        width: 100% !important;
    }
    div[data-testid="stHorizontalBlock"] .stButton > button:hover {
        color: #00E5FF !important;
        background: rgba(0,229,255,0.06) !important;
        transform: none !important;
    }
    </style>""", unsafe_allow_html=True)

    pages = [
        ("Overview",    "app.py"),
        ("Network",     "pages/2_Network_Intelligence.py"),
        ("Threats",     "pages/3_Threat_Analytics.py"),
        ("AI Insights", "pages/4_AI_Model_Insights.py"),
        ("Prediction",  "pages/5_Threat_Prediction.py"),
        ("Events",      "pages/6_Security_Events.py"),
        ("Config",      "pages/7_System_Configuration.py"),
        ("Data Mgmt",   "pages/8_Data_Management.py"),
    ]

    cols = st.columns(len(pages))
    for col, (label, path) in zip(cols, pages):
        with col:
            if label == current_page:
                st.markdown(
                    '<div style="text-align:center;padding:6px 0;border-bottom:2px solid #00E5FF;'
                    'color:#00E5FF;font-size:12px;font-weight:600;letter-spacing:0.3px;">'
                    + label + '</div>', unsafe_allow_html=True)
            else:
                if st.button(label, key=f"nav_{label}", use_container_width=True):
                    st.switch_page(path)

    st.markdown('<hr style="margin:-10px 0 16px 0;border-color:#2E3240;">', unsafe_allow_html=True)
