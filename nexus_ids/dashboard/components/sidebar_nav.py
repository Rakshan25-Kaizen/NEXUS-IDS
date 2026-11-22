"""
sidebar_nav.py — NEXUS-IDS SOC Platform: Sidebar Navigation

Renders the branded sidebar with 7-item navigation menu.
"""

import streamlit as st


def render_sidebar():
    """Renders the sidebar navigation and system controls."""
    with st.sidebar:
        st.markdown(
            '<div style="text-align:center;padding:16px 0;">'
            '<span style="font-size:42px;">🛡️</span><br>'
            '<span style="color:#38BDF8;font-size:22px;font-weight:700;">NEXUS-IDS</span><br>'
            '<span style="color:#94A3B8;font-size:11px;">SOC Intelligence Platform v3.0</span>'
            '</div>',
            unsafe_allow_html=True
        )
        st.markdown('<hr style="border-color:#334155;margin:8px 0 16px 0;">', unsafe_allow_html=True)

        st.markdown(
            '<div style="color:#94A3B8;font-size:10px;font-weight:600;letter-spacing:1.5px;'
            'margin-bottom:12px;">NAVIGATION</div>',
            unsafe_allow_html=True
        )

        pages = [
            ("📊", "Overview"),
            ("🌐", "Network Intelligence"),
            ("🎯", "Threat Analytics"),
            ("🧠", "AI Model Insights"),
            ("🔮", "Threat Prediction"),
            ("📋", "Security Events"),
            ("⚙️", "System Configuration"),
        ]
        for icon, label in pages:
            st.markdown(
                '<div style="padding:6px 8px;border-radius:4px;font-size:13px;color:#94A3B8;'
                'margin-bottom:2px;">' + icon + '  ' + label + '</div>',
                unsafe_allow_html=True
            )

        st.markdown('<hr style="border-color:#334155;margin:16px 0;">', unsafe_allow_html=True)
        st.markdown(
            '<div style="color:#94A3B8;font-size:10px;font-weight:600;letter-spacing:1.5px;'
            'margin-bottom:12px;">SYSTEM CONTROL</div>',
            unsafe_allow_html=True
        )
        run = st.button("🚀 Run Full Analysis", use_container_width=True)

        st.markdown('<hr style="border-color:#334155;margin:16px 0;">', unsafe_allow_html=True)
        st.markdown(
            '<div style="text-align:center;padding:8px;font-size:10px;color:#475569;">'
            '© 2026 NEXUS-IDS<br>Security Operations Platform'
            '</div>',
            unsafe_allow_html=True
        )
    return run
