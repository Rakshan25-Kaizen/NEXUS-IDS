"""
metric_cards.py — NEXUS-IDS SOC Platform: KPI Metric Cards

Renders styled metric cards with trend indicators for the Overview page.
"""

import streamlit as st


def render_metric_cards(metrics: list):
    """
    Renders N metric cards in equal columns.

    Args:
        metrics: List of dicts with keys: label, value, delta (optional), delta_color (optional).
    """
    cols = st.columns(len(metrics))
    for col, m in zip(cols, metrics):
        with col:
            kwargs = {"label": m["label"], "value": m["value"]}
            if "delta" in m:
                kwargs["delta"] = m["delta"]
            if "delta_color" in m:
                kwargs["delta_color"] = m["delta_color"]
            st.metric(**kwargs)
