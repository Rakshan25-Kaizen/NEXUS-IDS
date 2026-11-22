"""
alert_feed.py — NEXUS-IDS SOC: Active Alert Ticker
"""
import streamlit as st
from typing import List

def render_alert_feed(verdicts: List[dict]):
    alerts = [v for v in verdicts if v['severity'] != 'LOW']
    severity_rank = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2}
    alerts.sort(key=lambda x: severity_rank.get(x['severity'], 3))
    if not alerts:
        st.markdown('<div style="padding:20px;border-radius:12px;border:1px dashed rgba(0,255,178,0.3);text-align:center;"><span style="color:#00FFB2;font-size:14px;">No Active Threats</span></div>', unsafe_allow_html=True)
        return
    colours = {'CRITICAL': ('#FF5252', 'rgba(255,82,82,0.08)'), 'HIGH': ('#FFC107', 'rgba(255,193,7,0.08)'), 'MEDIUM': ('#00E5FF', 'rgba(0,229,255,0.08)')}
    crit = sum(1 for a in alerts if a['severity'] == 'CRITICAL')
    high = sum(1 for a in alerts if a['severity'] == 'HIGH')
    hdr = '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;">'
    hdr += '<span style="color:#00E5FF;font-size:11px;font-weight:600;letter-spacing:2px;">ALERTS (' + str(len(alerts)) + ')</span>'
    hdr += '<div><span style="color:#FF5252;font-size:10px;margin-right:8px;">' + str(crit) + ' CRIT</span>'
    hdr += '<span style="color:#FFC107;font-size:10px;">' + str(high) + ' HIGH</span></div></div>'
    st.markdown(hdr, unsafe_allow_html=True)
    cards = []
    for a in alerts[:50]:
        sev = a['severity']
        tc, bg = colours.get(sev, ('#FFF', 'rgba(255,255,255,0.05)'))
        msg = a['reason']
        anim = 'animation:blink 2s infinite;' if sev == 'CRITICAL' else ''
        card = '<div style="background:' + bg + ';border-left:3px solid ' + tc + ';padding:10px 12px;margin-bottom:6px;border-radius:0 8px 8px 0;">'
        card += '<span style="color:' + tc + ';font-size:10px;font-weight:700;' + anim + '">' + sev + '</span>'
        card += '<div style="color:#CCC;font-size:12px;margin-top:4px;line-height:1.3;">' + msg + '</div></div>'
        cards.append(card)
    style = '<style>@keyframes blink{0%{opacity:1}50%{opacity:0.4}100%{opacity:1}}</style>'
    container = '<div style="height:300px;overflow-y:auto;background:#0E1117;padding:8px;border:1px solid #2E3240;border-radius:12px;">' + ''.join(cards) + '</div>' + style
    st.markdown(container, unsafe_allow_html=True)
