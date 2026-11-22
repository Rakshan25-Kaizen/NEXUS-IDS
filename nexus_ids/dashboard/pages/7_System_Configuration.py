"""Page 7 — System Configuration with Logging Engine + Export Reports"""
import streamlit as st
import json
import io
import csv
import numpy as np
import sys
from pathlib import Path
from datetime import datetime

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))
sys.path.insert(0, str(PROJECT_ROOT / "graph_engine"))
sys.path.insert(0, str(PROJECT_ROOT / "dashboard" / "components"))

from theme import inject_theme
from header import render_header, render_nav
from soc_logger import get_recent_logs, clear_logs, log_system

st.set_page_config(page_title="NEXUS-IDS | Configuration", page_icon="🛡️", layout="wide", initial_sidebar_state="collapsed")
inject_theme()
render_header()
render_nav(current_page="Config")

tab1, tab2, tab3, tab4 = st.tabs(["Detection Settings", "Model Management", "System Logs", "Export Reports"])

# ── Tab 1: Detection Settings ──
with tab1:
    st.markdown('<div class="soc-panel-title">DETECTION PARAMETERS</div>', unsafe_allow_html=True)
    c1, c2 = st.columns(2)
    with c1:
        anomaly_thresh = st.slider("Anomaly Threshold", 0.0, 1.0, 0.5, 0.05, key="anom_thresh")
        red_thresh = st.slider("RED Trust Threshold", 0.0, 1.0, 0.3, 0.05, key="red_thresh")
        amber_thresh = st.slider("AMBER Trust Threshold", 0.0, 1.0, 0.6, 0.05, key="amber_thresh")
    with c2:
        max_nodes = st.number_input("Max Graph Nodes", 10, 200, 50, key="max_nodes")
        batch_size = st.number_input("Batch Size", 100, 50000, 5000, 500, key="batch_sz")
        auto_refresh = st.checkbox("Auto-Refresh Dashboard", False, key="auto_ref")
    if st.button("Save Settings", use_container_width=True, key="save_settings"):
        log_system(f"Settings updated — anomaly={anomaly_thresh}, red={red_thresh}, amber={amber_thresh}")
        st.success("Settings saved.")

# ── Tab 2: Model Management ──
with tab2:
    st.markdown('<div class="soc-panel-title">MODEL MANAGEMENT</div>', unsafe_allow_html=True)
    models_dir = PROJECT_ROOT / "models"
    if models_dir.exists():
        for f in sorted(models_dir.glob("*")):
            if f.is_file():
                mod_time = datetime.fromtimestamp(f.stat().st_mtime).strftime('%Y-%m-%d %H:%M')
                size_kb = f.stat().st_size / 1024
                st.markdown(
                    f'<div style="display:flex;justify-content:space-between;padding:8px 12px;'
                    f'background:#1C1F26;border-radius:8px;margin-bottom:6px;border:1px solid #2E3240;">'
                    f'<span style="color:#FFFFFF;font-size:13px;">{f.name}</span>'
                    f'<span style="color:#8892A0;font-size:11px;">{size_kb:.1f} KB — {mod_time}</span>'
                    f'</div>', unsafe_allow_html=True)
    c1, c2 = st.columns(2)
    with c1:
        if st.button("Retrain Ensemble", use_container_width=True, key="retrain_ens"):
            st.info("Use 'Run Full Analysis' from Overview to retrain models.")
    with c2:
        if st.button("Retrain Autoencoder", use_container_width=True, key="retrain_ae"):
            st.info("Use 'Run Full Analysis' from Overview to retrain models.")

# ── Tab 3: System Logs (Module 3 — Real Logging Engine) ──
with tab3:
    st.markdown('<div class="soc-panel-title">SOC ACTIVITY LOG</div>', unsafe_allow_html=True)
    c1, c2 = st.columns([4, 1])
    with c2:
        if st.button("Clear Logs", use_container_width=True, key="clear_logs"):
            clear_logs()
            st.rerun()
    with c1:
        n_lines = st.slider("Lines to display", 20, 200, 50, 10, key="log_lines")

    log_content = get_recent_logs(n_lines)
    st.markdown(
        '<div style="background:#0A0D12;border:1px solid #2E3240;border-radius:8px;'
        'padding:12px;font-family:Roboto Mono,monospace;font-size:11px;color:#8892A0;'
        'height:400px;overflow-y:auto;white-space:pre-wrap;line-height:1.6;">'
        + log_content.replace('<', '&lt;').replace('>', '&gt;')
        .replace('WARNING', '<span style="color:#FFC107;">WARNING</span>')
        .replace('CRITICAL', '<span style="color:#FF5252;">CRITICAL</span>')
        .replace('ERROR', '<span style="color:#FF5252;">ERROR</span>')
        .replace('SYSTEM:', '<span style="color:#00E5FF;">SYSTEM:</span>')
        + '</div>', unsafe_allow_html=True)

# ── Tab 4: Export Reports ──
with tab4:
    st.markdown('<div class="soc-panel-title">EXPORT SECURITY REPORTS</div>', unsafe_allow_html=True)

    if 'pipeline_result' in st.session_state:
        pr = st.session_state.pipeline_result
        total = int(pr["stats"].get("total_records", 0))
        normal = int(pr["stats"].get("normal_count", 0))
        attacks = total - normal
        red_nodes = sum(1 for v in pr["ti"].trust_data.values() if v['level'] == 'RED')
        amber_nodes = sum(1 for v in pr["ti"].trust_data.values() if v['level'] == 'AMBER')

        report_data = {
            "report_title": "NEXUS-IDS Security Intelligence Report",
            "generated_at": datetime.now().isoformat(),
            "pipeline": "RF + Autoencoder + Trust Engine",
            "summary": {
                "total_records": total,
                "normal_traffic": normal,
                "attacks_detected": attacks,
                "attack_rate": round(attacks / max(total, 1) * 100, 2),
                "avg_trust_score": round(float(pr["avg_trust"]), 4),
                "red_nodes": red_nodes,
                "amber_nodes": amber_nodes,
                "anomaly_index": round(float(np.mean(pr["anomaly_scores"])), 6),
            },
            "threat_breakdown": {
                "dos": int(np.sum(pr["predictions"] == 1)),
                "probe": int(np.sum(pr["predictions"] == 2)),
                "r2l": int(np.sum(pr["predictions"] == 3)),
                "u2r": int(np.sum(pr["predictions"] == 4)),
            },
        }

        incident_list = []
        for i, v in enumerate(pr["verdicts"][:100]):
            if v["severity"] in ("CRITICAL", "HIGH"):
                incident_list.append({
                    "id": f"INC-{1000+i:04d}",
                    "severity": v["severity"],
                    "reason": v["reason"],
                    "attack_type": v.get("attack_type", "unknown"),
                    "timestamp": datetime.now().isoformat(),
                })

        # ── Build attack graph figure for PNG/SVG export ──
        from topology_map import render_topology_map
        graph_fig = render_topology_map(pr["ti"].graph, pr["ti"].trust_data)

        # ── Button styling — clear text labels, SOC dark theme ──
        st.markdown("""<style>
        div[data-testid="stDownloadButton"] > button {
            background: #1C1F26 !important;
            color: #FFFFFF !important;
            border: 1px solid #00E5FF !important;
            border-radius: 8px !important;
            font-size: 13px !important;
            font-weight: 600 !important;
            padding: 12px 20px !important;
            letter-spacing: 0.3px !important;
            min-height: 52px !important;
        }
        div[data-testid="stDownloadButton"] > button:hover {
            background: rgba(0,229,255,0.12) !important;
            border-color: #00E5FF !important;
        }
        </style>""", unsafe_allow_html=True)

        st.markdown("#### Available Reports")
        st.markdown('<div style="height:8px;"></div>', unsafe_allow_html=True)

        c1, c2, c3, c4 = st.columns(4, gap="large")

        # ── Button 1: Download PNG Graph ──
        with c1:
            import matplotlib
            matplotlib.use('Agg')
            import matplotlib.pyplot as plt

            png_buf = io.BytesIO()
            trust_data = pr["ti"].trust_data
            nodes = list(trust_data.keys())[:30]
            scores = [trust_data[n]['trust_score'] for n in nodes]
            levels = [trust_data[n]['level'] for n in nodes]
            colors_map = {'GREEN': '#00FFB2', 'AMBER': '#FFC107', 'RED': '#FF5252'}
            bar_colors = [colors_map.get(l, '#8892A0') for l in levels]

            fig_mpl, ax = plt.subplots(figsize=(12, 6), facecolor='#0E1117')
            ax.set_facecolor('#0E1117')
            ax.barh(range(len(nodes)), scores, color=bar_colors, edgecolor='#2E3240', height=0.7)
            ax.set_yticks(range(len(nodes)))
            ax.set_yticklabels([n[:18] for n in nodes], fontsize=7, color='#8892A0')
            ax.set_xlabel('Trust Score', color='#8892A0', fontsize=10)
            ax.set_title('NEXUS-IDS Attack Graph — Node Trust Scores', color='#00E5FF', fontsize=13, fontweight='bold')
            ax.tick_params(colors='#8892A0')
            ax.spines['top'].set_visible(False)
            ax.spines['right'].set_visible(False)
            ax.spines['bottom'].set_color('#2E3240')
            ax.spines['left'].set_color('#2E3240')
            ax.set_xlim(0, 1)
            fig_mpl.tight_layout()
            fig_mpl.savefig(png_buf, format='png', dpi=150, facecolor='#0E1117')
            plt.close(fig_mpl)
            png_buf.seek(0)

            st.download_button(
                label="Download PNG Graph",
                data=png_buf.getvalue(),
                file_name="attack_graph.png",
                mime="image/png",
                use_container_width=True,
                key="dl_png_graph"
            )

        # ── Button 2: Download SVG Graph ──
        with c2:
            svg_buf = io.BytesIO()
            fig_mpl2, ax2 = plt.subplots(figsize=(12, 6), facecolor='#0E1117')
            ax2.set_facecolor('#0E1117')
            ax2.barh(range(len(nodes)), scores, color=bar_colors, edgecolor='#2E3240', height=0.7)
            ax2.set_yticks(range(len(nodes)))
            ax2.set_yticklabels([n[:18] for n in nodes], fontsize=7, color='#8892A0')
            ax2.set_xlabel('Trust Score', color='#8892A0', fontsize=10)
            ax2.set_title('NEXUS-IDS Attack Graph — Node Trust Scores', color='#00E5FF', fontsize=13, fontweight='bold')
            ax2.tick_params(colors='#8892A0')
            ax2.spines['top'].set_visible(False)
            ax2.spines['right'].set_visible(False)
            ax2.spines['bottom'].set_color('#2E3240')
            ax2.spines['left'].set_color('#2E3240')
            ax2.set_xlim(0, 1)
            fig_mpl2.tight_layout()
            fig_mpl2.savefig(svg_buf, format='svg', facecolor='#0E1117')
            plt.close(fig_mpl2)
            svg_buf.seek(0)
            svg_string = svg_buf.getvalue().decode('utf-8')

            st.download_button(
                label="Download SVG Graph",
                data=svg_string,
                file_name="attack_graph.svg",
                mime="image/svg+xml",
                use_container_width=True,
                key="dl_svg_graph"
            )

        # ── Button 3: Export Dataset Results (CSV) ──
        with c3:
            csv_buf = io.StringIO()
            writer = csv.writer(csv_buf)
            writer.writerow(["Record", "Prediction", "Anomaly_Score", "Severity", "Verdict"])
            class_names = ['Normal', 'DoS', 'Probe', 'R2L', 'U2R']
            for i in range(min(len(pr["predictions"]), 5000)):
                pred_label = class_names[pr["predictions"][i]] if pr["predictions"][i] < len(class_names) else "Unknown"
                sev = pr["verdicts"][i]["severity"] if i < len(pr["verdicts"]) else "N/A"
                reason = pr["verdicts"][i]["reason"][:60] if i < len(pr["verdicts"]) else ""
                writer.writerow([i+1, pred_label, round(float(pr["anomaly_scores"][i]), 6), sev, reason])
            st.download_button(
                label="Export Dataset Results (CSV)",
                data=csv_buf.getvalue(),
                file_name=f"nexus_dataset_results_{datetime.now().strftime('%Y%m%d')}.csv",
                mime="text/csv",
                use_container_width=True,
                key="dl_csv_results"
            )

        # ── Button 4: Download PDF Security Report ──
        with c4:
            try:
                from reportlab.pdfgen import canvas as pdf_canvas
                from reportlab.lib.pagesizes import A4

                def safe_text(s):
                    """Remove non-ASCII chars that break ReportLab fonts."""
                    return str(s).encode('ascii', 'replace').decode('ascii')

                pdf_buf = io.BytesIO()
                c = pdf_canvas.Canvas(pdf_buf, pagesize=A4)
                w, h = A4

                c.setFillColorRGB(0.055, 0.067, 0.09)
                c.rect(0, 0, w, h, fill=1)

                c.setFillColorRGB(0, 0.898, 1)
                c.setFont("Helvetica-Bold", 24)
                c.drawString(50, h - 60, "NEXUS-IDS")
                c.setFillColorRGB(1, 1, 1)
                c.setFont("Helvetica-Bold", 16)
                c.drawString(50, h - 85, "Security Intelligence Report")
                c.setFont("Helvetica", 10)
                c.setFillColorRGB(0.6, 0.6, 0.6)
                c.drawString(50, h - 105, safe_text(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"))
                c.drawString(50, h - 120, "Pipeline: RF + Autoencoder + Trust Engine")

                c.setFillColorRGB(0, 0.898, 1)
                c.setFont("Helvetica-Bold", 14)
                c.drawString(50, h - 155, "Threat Summary")
                c.setFillColorRGB(1, 1, 1)
                c.setFont("Helvetica", 11)
                y = h - 178
                for k, v in report_data["summary"].items():
                    c.drawString(60, y, safe_text(f"{k.replace('_', ' ').title()}: {v}"))
                    y -= 18

                y -= 15
                c.setFillColorRGB(0, 0.898, 1)
                c.setFont("Helvetica-Bold", 14)
                c.drawString(50, y, "Attack Breakdown")
                y -= 22
                c.setFillColorRGB(1, 1, 1)
                c.setFont("Helvetica", 11)
                for k, v in report_data["threat_breakdown"].items():
                    c.drawString(60, y, safe_text(f"{k.upper()}: {v:,}"))
                    y -= 18

                y -= 15
                c.setFillColorRGB(0, 0.898, 1)
                c.setFont("Helvetica-Bold", 14)
                c.drawString(50, y, safe_text(f"High-Severity Incidents ({len(incident_list)})"))
                y -= 22
                c.setFillColorRGB(1, 1, 1)
                c.setFont("Helvetica", 9)
                for inc in incident_list[:20]:
                    if y < 50:
                        break
                    c.drawString(60, y, safe_text(f"[{inc['severity']}] {inc['reason'][:90]}"))
                    y -= 14

                c.save()
                pdf_buf.seek(0)
                pdf_bytes = pdf_buf.getvalue()

                st.download_button(
                    label="Download PDF Security Report",
                    data=pdf_bytes,
                    file_name=f"nexus_security_report_{datetime.now().strftime('%Y%m%d')}.pdf",
                    mime="application/pdf",
                    use_container_width=True,
                    key="dl_pdf_report"
                )
                log_system("PDF security report generated")

            except ImportError:
                st.warning("Install reportlab for PDF export: pip install reportlab")
            except Exception as e:
                st.error(f"PDF generation error: {e}")

    else:
        st.info("Run the analysis from the Overview page first to generate reports.")

