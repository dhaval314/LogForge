"""
Streamlit Dashboard & Reporting Module for the Forensic AI Log Analyzer.
"""
from __future__ import annotations

# Standard Library
import io
import json
import tempfile
from dataclasses import asdict, is_dataclass
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional

# Third-Party
import pandas as pd
import streamlit as st
import streamlit.components.v1 as components
import plotly.express as px
from loguru import logger

try:
    import networkx as nx
    from pyvis.network import Network
except Exception:  # pragma: no cover
    nx = None
    Network = None

try:
    from docx import Document
    from docx.shared import Inches
    from docx.enum.text import WD_ALIGN_PARAGRAPH
except Exception:  # pragma: no cover
    logger.warning("python-docx not available, Word report generation disabled")
    Document = None

# Local Project Imports (these should exist in your repo)
from data_models import ForensicReport, LogEntry, SeverityLevel  # type: ignore
from agents import ForensicOrchestrator  # type: ignore
from config import Config  # type: ignore
from llm_analysis import GraniteAnalyzer  # type: ignore


# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------

def _safe_to_dict(obj: Any) -> Any:
    """Best-effort conversion of complex objects to plain dicts for JSON/reporting."""
    try:
        if is_dataclass(obj):
            return asdict(obj)
        if hasattr(obj, "dict") and callable(getattr(obj, "dict")):
            return obj.dict()  # pydantic-style
        if hasattr(obj, "model_dump"):
            return obj.model_dump()
        if isinstance(obj, (list, tuple)):
            return [_safe_to_dict(x) for x in obj]
        if isinstance(obj, dict):
            return {k: _safe_to_dict(v) for k, v in obj.items()}
        return obj
    except Exception:
        return str(obj)


def _pretty_json(data: Any) -> str:
    try:
        return json.dumps(_safe_to_dict(data), indent=2, default=str)
    except Exception:
        return str(data)


# -----------------------------------------------------------------------------
# Report Generator
# -----------------------------------------------------------------------------
class ReportGenerator:
    """Generates downloadable reports (DOCX/JSON) from a ForensicReport."""

    def generate_docx(self, report: ForensicReport) -> bytes:
        if Document is None:
            raise RuntimeError("python-docx is not installed. Install with: pip install python-docx")

        doc = Document()
        doc.add_heading("Forensic AI Log Analyzer Report", 0)

        # Case Metadata
        p = doc.add_paragraph()
        p.add_run("Case ID: ").bold = True
        p.add_run(str(getattr(report, "case_id", "N/A")))
        p = doc.add_paragraph()
        p.add_run("Generated: ").bold = True
        p.add_run(datetime.utcnow().strftime("%Y-%m-%d %H:%M:%SZ"))

        # Executive Summary
        doc.add_heading("Executive Summary", level=1)
        doc.add_paragraph(str(getattr(report, "executive_summary", "No summary available.")))

        # Key Metrics
        doc.add_heading("Key Metrics", level=1)
        table = doc.add_table(rows=1, cols=2)
        hdr_cells = table.rows[0].cells
        hdr_cells[0].text = "Metric"
        hdr_cells[1].text = "Value"
        metrics = {
            "Case ID": getattr(report, "case_id", "N/A"),
            "Total Events": f"{getattr(report, 'total_events', 0):,}",
            "Severity": str(getattr(getattr(report.analysis.initial_analysis, 'severity', ''), 'value', 'N/A')).upper()
            if getattr(report, 'analysis', None) and getattr(report.analysis, 'initial_analysis', None) else "N/A",
            "Confidence": f"{getattr(getattr(report.analysis.initial_analysis, 'confidence', 0.0), '__float__', lambda: report.analysis.initial_analysis.confidence)():.1%}"
            if getattr(report, 'analysis', None) and getattr(report.analysis, 'initial_analysis', None) else "N/A",
        }
        for k, v in metrics.items():
            row_cells = table.add_row().cells
            row_cells[0].text = str(k)
            row_cells[1].text = str(v)

        # IOCs
        doc.add_heading("Indicators of Compromise", level=1)
        iocs = getattr(getattr(report.analysis, 'initial_analysis', {}), 'iocs', []) if getattr(report, 'analysis', None) else []
        if iocs:
            t = doc.add_table(rows=1, cols=4)
            t.style = "Light Grid Accent 1"
            t.rows[0].cells[0].text = "Type"
            t.rows[0].cells[1].text = "Value"
            t.rows[0].cells[2].text = "Confidence"
            t.rows[0].cells[3].text = "Context"
            for i in iocs:
                row = t.add_row().cells
                row[0].text = str(getattr(i, 'type', '')).upper()
                row[1].text = str(getattr(i, 'value', ''))
                conf = getattr(i, 'confidence', None)
                row[2].text = f"{float(conf):.1%}" if conf is not None else "N/A"
                row[3].text = str(getattr(i, 'context', ''))
        else:
            doc.add_paragraph("No IOCs identified.")

        # MITRE
        doc.add_heading("MITRE ATT&CK Mapping", level=1)
        mappings = getattr(getattr(report.analysis, 'initial_analysis', {}), 'mitre_mappings', []) if getattr(report, 'analysis', None) else []
        if mappings:
            t = doc.add_table(rows=1, cols=5)
            t.style = "Light Grid"
            t.rows[0].cells[0].text = "Tactic ID"
            t.rows[0].cells[1].text = "Tactic"
            t.rows[0].cells[2].text = "Technique ID"
            t.rows[0].cells[3].text = "Technique"
            t.rows[0].cells[4].text = "Confidence"
            for m in mappings:
                row = t.add_row().cells
                row[0].text = str(getattr(m, 'tactic_id', ''))
                row[1].text = str(getattr(m, 'tactic_name', ''))
                row[2].text = str(getattr(m, 'technique_id', 'N/A'))
                row[3].text = str(getattr(m, 'technique_name', 'N/A'))
                conf = getattr(m, 'confidence', None)
                row[4].text = f"{float(conf):.1%}" if conf is not None else "N/A"
        else:
            doc.add_paragraph("No MITRE ATT&CK mappings identified.")

        # Timeline (compact)
        doc.add_heading("Event Timeline (compact)", level=1)
        timeline = getattr(report, 'timeline', []) or []
        if timeline:
            t = doc.add_table(rows=1, cols=5)
            t.style = "Light Shading"
            t.rows[0].cells[0].text = "Timestamp"
            t.rows[0].cells[1].text = "Source"
            t.rows[0].cells[2].text = "Severity"
            t.rows[0].cells[3].text = "Event Type"
            t.rows[0].cells[4].text = "Message"
            for ev in timeline[:200]:  # cap rows to keep docx reasonable
                row = t.add_row().cells
                row[0].text = str(ev.get('timestamp', ''))
                row[1].text = str(ev.get('source', ''))
                row[2].text = str(ev.get('severity', ''))
                row[3].text = str(ev.get('event_type', ''))
                row[4].text = str(ev.get('message', ''))
        else:
            doc.add_paragraph("No timeline data available.")

        # Recommendations
        doc.add_heading("Recommendations", level=1)
        recs = getattr(getattr(report, 'analysis', {}), 'recommendations', [])
        if recs:
            for r in recs:
                doc.add_paragraph(str(r), style="List Bullet")
        else:
            doc.add_paragraph("No specific recommendations generated.")

        # Serialize
        buf = io.BytesIO()
        doc.save(buf)
        return buf.getvalue()

    def generate_json(self, report: ForensicReport) -> bytes:
        return _pretty_json(report).encode("utf-8")


# -----------------------------------------------------------------------------
# Streamlit App
# -----------------------------------------------------------------------------
class ForensicDashboard:
    """Main Streamlit dashboard for forensic analysis."""

    def __init__(self):
        self.orchestrator = ForensicOrchestrator()
        self.report_generator = ReportGenerator()

        # Configure Streamlit page
        st.set_page_config(
            page_title="Forensic AI Log Analyzer",
            layout="wide",
            initial_sidebar_state="expanded",
        )

    def run(self):
        """Main dashboard application."""
        st.title("Forensic AI Log Analyzer")
        st.markdown("---")

        # Sidebar
        self._render_sidebar()

        # Tabs
        tab1, tab2, tab3, tab4 = st.tabs([
            "Upload & Analyze",
            "Analysis Results",
            "Timeline View",
            "Reports",
        ])

        with tab1:
            self._render_upload_tab()
        with tab2:
            self._render_analysis_tab()
        with tab3:
            self._render_timeline_tab()
        with tab4:
            self._render_reports_tab()

    # ---------------------------------------------
    # Sidebar
    # ---------------------------------------------
    def _render_sidebar(self):
        st.sidebar.header("Configuration")

        # LLM provider controls (runtime override)
        st.sidebar.subheader("LLM Provider")
        current_provider = getattr(Config, "LLM_PROVIDER", "ibm")
        selected_provider = st.sidebar.selectbox("Provider", ["ibm", "groq"], index=(0 if current_provider != "groq" else 1))
        if selected_provider != current_provider:
            Config.LLM_PROVIDER = selected_provider
        # if selected_provider == "groq":
        #     groq_key_input = st.sidebar.text_input("Groq API Key", value=(Config.GROQ_API_KEY or ""), type="password")
        #     if groq_key_input and groq_key_input != Config.GROQ_API_KEY:
        #         Config.GROQ_API_KEY = groq_key_input

        # Configuration status
        config_status = Config.validate_config()
        st.sidebar.subheader("Service Status")
        for service, status in config_status.items():
            service_name = service.replace("_", " ").title()
            st.sidebar.text(f"{service_name}: {'OK' if status else 'Not Configured'}")

        # Explicit LLM provider status
        provider = getattr(Config, "LLM_PROVIDER", "ibm")
        # Cache analyzer probe to avoid re-instantiation overhead
        if "_analyzer_probe" not in st.session_state:
            st.session_state["_analyzer_probe"] = GraniteAnalyzer()
        analyzer_probe = st.session_state["_analyzer_probe"]
        if provider == "groq":
            llm_ready = bool(getattr(analyzer_probe, "groq_client", None))
        else:
            llm_ready = bool(getattr(analyzer_probe, "model", None))
        st.sidebar.text(f"LLM Provider: {provider.upper()} - {'Ready' if llm_ready else 'Not Ready'}")
        if provider == "groq" and not llm_ready:
            st.sidebar.warning("Groq selected but not initialized. Provide API key above and try again.")

        # Analysis settings
        st.sidebar.subheader("Analysis Settings")
        st.sidebar.slider("Max Log Entries", 100, 50000, Config.MAX_LOG_ENTRIES, key="max_entries")
        st.sidebar.selectbox("Analysis Depth", ["Quick", "Standard", "Deep"], index=1, key="analysis_depth")
        show_charts = st.sidebar.checkbox("Enable charts (may be slower)", value=False, key="enable_charts")

        # About
        st.sidebar.subheader("ℹ️ About")
        st.sidebar.info(
            "Forensic AI Log Analyzer v1.0\n\n"
            "An AI-powered tool for automated security log analysis and incident investigation."
        )

    # ---------------------------------------------
    # Upload & Analyze
    # ---------------------------------------------
    def _render_upload_tab(self):
        st.header("Upload Log Files")

        uploaded_files = st.file_uploader(
            "Choose log files",
            accept_multiple_files=True,
            type=["csv", "json", "evtx", "log", "txt"],
            help="Supported formats: CSV, JSON, EVTX, LOG, TXT",
        )

        if uploaded_files:
            st.subheader("Uploaded Files")

            file_info = []
            temp_files: List[str] = []
            for uploaded_file in uploaded_files:
                with tempfile.NamedTemporaryFile(delete=False, suffix=f"_{uploaded_file.name}") as tmp_file:
                    tmp_file.write(uploaded_file.getbuffer())
                    temp_files.append(tmp_file.name)

                file_info.append(
                    {
                        "Name": uploaded_file.name,
                        "Size": f"{len(uploaded_file.getbuffer()) / 1024:.1f} KB",
                        "Type": uploaded_file.type or "Unknown",
                    }
                )

            df_files = pd.DataFrame(file_info)
            st.dataframe(df_files, width='stretch')

            col1, col2 = st.columns([2, 1])
            with col1:
                case_id = st.text_input("Case ID (optional)", placeholder="CASE_2025_001")
            with col2:
                st.write("")
                analyze_button = st.button("Start Analysis", type="primary", use_container_width=True)

            if analyze_button:
                with st.spinner("Running forensic analysis..."):
                    try:
                        progress_bar = st.progress(0)
                        status_text = st.empty()

                        status_text.text("Parsing log files...")
                        progress_bar.progress(25)

                        # Run investigation (your orchestrator should support file paths + settings)
                        report = self.orchestrator.investigate(temp_files, case_id or None)

                        status_text.text("Running AI analysis...")
                        progress_bar.progress(60)

                        status_text.text("Generating report...")
                        progress_bar.progress(100)

                        st.session_state["forensic_report"] = report
                        st.session_state["analysis_complete"] = True

                        # Cleanup temp files
                        for p in temp_files:
                            try:
                                Path(p).unlink(missing_ok=True)
                            except Exception:
                                pass

                        status_text.text("Analysis complete.")
                        st.success(f"Forensic analysis completed. Case ID: {getattr(report, 'case_id', 'N/A')}")
                        # Balloons animation intentionally not used
                    except Exception as e:  # pragma: no cover
                        st.error(f"Analysis failed: {e}")
                        logger.exception("Dashboard analysis error")
        else:
            st.info("Upload log files to begin analysis")

    # ---------------------------------------------
    # Analysis Results
    # ---------------------------------------------
    def _render_analysis_tab(self):
        if not st.session_state.get("analysis_complete", False):
            st.info("Run analysis first to view results")
            return

        report: ForensicReport = st.session_state.get("forensic_report")
        if not report:
            st.error("No analysis results available")
            return

        st.header("Analysis Results")

        # Executive Summary
        st.subheader("Executive Summary")
        st.info(str(getattr(report, "executive_summary", "No summary provided.")))

        # Key metrics
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Case ID", str(getattr(report, "case_id", "N/A")))
        with col2:
            st.metric("Total Events", f"{getattr(report, 'total_events', 0):,}")
        with col3:
            sev = (
                str(getattr(getattr(report.analysis.initial_analysis, "severity", ""), "value", "")).upper()
                if getattr(report, "analysis", None) and getattr(report.analysis, "initial_analysis", None)
                else "N/A"
            )
            st.metric("Severity", sev)
        with col4:
            conf = (
                f"{float(getattr(report.analysis.initial_analysis, 'confidence', 0.0)):.1%}"
                if getattr(report, "analysis", None) and getattr(report.analysis, "initial_analysis", None)
                else "N/A"
            )
            st.metric("Confidence", conf)

        # IOCs
        st.subheader("Indicators of Compromise")
        iocs = (
            getattr(getattr(report.analysis, "initial_analysis", {}), "iocs", [])
            if getattr(report, "analysis", None)
            else []
        )
        if iocs:
            ioc_data = []
            for ioc in iocs:
                ioc_data.append(
                    {
                        "Type": str(getattr(ioc, "type", "")).upper(),
                        "Value": str(getattr(ioc, "value", "")),
                        "Confidence": (
                            f"{float(getattr(ioc, 'confidence', 0.0)):.1%}" if getattr(ioc, "confidence", None) is not None else "N/A"
                        ),
                        "Context": str(getattr(ioc, "context", "")) or "N/A",
                    }
                )
            df_iocs = pd.DataFrame(ioc_data)
            st.dataframe(df_iocs, width='stretch')

            if st.session_state.get("enable_charts") and len(df_iocs) > 0:
                fig_iocs = px.pie(df_iocs, names="Type", title="IOCs by Type")
                st.plotly_chart(fig_iocs, use_container_width=True)
        else:
            st.info("No IOCs identified")

        # MITRE ATT&CK
        st.subheader("MITRE ATT&CK Mapping")
        mitre = (
            getattr(getattr(report.analysis, "initial_analysis", {}), "mitre_mappings", [])
            if getattr(report, "analysis", None)
            else []
        )
        if mitre:
            mitre_rows = []
            for m in mitre:
                mitre_rows.append(
                    {
                        "Tactic ID": getattr(m, "tactic_id", ""),
                        "Tactic": getattr(m, "tactic_name", ""),
                        "Technique ID": getattr(m, "technique_id", "N/A"),
                        "Technique": getattr(m, "technique_name", "N/A"),
                        "Confidence": (
                            f"{float(getattr(m, 'confidence', 0.0)):.1%}"
                            if getattr(m, "confidence", None) is not None
                            else "N/A"
                        ),
                    }
                )
            df_mitre = pd.DataFrame(mitre_rows)
            st.dataframe(df_mitre, width='stretch')
        else:
            st.info("No MITRE ATT&CK mappings identified")

        # Attack chain visualization
        st.subheader("Attack Chain")
        chain = getattr(getattr(report, "analysis", {}), "attack_chain", None)
        if chain:
            self._render_attack_chain(chain)
        else:
            st.info("Attack chain could not be reconstructed")

        # Recommendations
        st.subheader("Recommendations")
        recs = getattr(getattr(report, "analysis", {}), "recommendations", [])
        if recs:
            for i, r in enumerate(recs, 1):
                st.write(f"{i}. {r}")
        else:
            st.info("No specific recommendations generated")

    # ---------------------------------------------
    # Timeline View
    # ---------------------------------------------
    def _render_timeline_tab(self):
        if not st.session_state.get("analysis_complete", False):
            st.info("Run analysis first to view timeline")
            return

        report: ForensicReport = st.session_state.get("forensic_report")
        if not report or not getattr(report, "timeline", None):
            st.error("No timeline data available")
            return

        st.header("Event Timeline")

        # Controls
        col1, col2 = st.columns([3, 1])
        with col1:
            times = [
                datetime.fromisoformat(e.get("timestamp", "").replace("Z", "+00:00"))
                for e in report.timeline
                if e.get("timestamp")
            ]
            if not times:
                st.info("Timeline has no timestamps to plot")
                return
            min_time, max_time = min(times), max(times)
            time_range = st.slider(
                "Time Range",
                min_value=min_time,
                max_value=max_time,
                value=(min_time, max_time),
                format="YYYY-MM-DD HH:mm",
            )
        with col2:
            severity_filter = st.multiselect(
                "Severity Filter",
                ["critical", "high", "medium", "low", "info"],
                default=["critical", "high", "medium", "low", "info"],
            )

        # Filter
        filtered = []
        for ev in report.timeline:
            try:
                ev_time = datetime.fromisoformat(ev["timestamp"].replace("Z", "+00:00"))
            except Exception:
                continue
            if time_range[0] <= ev_time <= time_range[1] and ev.get("severity") in severity_filter:
                filtered.append(ev)

        if filtered:
            df = pd.DataFrame(filtered)
            df["timestamp"] = pd.to_datetime(df["timestamp"])
            if "sequence" not in df.columns:
                df["sequence"] = range(1, len(df) + 1)
            if "source" not in df.columns:
                df["source"] = "unknown"

            if st.session_state.get("enable_charts"):
                fig = px.scatter(
                    df,
                    x="timestamp",
                    y="source",
                    color="severity",
                    size="sequence",
                    hover_data=[c for c in ["event_type", "message", "event_id"] if c in df.columns],
                    title="Security Events Timeline",
                )
                fig.update_layout(height=600)
                st.plotly_chart(fig, use_container_width=True)

            st.subheader("📋 Event Details")
            events_per_page = 10
            total_pages = (len(filtered) - 1) // events_per_page + 1
            page = st.selectbox("Page", list(range(1, total_pages + 1)))
            start_idx = (page - 1) * events_per_page
            end_idx = min(start_idx + events_per_page, len(filtered))

            for ev in filtered[start_idx:end_idx]:
                title = f"{ev.get('timestamp')} - {ev.get('source', 'unknown')} ({str(ev.get('severity', '')).upper()})"
                with st.expander(title):
                    st.write(f"**Event Type:** {ev.get('event_type', 'N/A')}")
                    st.write(f"**Message:** {ev.get('message', 'N/A')}")
                    if ev.get("event_id"):
                        st.write(f"**Event ID:** {ev.get('event_id')}")
        else:
            st.info("No events match the selected filters or time range.")

    # ---------------------------------------------
    # Reports
    # ---------------------------------------------
    def _render_reports_tab(self):
        st.header("📋 Reports")

        if not st.session_state.get("analysis_complete", False):
            st.info("Run an analysis to generate reports")
            return

        report: ForensicReport = st.session_state.get("forensic_report")
        if not report:
            st.error("No report found in session")
            return

        # Preview JSON
        st.subheader("Preview (JSON)")
        st.code(_pretty_json(report), language="json")

        col1, col2 = st.columns(2)
        with col1:
            # DOCX download
            if Document is not None:
                try:
                    docx_bytes = self.report_generator.generate_docx(report)
                    st.download_button(
                        label="⬇️ Download Word Report (.docx)",
                        data=docx_bytes,
                        file_name=f"forensic_report_{getattr(report, 'case_id', 'case')}.docx",
                        mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                        width='stretch',
                    )
                except Exception as e:  # pragma: no cover
                    st.error(f"Failed to generate DOCX: {e}")
            else:
                st.warning("python-docx not installed. Cannot generate Word report.")
        with col2:
            json_bytes = self.report_generator.generate_json(report)
            st.download_button(
                label="⬇️ Download Full JSON",
                data=json_bytes,
                file_name=f"forensic_report_{getattr(report, 'case_id', 'case')}.json",
                mime="application/json",
                width='stretch',
            )

    # ---------------------------------------------
    # Attack Chain Rendering
    # ---------------------------------------------
    def _render_attack_chain(self, chain: Any):
        """Render attack chain using PyVis if available; otherwise fallback to table.

        Expected structures supported:
          • List[dict]: items with keys like {from, to, label, severity, weight, timestamp}
          • List[str]: sequential step names
        """
        # Normalize items
        if isinstance(chain, list) and chain and isinstance(chain[0], dict):
            edges = chain
            nodes = set()
            for e in edges:
                nodes.add(e.get("from", ""))
                nodes.add(e.get("to", ""))
        elif isinstance(chain, list) and chain and isinstance(chain[0], str):
            edges = [
                {"from": chain[i], "to": chain[i + 1], "label": "next"}
                for i in range(len(chain) - 1)
            ]
            nodes = set(chain)
        else:
            st.dataframe(pd.DataFrame(_safe_to_dict(chain)))
            return

        # Try interactive graph with PyVis
        if Network is not None:
            try:
                net = Network(height="520px", width="100%", bgcolor="#FFFFFF", font_color="#222222")
                net.barnes_hut()

                # Add nodes
                for n in nodes:
                    if not n:
                        continue
                    net.add_node(str(n), label=str(n))

                # Add edges
                for e in edges:
                    src = str(e.get("from", ""))
                    dst = str(e.get("to", ""))
                    lbl = str(e.get("label", ""))
                    if src and dst:
                        net.add_edge(src, dst, title=lbl, label=lbl)

                with tempfile.NamedTemporaryFile(delete=False, suffix="_attack_chain.html") as tmp:
                    net.write_html(tmp.name, open_browser=False, notebook=False)
                    html = Path(tmp.name).read_text(encoding="utf-8")
                components.html(html, height=540, scrolling=True)
                return
            except Exception:  # pragma: no cover
                logger.exception("PyVis render failed, falling back to table")

        # Fallback
        st.dataframe(pd.DataFrame(edges))


# -----------------------------------------------------------------------------
# Entrypoint
# -----------------------------------------------------------------------------
def main() -> None:
    """Run the Streamlit dashboard app."""
    ForensicDashboard().run()


if __name__ == "__main__":
    main()
