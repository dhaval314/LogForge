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
import os # Added for os.getenv

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
        tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
            "Upload & Analyze",
            "Analysis Results",
            "Timeline View",
            "Reports",
            "Semantic Search",
            "File History",
        ])

        with tab1:
            self._render_upload_tab()
        with tab2:
            self._render_analysis_tab()
        with tab3:
            self._render_timeline_tab()
        with tab4:
            self._render_reports_tab()
        with tab5:
            self._render_semantic_search_tab()
        with tab6:
            self._render_file_history_tab()

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
        st.sidebar.subheader("About")
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

            col1, col2, col3, col4 = st.columns([2, 1, 1, 1])
            with col1:
                case_id = st.text_input("Case ID (optional)", placeholder="CASE_2025_001")
            with col2:
                skip_dynamodb = st.checkbox("Skip DynamoDB", value=False, help="Skip storing logs for semantic search to speed up analysis")
            with col3:
                processing_mode = st.selectbox(
                    "Processing Mode",
                    ["High Performance", "Standard"],
                    help="High Performance: Parallel processing for large datasets. Standard: Sequential processing for smaller datasets."
                )
            with col4:
                st.write("")
                analyze_button = st.button("Start Analysis", type="primary", use_container_width=True)

            if analyze_button:
                with st.spinner("Running forensic analysis..."):
                    try:
                        progress_bar = st.progress(0)
                        status_text = st.empty()

                        status_text.text("Parsing log files and storing in DynamoDB...")
                        progress_bar.progress(25)

                        # Store logs in DynamoDB for semantic search
                        try:
                            from ddb_bedrock_logs import ingest_logs, ingest_logs_high_performance
                            
                            # Test DynamoDB connection first
                            status_text.text("Testing DynamoDB connection...")
                            try:
                                import boto3
                                from botocore.exceptions import ClientError, NoCredentialsError
                                
                                # Test basic DynamoDB access
                                ddb_test = boto3.client('dynamodb', region_name=os.getenv('AWS_REGION', 'us-east-1'))
                                ddb_test.describe_table(TableName=os.getenv('DYNAMODB_TABLE_NAME', 'SecurityLogs'))
                                st.success("DynamoDB connection verified")
                            except (ClientError, NoCredentialsError) as e:
                                st.error(f"DynamoDB connection failed: {str(e)[:100]}...")
                                st.warning("Please check your AWS credentials and DynamoDB table configuration")
                                st.session_state["stored_logs_count"] = 0
                                raise e
                            
                            # Read and parse log files
                            status_text.text("Reading and parsing log files...")
                            log_entries = []
                            for temp_file in temp_files:
                                try:
                                    with open(temp_file, 'r', encoding='utf-8', errors='ignore') as f:
                                        for line_num, line in enumerate(f, 1):
                                            line = line.strip()
                                            if line and len(line) > 10:  # Skip empty/short lines
                                                log_entries.append(line)
                                            
                                            # Limit to prevent overwhelming the system
                                            if len(log_entries) >= 1000:
                                                break
                                    
                                    if len(log_entries) >= 1000:
                                        break
                                except Exception as e:
                                    logger.warning(f"Could not read file {temp_file}: {e}")
                            
                            st.info(f"Parsed {len(log_entries)} valid log entries")
                            
                            if log_entries and not skip_dynamodb:
                                # Store in DynamoDB with embeddings
                                status_text.text("Generating embeddings and storing in DynamoDB...")
                                progress_bar.progress(35)
                                
                                try:
                                    # Store logs using selected processing mode
                                    if processing_mode == "High Performance":
                                        # High-performance mode: Parallel processing for large datasets
                                        max_workers = min(8, len(log_entries) // 100 + 1)  # Scale workers based on dataset size
                                        stored_items = ingest_logs_high_performance(log_entries, max_workers=max_workers)
                                        logger.info(f"Using high-performance mode with {max_workers} workers")
                                    else:
                                        # Standard mode: Sequential processing for smaller datasets
                                        stored_items = ingest_logs(log_entries)
                                        logger.info("Using standard sequential processing mode")
                                    
                                    if isinstance(stored_items, dict) and stored_items.get("stored_items"):
                                        # High-performance function returned detailed results
                                        successful_count = stored_items["successful"]
                                        failed_count = stored_items["failed"]
                                        st.session_state["stored_logs_count"] = successful_count
                                        
                                        if failed_count > 0:
                                            st.warning(f"Stored {successful_count} logs in DynamoDB, {failed_count} failed")
                                        else:
                                            st.success(f"Stored {successful_count} logs in DynamoDB")
                                        
                                        logger.info(f"Successfully stored {successful_count} log entries in DynamoDB using high-performance batching")
                                        progress_bar.progress(50)
                                    elif stored_items:
                                        # Regular function returned simple list
                                        st.session_state["stored_logs_count"] = len(stored_items)
                                        logger.info(f"Successfully stored {len(stored_items)} log entries in DynamoDB")
                                        st.success(f"Stored {len(stored_items)} logs in DynamoDB")
                                        progress_bar.progress(50)
                                    else:
                                        st.warning("No logs were stored in DynamoDB")
                                        st.session_state["stored_logs_count"] = 0
                                        
                                except Exception as e:
                                    logger.error(f"Failed to store logs in DynamoDB: {e}")
                                    st.error(f"Failed to store logs in DynamoDB: {str(e)}")
                                    st.session_state["stored_logs_count"] = 0
                                    # Continue with analysis even if DynamoDB fails
                            elif skip_dynamodb:
                                st.info("Skipping DynamoDB storage as requested")
                                st.session_state["stored_logs_count"] = 0
                            else:
                                st.warning("No valid log entries found to store")
                                st.session_state["stored_logs_count"] = 0
                                
                        except Exception as e:
                            logger.error(f"Failed to store logs in DynamoDB: {e}")
                            st.warning("Logs could not be stored in DynamoDB for semantic search")
                            st.session_state["stored_logs_count"] = 0

                        # Track file history
                        self._update_file_history(uploaded_files, case_id, len(log_entries) if 'log_entries' in locals() else 0)

                        status_text.text("Running forensic investigation...")
                        progress_bar.progress(50)

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
                        success_msg = f"Forensic analysis completed. Case ID: {getattr(report, 'case_id', 'N/A')}"
                        if st.session_state.get("stored_logs_count"):
                            success_msg += f" | {st.session_state['stored_logs_count']} logs stored in DynamoDB"
                        st.success(success_msg)
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

            st.subheader("Event Details")
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
        st.header("Reports")

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
                        label="Download Word Report (.docx)",
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
                label="Download Full JSON",
                data=json_bytes,
                file_name=f"forensic_report_{getattr(report, 'case_id', 'case')}.json",
                mime="application/json",
                width='stretch',
            )

    # ---------------------------------------------
    # Semantic Search
    # ---------------------------------------------
    def _render_semantic_search_tab(self):
        st.header("Semantic Search")
        st.markdown("---")

        # Search source information
        st.subheader("Search Sources")
        col1, col2 = st.columns(2)
        
        with col1:
            st.info("**DynamoDB + Bedrock**: Your uploaded security logs with AI-generated embeddings")
            if st.session_state.get("stored_logs_count"):
                st.success(f"**{st.session_state['stored_logs_count']} logs** available for search")
            else:
                st.warning("**No logs stored yet**. Upload and analyze logs first to enable semantic search.")
        
        with col2:
            st.info("**Local Knowledge Base**: Pre-populated cybersecurity knowledge (MITRE, attack patterns)")
            st.success("**5 knowledge documents** available")

        st.markdown("---")

        # Manual log storage for testing
        st.subheader("Store Logs Manually (Testing)")
        
        # Test DynamoDB connection
        col1, col2 = st.columns(2)
        with col1:
            if st.button("Test DynamoDB Connection"):
                try:
                    from ddb_bedrock_logs import search_logs
                    # Try a simple search to test connection
                    results = search_logs("test", top_k=1)
                    st.success("DynamoDB connection working!")
                    st.info(f"Found {len(results)} existing logs")
                except Exception as e:
                    st.error(f"DynamoDB connection failed: {str(e)[:100]}...")
                    logger.exception("DynamoDB connection test failed")
        
        with col2:
            if st.button("Store Sample Security Logs"):
                try:
                    from ddb_bedrock_logs import ingest_logs
                    
                    sample_logs = [
                        "2025-01-01 10:00:00 INFO User login succeeded for alice from 10.0.0.1",
                        "2025-01-01 10:05:10 WARN Multiple failed SSH attempts detected from 203.0.113.5",
                        "2025-01-01 11:22:45 ERROR PowerShell execution blocked by AppLocker on host WIN10-01",
                        "2025-01-01 12:15:30 WARN Unusual network activity detected from internal host 192.168.1.100",
                        "2025-01-01 13:45:12 INFO Database backup completed successfully",
                        "2025-01-01 14:20:00 ERROR Authentication failure for admin account from 198.51.100.23",
                        "2025-01-01 15:30:45 WARN Large data export initiated by user john.doe",
                        "2025-01-01 16:12:18 INFO Firewall rule updated to block suspicious IP 185.220.101.182"
                    ]
                    
                    with st.spinner("Storing sample logs with embeddings..."):
                        stored_items = ingest_logs(sample_logs)
                        st.session_state["stored_logs_count"] = len(stored_items)
                        st.success(f"Stored {len(stored_items)} sample logs in DynamoDB")
                        
                except Exception as e:
                    st.error(f"Failed to store sample logs: {e}")
                    logger.exception("Sample log storage error")

        # Real semantic search interface
        st.subheader("Search Your Logs")
        
        if not st.session_state.get("stored_logs_count", 0):
            st.warning("No logs available for search. Please upload and analyze logs first or use the manual storage above.")
            return

        # Search input
        search_query = st.text_input(
            "Enter search query", 
            placeholder="e.g., 'failed login', 'suspicious PowerShell', 'network anomaly'",
            help="Search for semantically similar security events in your uploaded logs"
        )

        if search_query:
            try:
                from ddb_bedrock_logs import search_logs
                
                with st.spinner("Searching logs with AI embeddings..."):
                    # Search DynamoDB for similar logs
                    results = search_logs(search_query, top_k=10)
                
                if results:
                    st.success(f"Found {len(results)} relevant log entries")
                    
                    # Display results with similarity scores
                    for i, result in enumerate(results, 1):
                        with st.expander(f"Result {i} - Score: {result.get('score', 0):.3f}"):
                            col1, col2 = st.columns([3, 1])
                            with col1:
                                st.write(f"**Log ID:** {result.get('logId', 'N/A')}")
                                st.write(f"**Text:** {result.get('logText', 'N/A')}")
                                st.write(f"**Confidence:** {result.get('confidence', 'N/A')}")
                            with col2:
                                score = result.get('score', 0)
                                if score > 0.8:
                                    st.success("High Match")
                                elif score > 0.6:
                                    st.warning("Medium Match")
                                else:
                                    st.info("Low Match")
                    
                    # Summary statistics
                    st.subheader("Search Summary")
                    high_matches = len([r for r in results if r.get('score', 0) > 0.8])
                    medium_matches = len([r for r in results if 0.6 < r.get('score', 0) <= 0.8])
                    low_matches = len([r for r in results if r.get('score', 0) <= 0.6])
                    
                    col1, col2, col3 = st.columns(3)
                    with col1:
                        st.metric("High Matches", high_matches)
                    with col2:
                        st.metric("Medium Matches", medium_matches)
                    with col3:
                        st.metric("Low Matches", low_matches)
                        
                else:
                    st.info("No relevant logs found for your query. Try different keywords or check if logs contain similar content.")
                    
            except Exception as e:
                st.error(f"Search failed: {e}")
                logger.exception("Semantic search error")

        # Local knowledge base search
        st.markdown("---")
        st.subheader("Search Cybersecurity Knowledge Base")
        
        kb_query = st.text_input(
            "Knowledge base query",
            placeholder="e.g., 'MITRE T1078', 'lateral movement', 'PowerShell attacks'",
            help="Search pre-populated cybersecurity knowledge and attack patterns"
        )
        
        if kb_query:
            try:
                from rag_enrichment import LocalKnowledgeBase
                
                kb = LocalKnowledgeBase()
                kb_results = kb.query(kb_query, n_results=3)
                
                if kb_results:
                    st.success(f"Found {len(kb_results)} knowledge base entries")
                    
                    for i, result in enumerate(kb_results, 1):
                        with st.expander(f"Knowledge {i} - Relevance: {1 - result.get('distance', 0):.3f}"):
                            st.write(f"**Content:** {result.get('content', 'N/A')}")
                            st.write(f"**Type:** {result.get('metadata', {}).get('type', 'N/A')}")
                            if result.get('metadata', {}).get('technique_id'):
                                st.write(f"**Technique ID:** {result['metadata']['technique_id']}")
                else:
                    st.info("No relevant knowledge base entries found.")
                    
            except Exception as e:
                st.error(f"Knowledge base search failed: {e}")
                logger.exception("Knowledge base search error")

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

    def _update_file_history(self, uploaded_files, case_id: str, log_count: int):
        """Update file history with newly uploaded files."""
        if "file_history" not in st.session_state:
            st.session_state["file_history"] = []
        
        current_time = datetime.now()
        
        for uploaded_file in uploaded_files:
            file_info = {
                "id": f"file_{current_time.timestamp()}_{uploaded_file.name}",
                "filename": uploaded_file.name,
                "size_bytes": len(uploaded_file.getbuffer()),
                "size_mb": len(uploaded_file.getbuffer()) / (1024 * 1024),
                "file_type": uploaded_file.type or "Unknown",
                "upload_time": current_time.isoformat(),
                "case_id": case_id or "No Case ID",
                "log_entries_processed": log_count,
                "analysis_completed": True,
                "status": "Completed"
            }
            
            # Check if file already exists in history (by name and size)
            existing_file = next(
                (f for f in st.session_state["file_history"] 
                 if f["filename"] == file_info["filename"] and 
                 abs(f["size_bytes"] - file_info["size_bytes"]) < 100),  # Allow 100 byte difference
                None
            )
            
            if existing_file:
                # Update existing entry
                existing_file.update({
                    "upload_time": current_time.isoformat(),
                    "case_id": case_id or "No Case ID",
                    "log_entries_processed": log_count,
                    "analysis_completed": True,
                    "status": "Re-analyzed"
                })
            else:
                # Add new entry
                st.session_state["file_history"].append(file_info)
        
        # Keep only last 50 files to prevent memory issues
        if len(st.session_state["file_history"]) > 50:
            st.session_state["file_history"] = st.session_state["file_history"][-50:]
        
        logger.info(f"Updated file history with {len(uploaded_files)} files")

    def _get_file_history(self) -> List[Dict[str, Any]]:
        """Get the current file history."""
        return st.session_state.get("file_history", [])

    def _render_file_history_tab(self):
        """Render the file history tab."""
        st.header("File History")
        st.markdown("---")
        
        # File history controls
        col1, col2, col3 = st.columns([2, 1, 1])
        
        with col1:
            st.subheader("Previously Uploaded Files")
        
        with col2:
            if st.button("Refresh History", use_container_width=True):
                st.rerun()
        
        with col3:
            if st.button("Clear History", use_container_width=True):
                if st.session_state.get("file_history"):
                    st.session_state["file_history"] = []
                    st.success("File history cleared!")
                    st.rerun()
        
        # Get file history
        file_history = self._get_file_history()
        
        if not file_history:
            st.info("No files have been uploaded yet. Upload files in the 'Upload & Analyze' tab to see them here.")
            return
        
        # File history statistics
        st.subheader("Statistics")
        total_files = len(file_history)
        total_size_mb = sum(f["size_mb"] for f in file_history)
        unique_cases = len(set(f["case_id"] for f in file_history))
        total_logs = sum(f["log_entries_processed"] for f in file_history)
        
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Total Files", total_files)
        with col2:
            st.metric("Total Size", f"{total_size_mb:.1f} MB")
        with col3:
            st.metric("Unique Cases", unique_cases)
        with col4:
            st.metric("Total Log Entries", f"{total_logs:,}")
        
        # File filtering
        st.markdown("---")
        st.subheader("Filter Files")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            # Filter by case ID
            case_ids = ["All Cases"] + sorted(list(set(f["case_id"] for f in file_history)))
            selected_case = st.selectbox("Case ID Filter", case_ids)
        
        with col2:
            # Filter by file type
            file_types = ["All Types"] + sorted(list(set(f["file_type"] for f in file_history)))
            selected_type = st.selectbox("File Type Filter", file_types)
        
        with col3:
            # Filter by status
            statuses = ["All Statuses"] + sorted(list(set(f["status"] for f in file_history)))
            selected_status = st.selectbox("Status Filter", statuses)
        
        # Apply filters
        filtered_files = file_history.copy()
        
        if selected_case != "All Cases":
            filtered_files = [f for f in filtered_files if f["case_id"] == selected_case]
        
        if selected_type != "All Types":
            filtered_files = [f for f in filtered_files if f["file_type"] == selected_type]
        
        if selected_status != "All Statuses":
            filtered_files = [f for f in filtered_files if f["status"] == selected_status]
        
        # Display filtered files
        st.markdown("---")
        st.subheader(f"Files ({len(filtered_files)} of {total_files})")
        
        if filtered_files:
            # Sort by upload time (newest first)
            filtered_files.sort(key=lambda x: x["upload_time"], reverse=True)
            
            # Create DataFrame for display
            display_data = []
            for file_info in filtered_files:
                display_data.append({
                    "Filename": file_info["filename"],
                    "Size": f"{file_info['size_mb']:.2f} MB",
                    "Type": file_info["file_type"],
                    "Case ID": file_info["case_id"],
                    "Log Entries": f"{file_info['log_entries_processed']:,}",
                    "Upload Time": file_info["upload_time"][:19].replace("T", " "),
                    "Status": file_info["status"]
                })
            
            df_files = pd.DataFrame(display_data)
            st.dataframe(df_files, use_container_width=True, hide_index=True)
            
            # File details in expandable sections
            st.subheader("File Details")
            
            for i, file_info in enumerate(filtered_files):
                with st.expander(f"{file_info['filename']} - {file_info['status']}"):
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        st.write(f"**File ID:** {file_info['id']}")
                        st.write(f"**Size:** {file_info['size_mb']:.2f} MB ({file_info['size_bytes']:,} bytes)")
                        st.write(f"**Type:** {file_info['file_type']}")
                        st.write(f"**Case ID:** {file_info['case_id']}")
                    
                    with col2:
                        st.write(f"**Upload Time:** {file_info['upload_time'][:19].replace('T', ' ')}")
                        st.write(f"**Log Entries:** {file_info['log_entries_processed']:,}")
                        st.write(f"**Analysis Status:** {file_info['status']}")
                        st.write(f"**Analysis Completed:** {'✅ Yes' if file_info['analysis_completed'] else '❌ No'}")
                    
                    # Action buttons
                    col1, col2, col3 = st.columns(3)
                    
                    with col1:
                        if st.button(f"Re-analyze", key=f"reanalyze_{i}"):
                            st.info("Re-analysis feature coming soon! This will allow you to re-analyze previously uploaded files.")
                    
                    with col2:
                        if st.button(f"View Report", key=f"view_report_{i}"):
                            st.info("Report viewing feature coming soon! This will show the analysis report for this file.")
                    
                    with col3:
                        if st.button(f"Remove", key=f"remove_{i}"):
                            # Remove file from history
                            st.session_state["file_history"] = [f for f in st.session_state["file_history"] if f["id"] != file_info["id"]]
                            st.success(f"Removed {file_info['filename']} from history!")
                            st.rerun()
        else:
            st.warning("No files match the selected filters.")
        
        # Export functionality
        st.markdown("---")
        st.subheader("Export History")
        
        col1, col2 = st.columns(2)
        
        with col1:
            if filtered_files:
                # Export filtered files as CSV
                df_export = pd.DataFrame(filtered_files)
                csv_data = df_export.to_csv(index=False)
                st.download_button(
                    label="Download CSV",
                    data=csv_data,
                    file_name=f"file_history_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                    mime="text/csv",
                    use_container_width=True
                )
        
        with col2:
            if filtered_files:
                # Export as JSON
                json_data = json.dumps(filtered_files, indent=2, default=str)
                st.download_button(
                    label="Download JSON",
                    data=json_data,
                    file_name=f"file_history_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                    mime="application/json",
                    use_container_width=True
                )


# -----------------------------------------------------------------------------
# Entrypoint
# -----------------------------------------------------------------------------
def main() -> None:
    """Run the Streamlit dashboard app."""
    ForensicDashboard().run()


if __name__ == "__main__":
    main()
