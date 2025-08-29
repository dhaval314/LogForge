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
from aws_s3_utils import get_s3_utils, is_s3_available  # type: ignore


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
        tab1, tab2, tab3, tab4, tab5, tab6, tab7 = st.tabs([
            "Upload & Analyze",
            "Analysis Results",
            "Timeline View",
            "Reports",
            "Semantic Search",
            "Saved Results",
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
            self._render_saved_results_tab()
        with tab7:
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

        # S3 Status and Configuration
        s3_available = is_s3_available()
        if s3_available:
            st.success("✅ AWS S3 is configured and available")
        else:
            st.info("ℹ️ AWS S3 is not configured. Files will be processed locally only.")
            st.info("To enable S3, set AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, and AWS_S3_BUCKET environment variables.")

        # S3 File Selection (if available)
        if s3_available:
            st.subheader("📁 Select Files from S3")
            
            s3_utils = get_s3_utils()
            s3_files = s3_utils.list_files()
            
            if s3_files:
                selected_s3_file = st.selectbox(
                    "Choose a file from S3",
                    options=[""] + s3_files,
                    format_func=lambda x: "Select a file..." if x == "" else x,
                    help="Select a file from your S3 bucket to analyze"
                )
                
                if selected_s3_file:
                    col1, col2 = st.columns([3, 1])
                    with col1:
                        st.info(f"Selected: {selected_s3_file}")
                    with col2:
                        if st.button("Download & Analyze", key="s3_download_analyze"):
                            with st.spinner(f"Downloading {selected_s3_file} from S3..."):
                                try:
                                    downloaded_path = s3_utils.download_file(key=selected_s3_file)
                                    if downloaded_path:
                                        st.success(f"Downloaded to: {downloaded_path}")
                                        # Add to temp_files for analysis
                                        if 'temp_files' not in st.session_state:
                                            st.session_state.temp_files = []
                                        st.session_state.temp_files.append(downloaded_path)
                                        
                                        # Add file info
                                        if 'file_info' not in st.session_state:
                                            st.session_state.file_info = []
                                        file_info_item = {
                                            "Name": selected_s3_file,
                                            "Size": "Unknown",
                                            "Type": "S3 File",
                                            "Source": "S3 Bucket"
                                        }
                                        st.session_state.file_info.append(file_info_item)
                                        st.rerun()
                                    else:
                                        st.error("Failed to download file from S3")
                                except Exception as e:
                                    st.error(f"Error downloading file: {e}")
                                    logger.exception("S3 download error")
            else:
                st.info("No files found in S3 bucket")

        # File upload section
        st.subheader("📤 Upload Files")
        
        # ZIP file upload
        zip_file = st.file_uploader(
            "Upload ZIP file containing log files",
            type=["zip"],
            help="Upload a ZIP file containing multiple log files (network, system, process, services, etc.)",
            key="zip_uploader"
        )
        
        # Individual file upload
        uploaded_files = st.file_uploader(
            "Or upload individual log files",
            accept_multiple_files=True,
            type=["csv", "json", "evtx", "log", "txt"],
            help="Supported formats: CSV, JSON, EVTX, LOG, TXT",
            key="file_uploader"
        )

        # Process uploaded files
        temp_files: List[str] = []
        file_info = []
        zip_processor = None
        zip_results = None
        
        # Add S3 files from session state
        if 'temp_files' in st.session_state and st.session_state.temp_files:
            temp_files.extend(st.session_state.temp_files)
        if 'file_info' in st.session_state and st.session_state.file_info:
            file_info.extend(st.session_state.file_info)
        
        # Handle ZIP file upload
        if zip_file:
            st.subheader("ZIP File Processing")
            
            try:
                # Save ZIP file to temporary location
                with tempfile.NamedTemporaryFile(delete=False, suffix=".zip") as tmp_zip:
                    tmp_zip.write(zip_file.getbuffer())
                    zip_path = tmp_zip.name
                
                # Process ZIP file
                from zip_processor import ZIPProcessor
                zip_processor = ZIPProcessor(max_file_size_mb=100, max_total_size_mb=500)
                zip_results = zip_processor.extract_and_categorize(zip_path)
                
                if zip_results["success"]:
                    st.success(f"Successfully extracted {zip_results['file_count']} files from ZIP")
                    
                    # Display ZIP summary
                    with st.expander("ZIP Extraction Summary", expanded=True):
                        st.text(zip_processor.generate_summary_report(zip_results))
                    
                    # Display categorized files
                    st.subheader("Extracted Files by Category")
                    
                    for category, files in zip_results["categorized_files"].items():
                        with st.expander(f"{category.title()} ({len(files)} files)", expanded=True):
                            category_df = pd.DataFrame([
                                {
                                    "Name": f["name"],
                                    "Size": f"{f['size_mb']:.2f} MB",
                                    "Path": f["relative_path"]
                                }
                                for f in files
                            ])
                            st.dataframe(category_df, width='stretch')
                    
                    # Get readable files for analysis
                    readable_files = zip_processor.get_readable_files(zip_results["extracted_files"])
                    temp_files.extend(readable_files)
                    
                    # Add file info for display
                    for file_info_item in zip_results["extracted_files"]:
                        file_info.append({
                            "Name": file_info_item["name"],
                            "Size": f"{file_info_item['size_mb']:.2f} MB",
                            "Type": file_info_item["category"].title(),
                            "Source": "ZIP Archive"
                        })
                    
                    # Upload ZIP contents to S3 if requested
                    if s3_available and st.checkbox("Upload ZIP contents to S3", value=False, key="zip_s3_upload"):
                        s3_utils = get_s3_utils()
                        uploaded_count = 0
                        for file_path in readable_files:
                            try:
                                file_name = Path(file_path).name
                                s3_key = f"zip_extracts/{datetime.now().strftime('%Y%m%d_%H%M%S')}/{file_name}"
                                if s3_utils.upload_file(file_path, key=s3_key):
                                    uploaded_count += 1
                            except Exception as e:
                                logger.warning(f"Failed to upload {file_path} to S3: {e}")
                        
                        if uploaded_count > 0:
                            st.success(f"✅ Uploaded {uploaded_count} files from ZIP to S3")
                    
                    # Clean up temporary ZIP file
                    os.unlink(zip_path)
                    
                else:
                    st.error(f"Failed to extract ZIP file: {zip_results['error']}")
                    if zip_results["temp_dir"]:
                        zip_processor.cleanup_temp_dir(zip_results["temp_dir"])
                    
            except Exception as e:
                st.error(f"Error processing ZIP file: {str(e)}")
                logger.exception("ZIP processing error")
        
        # Handle individual file uploads
        if uploaded_files:
            st.subheader("Individual Files")
            
            # S3 upload option
            if s3_available:
                upload_to_s3 = st.checkbox(
                    "Upload files to S3 after processing",
                    value=False,
                    help="Upload processed files to your S3 bucket for future access"
                )
            else:
                upload_to_s3 = False
            
            for uploaded_file in uploaded_files:
                with tempfile.NamedTemporaryFile(delete=False, suffix=f"_{uploaded_file.name}") as tmp_file:
                    tmp_file.write(uploaded_file.getbuffer())
                    temp_files.append(tmp_file.name)
                    
                    # Upload to S3 if requested
                    if upload_to_s3 and s3_available:
                        try:
                            s3_utils = get_s3_utils()
                            s3_key = f"uploads/{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uploaded_file.name}"
                            if s3_utils.upload_file(tmp_file.name, key=s3_key):
                                st.success(f"✅ Uploaded {uploaded_file.name} to S3 as {s3_key}")
                            else:
                                st.warning(f"⚠️ Failed to upload {uploaded_file.name} to S3")
                        except Exception as e:
                            st.warning(f"⚠️ S3 upload error for {uploaded_file.name}: {e}")
                            logger.exception(f"S3 upload error for {uploaded_file.name}")

                file_info.append(
                    {
                        "Name": uploaded_file.name,
                        "Size": f"{len(uploaded_file.getbuffer()) / 1024:.1f} KB",
                        "Type": uploaded_file.type or "Unknown",
                        "Source": "Direct Upload"
                    }
                )
        
        # Display all files if any were uploaded
        if file_info:
            st.subheader("All Files for Analysis")
            df_files = pd.DataFrame(file_info)
            st.dataframe(df_files, width='stretch')
            
            # Check for EVTX files and show warning
            evtx_files = [f for f in file_info if f["Type"].lower() == "evtx"]
            if evtx_files and not skip_evtx:
                st.warning("**EVTX files detected**: Windows Event Log files (.evtx) can cause parsing delays or timeouts. If analysis gets stuck, try enabling 'Skip EVTX Files' option above.")
            
            # Show file statistics
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Total Files", len(file_info))
            with col2:
                total_size = sum(float(f["Size"].split()[0]) for f in file_info if "MB" in f["Size"])
                st.metric("Total Size", f"{total_size:.2f} MB")
            with col3:
                categories = set(f["Type"] for f in file_info)
                st.metric("Categories", len(categories))

            # Analysis controls
            st.markdown("---")
            st.subheader("Analysis Configuration")
            
            col1, col2, col3, col4, col5, col6 = st.columns([2, 1, 1, 1, 1, 1])
            with col1:
                case_id = st.text_input("Case ID (optional)", placeholder="CASE_2025_001")
            with col2:
                skip_chromadb = st.checkbox("Skip ChromaDB", value=False, help="Skip storing logs for semantic search to speed up analysis")
            with col3:
                skip_evtx = st.checkbox("Skip EVTX Files", value=False, help="Skip Windows Event Log files to avoid parsing issues. Enable if analysis gets stuck on .evtx files.")
            with col4:
                skip_rag = st.checkbox("Skip RAG Enrichment", value=False, help="Skip RAG enrichment to avoid hanging. Enable if analysis gets stuck at 'RAG enrichment completed successfully'.")
            with col5:
                processing_mode = st.selectbox(
                    "Processing Mode",
                    ["High Performance", "Standard"],
                    help="High Performance: Parallel processing for large datasets. Standard: Sequential processing for smaller datasets."
                )
            with col6:
                st.write("")
                analyze_button = st.button("Start Analysis", type="primary")

            if analyze_button:
                with st.spinner("Running forensic analysis..."):
                    try:
                        progress_bar = st.progress(0)
                        status_text = st.empty()

                        status_text.text("Parsing log files and storing in DynamoDB...")
                        progress_bar.progress(25)

                        # Store logs in ChromaDB for semantic search
                        try:
                            from chromadb_logs import ingest_logs, ingest_logs_high_performance
                            
                            # Test ChromaDB connection first
                            status_text.text("Testing ChromaDB connection...")
                            try:
                                from chromadb_logs import get_log_store
                                log_store = get_log_store()
                                stats = log_store.get_collection_stats()
                                st.success(f"ChromaDB connection verified - {stats.get('total_logs', 0)} existing logs")
                            except Exception as e:
                                st.error(f"ChromaDB connection failed: {str(e)[:100]}...")
                                st.warning("Please check your ChromaDB configuration")
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
                            
                            if log_entries and not skip_chromadb:
                                # Store in ChromaDB with embeddings
                                status_text.text("Generating embeddings and storing in ChromaDB...")
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
                                            st.warning(f"Stored {successful_count} logs in ChromaDB, {failed_count} failed")
                                        else:
                                            st.success(f"Stored {successful_count} logs in ChromaDB")
                                        
                                        logger.info(f"Successfully stored {successful_count} log entries in ChromaDB using high-performance batching")
                                        progress_bar.progress(50)
                                    elif stored_items:
                                        # Regular function returned simple list
                                        st.session_state["stored_logs_count"] = len(stored_items)
                                        logger.info(f"Successfully stored {len(stored_items)} log entries in ChromaDB")
                                        st.success(f"Stored {len(stored_items)} logs in ChromaDB")
                                        progress_bar.progress(50)
                                    else:
                                        st.warning("No logs were stored in ChromaDB")
                                        st.session_state["stored_logs_count"] = 0
                                        
                                except Exception as e:
                                    logger.error(f"Failed to store logs in ChromaDB: {e}")
                                    st.error(f"Failed to store logs in ChromaDB: {str(e)}")
                                    st.session_state["stored_logs_count"] = 0
                                    # Continue with analysis even if ChromaDB fails
                            elif skip_chromadb:
                                st.info("Skipping ChromaDB storage as requested")
                                st.session_state["stored_logs_count"] = 0
                            else:
                                st.warning("No valid log entries found to store")
                                st.session_state["stored_logs_count"] = 0
                                
                        except Exception as e:
                            logger.error(f"Failed to store logs in ChromaDB: {e}")
                            st.warning("Logs could not be stored in ChromaDB for semantic search")
                            st.session_state["stored_logs_count"] = 0

                        # Track file history
                        all_uploaded_files = []
                        if zip_file:
                            all_uploaded_files.append(zip_file)
                        if uploaded_files:
                            all_uploaded_files.extend(uploaded_files)
                        
                        self._update_file_history(all_uploaded_files, case_id, len(log_entries) if 'log_entries' in locals() else 0)

                        status_text.text("Running forensic investigation...")
                        progress_bar.progress(50)

                        # Run investigation with EVTX skip option
                        if skip_evtx:
                            # Create a new orchestrator with EVTX files skipped
                            from agents import ForensicOrchestrator
                            evtx_skip_orchestrator = ForensicOrchestrator(skip_evtx_files=True)
                            report = evtx_skip_orchestrator.investigate(temp_files, case_id or None, skip_rag)
                        else:
                            # Use the default orchestrator
                            report = self.orchestrator.investigate(temp_files, case_id or None, skip_rag)

                        status_text.text("Running AI analysis...")
                        progress_bar.progress(60)

                        # Generate report (timeout handling is now in the RAG pipeline)
                        status_text.text("Generating report...")
                        progress_bar.progress(100)

                        st.session_state["forensic_report"] = report
                        st.session_state["analysis_complete"] = True

                        # Save analysis result to database
                        try:
                            from results_storage import get_results_storage
                            storage = get_results_storage()
                            
                            # Prepare analysis configuration
                            analysis_config = {
                                "processing_mode": processing_mode,
                                "skip_chromadb": skip_chromadb,
                                "max_entries": st.session_state.get("max_entries", Config.MAX_LOG_ENTRIES),
                                "analysis_depth": st.session_state.get("analysis_depth", "Standard")
                            }
                            
                            # Save the result
                            analysis_id = storage.save_analysis_result(
                                case_id=case_id or f"auto_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                                case_name=case_id or "Auto-generated Case",
                                analysis_result=report,
                                file_paths=temp_files,
                                zip_file_path=zip_file.name if zip_file else None,
                                analysis_config=analysis_config
                            )
                            
                            st.session_state["saved_analysis_id"] = analysis_id
                            st.success(f"Analysis saved with ID: {analysis_id}")
                            
                        except Exception as e:
                            logger.error(f"Failed to save analysis result: {e}")
                            st.warning("Analysis completed but could not be saved to database")

                        # Cleanup temp files
                        for p in temp_files:
                            try:
                                Path(p).unlink(missing_ok=True)
                            except Exception:
                                pass
                        
                        # Cleanup ZIP extraction directory if it exists
                        if zip_processor and zip_results and zip_results.get("temp_dir"):
                            zip_processor.cleanup_temp_dir(zip_results["temp_dir"])
                        
                        # Cleanup S3 session state
                        if 'temp_files' in st.session_state:
                            del st.session_state.temp_files
                        if 'file_info' in st.session_state:
                            del st.session_state.file_info
                        
                        # Cleanup S3 session state
                        if 'temp_files' in st.session_state:
                            del st.session_state.temp_files
                        if 'file_info' in st.session_state:
                            del st.session_state.file_info

                        status_text.text("Analysis complete.")
                        success_msg = f"Forensic analysis completed. Case ID: {getattr(report, 'case_id', 'N/A')}"
                        if st.session_state.get("stored_logs_count"):
                            success_msg += f" | {st.session_state['stored_logs_count']} logs stored in ChromaDB"
                        st.success(success_msg)
                    except Exception as e:  # pragma: no cover
                        st.error(f"Analysis failed: {e}")
                        logger.exception("Dashboard analysis error")
        else:
            st.info("Upload log files or a ZIP archive to begin analysis")
            
            # Show supported formats
            st.markdown("---")
            st.subheader("Supported Formats")
            
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown("**Individual Files:**")
                st.markdown("• CSV files (.csv)")
                st.markdown("• JSON files (.json)")
                st.markdown("• Windows Event Logs (.evtx)")
                st.markdown("• Log files (.log)")
                st.markdown("• Text files (.txt)")
            
            with col2:
                st.markdown("**ZIP Archives:**")
                st.markdown("• Network logs (pcap, netflow)")
                st.markdown("• System logs (syslog, events)")
                st.markdown("• Process lists (tasklist, ps)")
                st.markdown("• Service logs (daemon, init)")
                st.markdown("• Authentication logs (auth, login)")
                st.markdown("• Any combination of the above")

    # ---------------------------------------------
    # Analysis Results
    # ---------------------------------------------
    def _render_analysis_tab(self):
        # Check if we're viewing a saved analysis
        if st.session_state.get("view_analysis_id"):
            self._render_saved_analysis(st.session_state["view_analysis_id"])
            return
        
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
                st.plotly_chart(fig_iocs, width='stretch')
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
                st.plotly_chart(fig, width='stretch')

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
            st.info("**ChromaDB**: Your uploaded security logs with AI-generated embeddings")
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
        
        # Test ChromaDB connection
        col1, col2 = st.columns(2)
        with col1:
            if st.button("Test ChromaDB Connection"):
                try:
                    from chromadb_logs import search_logs
                    # Try a simple search to test connection
                    results = search_logs("test", top_k=1)
                    st.success("ChromaDB connection working!")
                    st.info(f"Found {len(results)} existing logs")
                except Exception as e:
                    st.error(f"ChromaDB connection failed: {str(e)[:100]}...")
                    logger.exception("ChromaDB connection test failed")
        
        with col2:
            if st.button("Store Sample Security Logs"):
                try:
                    from chromadb_logs import ingest_logs
                    
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
                        st.success(f"Stored {len(stored_items)} sample logs in ChromaDB")
                        
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
                from chromadb_logs import search_logs
                
                with st.spinner("Searching logs with AI embeddings..."):
                    # Search ChromaDB for similar logs
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
    
    def _render_saved_analysis(self, analysis_id: int):
        """Render a saved analysis from the database."""
        try:
            from results_storage import get_results_storage
            storage = get_results_storage()
            
            analysis = storage.get_analysis_by_id(analysis_id)
            if not analysis:
                st.error(f"Analysis with ID {analysis_id} not found")
                return
            
            # Header with back button
            col1, col2 = st.columns([3, 1])
            with col1:
                st.header(f"Saved Analysis: {analysis['case_name']}")
            with col2:
                if st.button("← Back to Saved Results"):
                    st.session_state.pop("view_analysis_id", None)
                    st.rerun()
            
            st.markdown("---")
            
            # Analysis metadata
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("Case ID", analysis['case_id'])
            with col2:
                st.metric("Analysis Date", analysis['created_at'][:19].replace("T", " "))
            with col3:
                st.metric("Files Analyzed", analysis['file_count'])
            with col4:
                st.metric("Log Entries", f"{analysis['log_entries_count']:,}")
            
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                severity = analysis['severity'].upper() if analysis['severity'] else "UNKNOWN"
                st.metric("Severity", severity)
            with col2:
                confidence = f"{analysis['confidence']:.1%}" if analysis['confidence'] else "N/A"
                st.metric("Confidence", confidence)
            with col3:
                st.metric("IOCs Found", analysis['iocs_count'])
            with col4:
                st.metric("MITRE Mappings", analysis['mitre_mappings_count'])
            
            # Executive Summary
            st.subheader("📋 Executive Summary")
            st.info(analysis['executive_summary'])
            
            # Detailed Results
            detailed_results = analysis.get('detailed_results', {})
            
            # IOCs
            if detailed_results.get('iocs'):
                st.subheader("Indicators of Compromise")
                ioc_data = []
                for ioc in detailed_results['iocs']:
                    ioc_data.append({
                        "Type": str(ioc.get('type', '')).upper(),
                        "Value": str(ioc.get('value', '')),
                        "Confidence": f"{ioc.get('confidence', 0):.1%}" if ioc.get('confidence') else "N/A",
                        "Context": str(ioc.get('context', '')) or "N/A"
                    })
                
                if ioc_data:
                    df_iocs = pd.DataFrame(ioc_data)
                    st.dataframe(df_iocs, width='stretch')
                else:
                    st.info("No IOCs identified")
            
            # MITRE ATT&CK
            if detailed_results.get('mitre'):
                st.subheader("MITRE ATT&CK Mapping")
                mitre_data = []
                for mapping in detailed_results['mitre']:
                    mitre_data.append({
                        "Tactic ID": mapping.get('tactic_id', ''),
                        "Tactic": mapping.get('tactic_name', ''),
                        "Technique ID": mapping.get('technique_id', 'N/A'),
                        "Technique": mapping.get('technique_name', 'N/A'),
                        "Confidence": f"{mapping.get('confidence', 0):.1%}" if mapping.get('confidence') else "N/A"
                    })
                
                if mitre_data:
                    df_mitre = pd.DataFrame(mitre_data)
                    st.dataframe(df_mitre, width='stretch')
                else:
                    st.info("No MITRE ATT&CK mappings identified")
            
            # Recommendations
            if detailed_results.get('recommendations'):
                st.subheader("💡 Recommendations")
                for i, rec in enumerate(detailed_results['recommendations'], 1):
                    st.write(f"{i}. {rec}")
            else:
                st.subheader("💡 Recommendations")
                st.info("No specific recommendations generated")
            
            # Timeline
            if detailed_results.get('timeline'):
                st.subheader("⏰ Event Timeline")
                timeline_data = []
                for event in detailed_results['timeline'][:100]:  # Show first 100 events
                    timeline_data.append({
                        "Timestamp": event.get('timestamp', ''),
                        "Source": event.get('source', ''),
                        "Severity": event.get('severity', ''),
                        "Event Type": event.get('event_type', ''),
                        "Message": event.get('message', '')[:100] + "..." if len(str(event.get('message', ''))) > 100 else event.get('message', '')
                    })
                
                if timeline_data:
                    df_timeline = pd.DataFrame(timeline_data)
                    st.dataframe(df_timeline, width='stretch')
                    
                    if len(detailed_results['timeline']) > 100:
                        st.info(f"Showing first 100 of {len(detailed_results['timeline'])} timeline events")
                else:
                    st.info("No timeline data available")
            
            # File Information
            if analysis.get('files'):
                st.subheader("Analyzed Files")
                file_data = []
                for file_info in analysis['files']:
                    file_data.append({
                        "Name": file_info['original_name'],
                        "Type": file_info['file_type'],
                        "Category": file_info['file_category'],
                        "Size": f"{file_info['file_size'] / (1024*1024):.2f} MB"
                    })
                
                df_files = pd.DataFrame(file_data)
                st.dataframe(df_files, width='stretch')
            
            # Analysis Configuration
            if analysis.get('analysis_config'):
                st.subheader("Analysis Configuration")
                config = analysis['analysis_config']
                col1, col2 = st.columns(2)
                with col1:
                    st.write(f"**Processing Mode:** {config.get('processing_mode', 'N/A')}")
                    st.write(f"**Skip ChromaDB:** {config.get('skip_chromadb', 'N/A')}")
                with col2:
                    st.write(f"**Max Entries:** {config.get('max_entries', 'N/A')}")
                    st.write(f"**Analysis Depth:** {config.get('analysis_depth', 'N/A')}")
            
            # Action buttons
            st.markdown("---")
            col1, col2, col3 = st.columns(3)
            
            with col1:
                if st.button("📥 Download Report", key=f"download_saved_{analysis_id}"):
                    st.info("Download functionality coming soon!")
            
            with col2:
                if st.button("🔄 Re-analyze", key=f"reanalyze_saved_{analysis_id}"):
                    st.info("Re-analysis functionality coming soon!")
            
            with col3:
                if st.button("Delete Analysis", key=f"delete_saved_{analysis_id}"):
                    if storage.delete_analysis(analysis_id):
                        st.success("Analysis deleted successfully!")
                        st.session_state.pop("view_analysis_id", None)
                        st.rerun()
                    else:
                        st.error("Failed to delete analysis")
                        
        except Exception as e:
            st.error(f"Error loading saved analysis: {e}")
            logger.exception("Error in saved analysis view")

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

    def _render_saved_results_tab(self):
        """Render the saved results tab."""
        st.header("Saved Analysis Results")
        st.markdown("---")
        
        try:
            from results_storage import get_results_storage
            storage = get_results_storage()
            
            # Get statistics
            stats = storage.get_statistics()
            
            # Display statistics
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("Total Analyses", stats.get('total_analyses', 0))
            with col2:
                st.metric("Recent (30 days)", stats.get('recent_analyses', 0))
            with col3:
                st.metric("Total Files", stats.get('total_files', 0))
            with col4:
                st.metric("Total IOCs", stats.get('total_iocs', 0))
            
            # Search and filter controls
            st.markdown("---")
            col1, col2, col3 = st.columns([2, 1, 1])
            
            with col1:
                search_query = st.text_input(
                    "Search analyses",
                    placeholder="Search by case ID, case name, or content...",
                    help="Search through saved analysis results"
                )
            
            with col2:
                if st.button("Search"):
                    st.session_state["search_results"] = storage.search_analyses(search_query) if search_query else []
                    st.session_state["show_search_results"] = True
            
            with col3:
                if st.button("🔄 Refresh"):
                    st.rerun()
            
            # Display results
            if st.session_state.get("show_search_results") and st.session_state.get("search_results"):
                st.subheader(f"Search Results ({len(st.session_state['search_results'])} found)")
                analyses = st.session_state["search_results"]
            else:
                st.subheader("📋 Recent Analyses")
                analyses = storage.get_all_analyses(limit=20)
            
            if analyses:
                # Create DataFrame for display
                display_data = []
                for analysis in analyses:
                    display_data.append({
                        "ID": analysis['id'],
                        "Case ID": analysis['case_id'],
                        "Case Name": analysis['case_name'],
                        "Date": analysis['created_at'][:19].replace("T", " "),
                        "Files": analysis['file_count'],
                        "Log Entries": f"{analysis['log_entries_count']:,}",
                        "Severity": analysis['severity'].upper() if analysis['severity'] else "UNKNOWN",
                        "Confidence": f"{analysis['confidence']:.1%}" if analysis['confidence'] else "N/A",
                        "IOCs": analysis['iocs_count'],
                        "MITRE": analysis['mitre_mappings_count']
                    })
                
                df_analyses = pd.DataFrame(display_data)
                st.dataframe(df_analyses, width='stretch', hide_index=True)
                
                # Analysis details
                st.subheader("📄 Analysis Details")
                
                for analysis in analyses:
                    with st.expander(f"{analysis['case_name']} (ID: {analysis['id']}) - {analysis['created_at'][:19].replace('T', ' ')}"):
                        col1, col2 = st.columns(2)
                        
                        with col1:
                            st.write(f"**Case ID:** {analysis['case_id']}")
                            st.write(f"**Analysis Date:** {analysis['created_at'][:19].replace('T', ' ')}")
                            st.write(f"**Files Analyzed:** {analysis['file_count']}")
                            st.write(f"**Log Entries:** {analysis['log_entries_count']:,}")
                            st.write(f"**Severity:** {analysis['severity'].upper() if analysis['severity'] else 'UNKNOWN'}")
                            st.write(f"**Confidence:** {analysis['confidence']:.1%}" if analysis['confidence'] else "**Confidence:** N/A")
                        
                        with col2:
                            st.write(f"**IOCs Found:** {analysis['iocs_count']}")
                            st.write(f"**MITRE Mappings:** {analysis['mitre_mappings_count']}")
                            st.write(f"**Recommendations:** {analysis['recommendations_count']}")
                            if analysis.get('zip_file_path'):
                                st.write(f"**ZIP File:** {analysis['zip_file_path']}")
                            st.write(f"**Status:** {analysis['status']}")
                        
                        # Executive summary
                        st.markdown("---")
                        st.write("**Executive Summary:**")
                        st.info(analysis['executive_summary'])
                        
                        # Action buttons
                        col1, col2, col3 = st.columns(3)
                        
                        with col1:
                            if st.button(f"View Full Report", key=f"view_{analysis['id']}"):
                                st.session_state["view_analysis_id"] = analysis['id']
                                st.rerun()
                        
                        with col2:
                            if st.button(f"📥 Download Report", key=f"download_{analysis['id']}"):
                                # TODO: Implement download functionality
                                st.info("Download functionality coming soon!")
                        
                        with col3:
                            if st.button(f"Delete", key=f"delete_{analysis['id']}"):
                                if storage.delete_analysis(analysis['id']):
                                    st.success(f"Analysis {analysis['id']} deleted successfully!")
                                    st.rerun()
                                else:
                                    st.error("Failed to delete analysis")
            
            else:
                st.info("📭 No saved analyses found. Run an analysis first to see results here.")
                
                # Show example of what will be saved
                st.markdown("---")
                st.subheader("💡 What gets saved?")
                st.markdown("""
                When you run an analysis, the following information is automatically saved:
                - **Case details** (ID, name, date)
                - **Analysis results** (IOCs, MITRE mappings, recommendations)
                - **File information** (names, types, categories)
                - **Timeline data** (event sequences)
                - **Configuration** (analysis settings used)
                """)
                
        except Exception as e:
            st.error(f"Error loading saved results: {e}")
            logger.exception("Error in saved results tab")
    
    def _render_file_history_tab(self):
        """Render the file history tab."""
        st.header("File History")
        st.markdown("---")
        
        # File history controls
        col1, col2, col3 = st.columns([2, 1, 1])
        
        with col1:
            st.subheader("Previously Uploaded Files")
        
        with col2:
            if st.button("Refresh History"):
                st.rerun()
        
        with col3:
            if st.button("Clear History"):
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
            st.dataframe(df_files, width='stretch', hide_index=True)
            
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
                        st.write(f"**Analysis Completed:** {'Yes' if file_info['analysis_completed'] else 'No'}")
                    
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
                    width='stretch'
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
                    width='stretch'
                )


# -----------------------------------------------------------------------------
# Entrypoint
# -----------------------------------------------------------------------------
def main() -> None:
    """Run the Streamlit dashboard app."""
    ForensicDashboard().run()


if __name__ == "__main__":
    main()
