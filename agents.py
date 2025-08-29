"""
Agentic Workflow Module using LangGraph for AI orchestration.
"""
import uuid
from datetime import datetime
from typing import Dict, Any, List, Optional, TypedDict
from pathlib import Path
from loguru import logger

try:
    from langgraph.graph import StateGraph, END
    from langgraph.checkpoint.memory import MemorySaver
except ImportError:
    logger.warning("LangGraph not available, using simplified orchestration")
    StateGraph = None
    END = None
    MemorySaver = None

from data_models import LogEntry, InitialAnalysis, EnrichedAnalysis, AgentMessage, ForensicReport, SeverityLevel
from data_prep import LogParser, TimelineCreator
from llm_analysis import GraniteAnalyzer
from rag_enrichment import RAGPipeline
from utilities import VirusTotalEnricher, YaraScanner

class InvestigationState(TypedDict):
    """State object for the investigation workflow."""
    case_id: str
    log_files: List[str]
    parsed_logs: List[LogEntry]
    initial_analysis: Optional[InitialAnalysis]
    enriched_analysis: Optional[EnrichedAnalysis]
    final_report: Optional[ForensicReport]
    timeline: List[Dict[str, Any]]
    messages: List[AgentMessage]
    errors: List[str]

class BaseAgent:
    """Base class for all forensic analysis agents."""
    
    def __init__(self, name: str):
        self.name = name
        self.logger = logger.bind(agent=name)
    
    def create_message(self, message_type: str, data: Dict[str, Any], correlation_id: str) -> AgentMessage:
        """Create a standardized agent message."""
        return AgentMessage(
            agent_name=self.name,
            message_type=message_type,
            data=data,
            timestamp=datetime.now(),
            correlation_id=correlation_id
        )
    
    def log_error(self, error: str, state: InvestigationState):
        """Log an error to the investigation state."""
        self.logger.error(error)
        if "errors" not in state:
            state["errors"] = []
        state["errors"].append(f"{self.name}: {error}")

class LogParserAgent(BaseAgent):
    """Agent responsible for parsing and normalizing log files."""
    
    def __init__(self, skip_evtx_files=False):
        super().__init__("Log_Parser_Agent")
        self.parser = LogParser(skip_evtx_files=skip_evtx_files)
    
    def execute(self, state: InvestigationState) -> InvestigationState:
        """Parse log files and normalize them."""
        self.logger.info("Starting log parsing process")
        
        try:
            parsed_logs = []
            log_files = state.get("log_files", [])
            
            if not log_files:
                self.log_error("No log files provided for parsing", state)
                return state
            
            for log_file in log_files:
                try:
                    file_path = Path(log_file)
                    if file_path.exists():
                        entries = self.parser.parse_logs(file_path)
                        parsed_logs.extend(entries)
                        self.logger.info(f"Parsed {len(entries)} entries from {file_path}")
                    else:
                        self.log_error(f"Log file not found: {log_file}", state)
                        
                except Exception as e:
                    self.log_error(f"Error parsing {log_file}: {e}", state)
            
            state["parsed_logs"] = parsed_logs
            
            # Add message to workflow
            message = self.create_message(
                message_type="parsing_complete",
                data={"total_entries": len(parsed_logs), "files_processed": len(log_files)},
                correlation_id=state["case_id"]
            )
            
            if "messages" not in state:
                state["messages"] = []
            state["messages"].append(message)
            
            self.logger.info(f"Log parsing completed: {len(parsed_logs)} total entries")
            
        except Exception as e:
            self.log_error(f"Critical error in log parsing: {e}", state)
        
        return state

class InitialAnalysisAgent(BaseAgent):
    """Agent responsible for initial LLM-based analysis."""
    
    def __init__(self):
        super().__init__("Initial_Analysis_Agent")
        self.analyzer = GraniteAnalyzer()
    
    def execute(self, state: InvestigationState) -> InvestigationState:
        """Perform initial analysis using Granite LLM."""
        self.logger.info("Starting initial analysis")
        
        try:
            parsed_logs = state.get("parsed_logs", [])
            
            if not parsed_logs:
                self.log_error("No parsed logs available for analysis", state)
                return state
            
            # Perform initial analysis
            analysis = self.analyzer.analyze_logs(parsed_logs)
            state["initial_analysis"] = analysis
            
            # Add message to workflow
            message = self.create_message(
                message_type="initial_analysis_complete",
                data={
                    "iocs_found": len(analysis.iocs),
                    "mitre_mappings": len(analysis.mitre_mappings),
                    "severity": analysis.severity.value,
                    "confidence": analysis.confidence
                },
                correlation_id=state["case_id"]
            )
            state["messages"].append(message)
            
            self.logger.info(f"Initial analysis completed: {len(analysis.iocs)} IOCs, severity: {analysis.severity}")
            
        except Exception as e:
            self.log_error(f"Error in initial analysis: {e}", state)
        
        return state

class EnrichmentAgent(BaseAgent):
    """Agent responsible for enriching analysis with external context."""
    
    def __init__(self):
        super().__init__("Enrichment_Agent")
        self.rag_pipeline = RAGPipeline()
        self.vt_enricher = VirusTotalEnricher()
        self.yara_scanner = YaraScanner()
    
    def execute(self, state: InvestigationState) -> InvestigationState:
        """Enrich initial analysis with additional context."""
        self.logger.info("Starting enrichment process")
        
        try:
            initial_analysis = state.get("initial_analysis")
            
            if not initial_analysis:
                self.log_error("No initial analysis available for enrichment", state)
                return state
            
            # Check if RAG enrichment should be skipped
            skip_rag = state.get("skip_rag", False)
            
            if skip_rag:
                self.logger.info("Skipping RAG enrichment as requested")
                # Create minimal enriched analysis without RAG
                from data_models import EnrichedAnalysis
                enriched_analysis = EnrichedAnalysis(
                    initial_analysis=initial_analysis,
                    enrichments=[],
                    enhanced_summary=initial_analysis.summary,
                    attack_chain=["Attack chain analysis skipped"],
                    recommendations=["Manual review recommended due to RAG enrichment being disabled"]
                )
            else:
                # RAG enrichment
                enriched_analysis = self.rag_pipeline.enrich_analysis(initial_analysis)
            
            # VirusTotal enrichment for IOCs
            for ioc in initial_analysis.iocs:
                if ioc.type in ["ip", "domain", "hash"]:
                    try:
                        vt_data = self.vt_enricher.check_ioc(ioc.value, ioc.type)
                        if vt_data:
                            enriched_analysis.enrichments.append(vt_data)
                    except Exception as e:
                        self.logger.debug(f"VT enrichment failed for {ioc.value}: {e}")
            
            # YARA scanning if applicable
            try:
                yara_results = self.yara_scanner.scan_for_patterns(state.get("parsed_logs", []))
                if yara_results:
                    # Add YARA results to enrichments
                    for result in yara_results:
                        from data_models import EnrichmentData
                        yara_enrichment = EnrichmentData(
                            source="yara_scanner",
                            ioc_value=result.get("pattern", "unknown"),
                            additional_context=result,
                            last_updated=datetime.now()
                        )
                        enriched_analysis.enrichments.append(yara_enrichment)
            except Exception as e:
                self.logger.debug(f"YARA scanning failed: {e}")
            
            state["enriched_analysis"] = enriched_analysis
            
            # Add message to workflow
            message = self.create_message(
                message_type="enrichment_complete",
                data={
                    "enrichments_added": len(enriched_analysis.enrichments),
                    "recommendations": len(enriched_analysis.recommendations),
                    "attack_chain_steps": len(enriched_analysis.attack_chain)
                },
                correlation_id=state["case_id"]
            )
            state["messages"].append(message)
            
            self.logger.info(f"Enrichment completed: {len(enriched_analysis.enrichments)} enrichments added")
            
        except Exception as e:
            self.log_error(f"Error during enrichment: {e}", state)
        
        return state

class ReportingAgent(BaseAgent):
    """Agent responsible for generating final reports and timelines."""
    
    def __init__(self):
        super().__init__("Reporting_Agent")
        self.timeline_creator = TimelineCreator()
    
    def execute(self, state: InvestigationState) -> InvestigationState:
        """Generate final forensic report and timeline."""
        self.logger.info("Starting report generation")
        
        try:
            enriched_analysis = state.get("enriched_analysis")
            parsed_logs = state.get("parsed_logs", [])
            
            if not enriched_analysis:
                self.log_error("No enriched analysis available for reporting", state)
                return state
            
            # Create timeline
            timeline = self._create_event_timeline(parsed_logs)
            state["timeline"] = timeline
            
            # Generate executive summary
            executive_summary = self._generate_executive_summary(enriched_analysis)
            
            # Create final report
            final_report = ForensicReport(
                case_id=state["case_id"],
                analyst="Forensic AI Analyzer",
                investigation_date=datetime.now(),
                log_sources=state.get("log_files", []),
                total_events=len(parsed_logs),
                analysis=enriched_analysis,
                timeline=timeline,
                executive_summary=executive_summary
            )
            
            state["final_report"] = final_report
            
            # Add message to workflow
            message = self.create_message(
                message_type="reporting_complete",
                data={
                    "timeline_events": len(timeline),
                    "report_generated": True,
                    "case_id": state["case_id"]
                },
                correlation_id=state["case_id"]
            )
            state["messages"].append(message)
            
            self.logger.info("Report generation completed successfully")
            
        except Exception as e:
            self.log_error(f"Error during report generation: {e}", state)
        
        return state
    
    def _create_event_timeline(self, parsed_logs: List[LogEntry]) -> List[Dict[str, Any]]:
        """Create a chronological timeline of events."""
        try:
            # Sort logs by timestamp, ensuring all timestamps are timezone-naive for comparison
            def get_sortable_timestamp(log_entry):
                timestamp = log_entry.timestamp
                # If timestamp is timezone-aware, convert to naive
                if timestamp.tzinfo is not None:
                    return timestamp.replace(tzinfo=None)
                return timestamp
            
            sorted_logs = sorted(parsed_logs, key=get_sortable_timestamp)
            
            timeline = []
            for i, log_entry in enumerate(sorted_logs):
                timeline_event = {
                    "sequence": i + 1,
                    "timestamp": log_entry.timestamp.isoformat(),
                    "source": log_entry.source,
                    "event_type": log_entry.event_type.value,
                    "severity": log_entry.severity.value if log_entry.severity else "info",
                    "message": log_entry.message[:200] + "..." if len(log_entry.message) > 200 else log_entry.message,
                    "event_id": log_entry.event_id
                }
                timeline.append(timeline_event)
            
            return timeline
            
        except Exception as e:
            self.logger.error(f"Error creating timeline: {e}")
            return []
    
    def _generate_executive_summary(self, enriched_analysis: EnrichedAnalysis) -> str:
        """Generate executive summary for management."""
        try:
            summary_parts = []
            
            # Overall assessment
            severity = enriched_analysis.initial_analysis.severity.value.upper()
            summary_parts.append(f"SECURITY INCIDENT ASSESSMENT: {severity} PRIORITY")
            summary_parts.append("")
            
            # Key findings
            ioc_count = len(enriched_analysis.initial_analysis.iocs)
            mitre_count = len(enriched_analysis.initial_analysis.mitre_mappings)
            
            summary_parts.append("KEY FINDINGS:")
            summary_parts.append(f"• {ioc_count} indicators of compromise identified")
            summary_parts.append(f"• {mitre_count} MITRE ATT&CK techniques detected")
            summary_parts.append(f"• Analysis confidence: {enriched_analysis.initial_analysis.confidence:.1%}")
            summary_parts.append("")
            
            # Attack overview
            if enriched_analysis.attack_chain:
                summary_parts.append("ATTACK PROGRESSION:")
                for i, step in enumerate(enriched_analysis.attack_chain[:5], 1):
                    summary_parts.append(f"{i}. {step}")
                summary_parts.append("")
            
            # Immediate actions
            if enriched_analysis.recommendations:
                summary_parts.append("IMMEDIATE ACTIONS REQUIRED:")
                for rec in enriched_analysis.recommendations[:5]:
                    summary_parts.append(f"• {rec}")
                summary_parts.append("")
            
            # Risk assessment
            risk_level = "HIGH" if severity in ["CRITICAL", "HIGH"] else "MODERATE"
            summary_parts.append(f"BUSINESS RISK: {risk_level}")
            summary_parts.append("Detailed technical analysis and remediation steps are available in the full report.")
            
            return "\n".join(summary_parts)
            
        except Exception as e:
            self.logger.error(f"Error generating executive summary: {e}")
            return "Executive summary generation failed. Please review detailed technical analysis."

class ForensicOrchestrator:
    """Main orchestrator for the forensic investigation workflow."""
    
    def __init__(self, skip_evtx_files=False):
        self.logger = logger.bind(component="orchestrator")
        self.agents = {
            "parser": LogParserAgent(skip_evtx_files=skip_evtx_files),
            "analyzer": InitialAnalysisAgent(),
            "enricher": EnrichmentAgent(),
            "reporter": ReportingAgent()
        }
        self.workflow = None
        self._initialize_workflow()
    
    def _initialize_workflow(self):
        """Initialize the LangGraph workflow."""
        if not StateGraph:
            self.logger.warning("LangGraph not available, using simple sequential execution")
            return
        
        try:
            # Create workflow graph
            workflow = StateGraph(InvestigationState)
            
            # Add agent nodes
            workflow.add_node("parse_logs", self.agents["parser"].execute)
            workflow.add_node("analyze", self.agents["analyzer"].execute)
            workflow.add_node("enrich", self.agents["enricher"].execute)
            workflow.add_node("report", self.agents["reporter"].execute)
            
            # Define workflow edges
            workflow.set_entry_point("parse_logs")
            workflow.add_edge("parse_logs", "analyze")
            workflow.add_edge("analyze", "enrich")
            workflow.add_edge("enrich", "report")
            workflow.add_edge("report", END)
            
            # Compile workflow with memory
            memory = MemorySaver()
            self.workflow = workflow.compile(checkpointer=memory)
            
            self.logger.info("LangGraph workflow initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize LangGraph workflow: {e}")
            self.workflow = None
    
    def investigate(self, log_files: List[str], case_id: str = None, skip_rag: bool = False) -> ForensicReport:
        """
        Run complete forensic investigation.
        
        Args:
            log_files: List of log file paths to analyze
            case_id: Optional case ID for tracking
            skip_rag: Whether to skip RAG enrichment
            
        Returns:
            Complete forensic report
        """
        case_id = case_id or f"CASE_{uuid.uuid4().hex[:8].upper()}"
        
        self.logger.info(f"Starting forensic investigation: {case_id}")
        
        # Initialize investigation state
        initial_state: InvestigationState = {
            "case_id": case_id,
            "log_files": log_files,
            "parsed_logs": [],
            "initial_analysis": None,
            "enriched_analysis": None,
            "final_report": None,
            "timeline": [],
            "messages": [],
            "errors": [],
            "skip_rag": skip_rag
        }
        
        try:
            if self.workflow:
                # Use LangGraph workflow
                final_state = self._run_langgraph_workflow(initial_state)
                # Fallback to sequential if workflow did not produce a final report
                if not final_state.get("final_report"):
                    self.logger.warning("Workflow produced no final report; falling back to sequential execution")
                    final_state = self._run_sequential_workflow(initial_state)
            else:
                # Use simple sequential execution
                final_state = self._run_sequential_workflow(initial_state)
            
            # Extract final report
            final_report = final_state.get("final_report")
            
            if final_report:
                self.logger.info(f"Investigation completed successfully: {case_id}")
                return final_report
            else:
                raise Exception("Investigation failed to generate final report")
                
        except Exception as e:
            self.logger.error(f"Investigation failed: {e}")
            # Return minimal report on failure
            from data_models import EnrichedAnalysis, InitialAnalysis
            
            minimal_analysis = InitialAnalysis(
                summary=f"Investigation failed: {e}",
                iocs=[],
                mitre_mappings=[],
                severity=SeverityLevel.INFO,
                confidence=0.0,
                suspicious_patterns=[]
            )
            
            minimal_enriched = EnrichedAnalysis(
                initial_analysis=minimal_analysis,
                enrichments=[],
                enhanced_summary=f"Investigation failed due to error: {e}",
                attack_chain=["Investigation incomplete"],
                recommendations=["Manual analysis recommended"]
            )
            
            return ForensicReport(
                case_id=case_id,
                analyst="Forensic AI Analyzer",
                investigation_date=datetime.now(),
                log_sources=log_files,
                total_events=0,
                analysis=minimal_enriched,
                timeline=[],
                executive_summary="Investigation failed to complete successfully."
            )
    
    def _run_langgraph_workflow(self, initial_state: InvestigationState) -> InvestigationState:
        """Run investigation using LangGraph workflow."""
        try:
            config = {"configurable": {"thread_id": initial_state["case_id"]}}
            
            # Execute workflow
            final_state = None
            for state in self.workflow.stream(initial_state, config):
                final_state = state
            
            return final_state
            
        except Exception as e:
            self.logger.error(f"LangGraph workflow execution failed: {e}")
            raise
    
    def _run_sequential_workflow(self, initial_state: InvestigationState) -> InvestigationState:
        """Run investigation using simple sequential execution."""
        try:
            # Execute agents in sequence
            state = initial_state
            
            state = self.agents["parser"].execute(state)
            state = self.agents["analyzer"].execute(state)
            state = self.agents["enricher"].execute(state)
            state = self.agents["reporter"].execute(state)
            
            return state
            
        except Exception as e:
            self.logger.error(f"Sequential workflow execution failed: {e}")
            raise
    
    def get_workflow_status(self, case_id: str) -> Dict[str, Any]:
        """Get current status of a workflow."""
        try:
            if not self.workflow:
                return {"status": "workflow_not_available"}
            
            # This would retrieve state from memory in a real implementation
            return {
                "case_id": case_id,
                "status": "completed",  # Placeholder
                "message": "Workflow status tracking not fully implemented"
            }
            
        except Exception as e:
            self.logger.error(f"Error getting workflow status: {e}")
            return {"status": "error", "message": str(e)}