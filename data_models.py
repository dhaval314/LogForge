"""
Pydantic data models for the Forensic AI Log Analyzer.
"""
from datetime import datetime
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from enum import Enum

class LogEntryType(str, Enum):
    """Enumeration of supported log entry types."""
    WINDOWS_EVENT = "windows_event"
    SYSLOG = "syslog"
    ACCESS_LOG = "access_log"
    FIREWALL = "firewall"
    DNS = "dns"
    GENERIC = "generic"

class SeverityLevel(str, Enum):
    """Severity levels for security events."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class LogEntry(BaseModel):
    """Standardized log entry model."""
    timestamp: datetime = Field(description="Normalized timestamp")
    source: str = Field(description="Log source identifier")
    event_type: LogEntryType = Field(description="Type of log entry")
    event_id: Optional[str] = Field(None, description="Event ID if applicable")
    message: str = Field(description="Log message content")
    raw_data: Optional[Dict[str, Any]] = Field(None, description="Original log data")
    severity: Optional[SeverityLevel] = Field(None, description="Event severity")

class IOC(BaseModel):
    """Indicator of Compromise model."""
    type: str = Field(description="IOC type (ip, domain, hash, etc.)")
    value: str = Field(description="IOC value")
    confidence: float = Field(ge=0.0, le=1.0, description="Confidence score")
    context: Optional[str] = Field(None, description="Context where IOC was found")

class MitreMapping(BaseModel):
    """MITRE ATT&CK framework mapping."""
    tactic_id: str = Field(description="MITRE tactic ID (e.g., TA0001)")
    tactic_name: str = Field(description="MITRE tactic name")
    technique_id: Optional[str] = Field(None, description="MITRE technique ID (e.g., T1078)")
    technique_name: Optional[str] = Field(None, description="MITRE technique name")
    confidence: float = Field(ge=0.0, le=1.0, description="Confidence in mapping")

class InitialAnalysis(BaseModel):
    """Initial LLM analysis results."""
    summary: str = Field(description="Summary of findings")
    iocs: List[IOC] = Field(description="Identified IOCs")
    mitre_mappings: List[MitreMapping] = Field(description="MITRE ATT&CK mappings")
    severity: SeverityLevel = Field(description="Overall incident severity")
    confidence: float = Field(ge=0.0, le=1.0, description="Analysis confidence")
    suspicious_patterns: List[str] = Field(description="Identified suspicious patterns")

class EnrichmentData(BaseModel):
    """Data from enrichment sources."""
    source: str = Field(description="Enrichment source (VirusTotal, DynamoDB+Bedrock, etc.)")
    ioc_value: str = Field(description="IOC that was enriched")
    reputation_score: Optional[float] = Field(None, description="Reputation score if available")
    additional_context: Dict[str, Any] = Field(description="Additional context data")
    last_updated: datetime = Field(description="When enrichment data was retrieved")

class EnrichedAnalysis(BaseModel):
    """Enriched analysis results."""
    initial_analysis: InitialAnalysis = Field(description="Initial analysis")
    enrichments: List[EnrichmentData] = Field(description="Enrichment data")
    enhanced_summary: str = Field(description="Enhanced summary with enrichment")
    attack_chain: List[str] = Field(description="Reconstructed attack chain")
    recommendations: List[str] = Field(description="Security recommendations")

class ForensicReport(BaseModel):
    """Complete forensic investigation report."""
    case_id: str = Field(description="Unique case identifier")
    analyst: str = Field(description="Analyst name")
    investigation_date: datetime = Field(description="Investigation date")
    log_sources: List[str] = Field(description="Sources of analyzed logs")
    total_events: int = Field(description="Total number of events analyzed")
    analysis: EnrichedAnalysis = Field(description="Complete analysis results")
    timeline: List[Dict[str, Any]] = Field(description="Event timeline")
    executive_summary: str = Field(description="Executive summary for management")

class AgentMessage(BaseModel):
    """Message format for agent communication."""
    agent_name: str = Field(description="Name of sending agent")
    message_type: str = Field(description="Type of message")
    data: Dict[str, Any] = Field(description="Message payload")
    timestamp: datetime = Field(description="Message timestamp")
    correlation_id: str = Field(description="Correlation ID for tracking")