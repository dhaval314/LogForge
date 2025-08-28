"""
Granite LLM Analysis Module - Forensic Reasoning with IBM Watsonx.ai
"""
import json
from typing import List, Dict, Any
from datetime import datetime
from loguru import logger
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout

try:
    from ibm_watson_machine_learning import APIClient
    from ibm_watson_machine_learning.foundation_models import Model
except ImportError:
    logger.warning("IBM Watson ML not available, using mock implementation")
    APIClient = None
    Model = None

# Optional Groq SDK
try:
    from groq import Groq
except ImportError:
    Groq = None

from data_models import LogEntry, InitialAnalysis, IOC, MitreMapping, SeverityLevel
from config import Config

class GraniteAnalyzer:
    """
    Forensic analysis using IBM's Granite LLM via Watsonx.ai API.
    """
    
    def __init__(self):
        self.client = None  # IBM WML client
        self.model = None   # IBM Granite model
        self.groq_client = None  # Groq client
        self._initialize_client()
    
    def _initialize_client(self):
        """Initialize LLM client based on configured provider."""
        # Prefer explicit provider, else auto-select Groq if IBM creds missing
        provider = getattr(Config, "LLM_PROVIDER", "ibm")
        if provider not in ("ibm", "groq"):
            provider = "ibm"
        if provider == "ibm" and not getattr(Config, "IBM_API_KEY", None) and getattr(Config, "GROQ_API_KEY", None):
            provider = "groq"
        logger.info(f"LLM provider selected: {provider}")

        if provider == "groq":
            if Groq is None:
                logger.warning("Groq SDK not available; falling back to mock analysis")
                return
            try:
                if not Config.GROQ_API_KEY:
                    raise ValueError("GROQ_API_KEY is not set")
                self.groq_client = Groq(api_key=Config.GROQ_API_KEY)
                logger.info("Groq client initialized successfully")
            except Exception as e:
                logger.error(f"Failed to initialize Groq client: {e}")
                self.groq_client = None
            return

        # Default to IBM provider
        if not APIClient or not Model:
            logger.warning("IBM Watson ML SDK not available")
            return
        try:
            wml_credentials = {
                "url": Config.IBM_URL,
                "apikey": Config.IBM_API_KEY
            }
            self.client = APIClient(wml_credentials)
            model_params = {
                "model_id": Config.GRANITE_MODEL_ID,
                "params": Config.GRANITE_PARAMETERS,
                "project_id": Config.IBM_PROJECT_ID
            }
            self.model = Model(
                model_id=model_params["model_id"],
                params=model_params["params"],
                credentials=wml_credentials,
                project_id=model_params["project_id"]
            )
            logger.info("IBM Granite LLM initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize IBM Granite LLM: {e}")
            self.client = None
            self.model = None
    
    def analyze_logs(self, log_entries: List[LogEntry]) -> InitialAnalysis:
        """
        Analyze normalized log entries for security threats.
        
        Args:
            log_entries: List of normalized log entries
            
        Returns:
            InitialAnalysis containing findings and IOCs
        """
        # Re-evaluate provider in case environment changed between init and call
        provider = getattr(Config, "LLM_PROVIDER", "ibm")
        if provider not in ("ibm", "groq"):
            provider = "ibm"
        if provider == "ibm" and not getattr(Config, "IBM_API_KEY", None) and getattr(Config, "GROQ_API_KEY", None):
            provider = "groq"
        logger.info(f"Analyzing {len(log_entries)} log entries with provider: {provider}")
        
        if provider == "groq":
            if not self.groq_client:
                logger.warning("Groq client not available, using mock analysis")
                return self._mock_analysis(log_entries)
            return self._analyze_with_groq(log_entries)

        if not self.model:
            logger.warning("IBM Granite LLM not available, using mock analysis")
            return self._mock_analysis(log_entries)
        
        try:
            # Prepare log data for analysis
            log_summary = self._prepare_log_summary(log_entries)
            
            # Create forensic analysis prompt
            prompt = self._create_forensic_prompt(log_summary)

            def _ibm_call() -> str:
                return self.model.generate_text(prompt)

            # Timebox the IBM call to prevent UI hangs
            with ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(_ibm_call)
                try:
                    response = future.result(timeout=30)
                except FuturesTimeout:
                    logger.error("IBM LLM call timed out; falling back to mock analysis")
                    return self._mock_analysis(log_entries)
            
            # Parse LLM response into structured format
            analysis = self._parse_llm_response(response, log_entries)
            
            logger.info("Granite LLM analysis completed")
            return analysis
            
        except Exception as e:
            logger.error(f"Error during Granite LLM analysis: {e}")
            return self._mock_analysis(log_entries)

    def _analyze_with_groq(self, log_entries: List[LogEntry]) -> InitialAnalysis:
        """Run analysis using Groq Chat Completions API."""
        try:
            log_summary = self._prepare_log_summary(log_entries)
            prompt = self._create_forensic_prompt(log_summary)

            # Use a system+user prompt with chat.completions
            messages = [
                {"role": "system", "content": "You are an expert cybersecurity forensic analyst."},
                {"role": "user", "content": prompt}
            ]

            def _groq_call():
                return self.groq_client.chat.completions.create(
                    model=Config.GROQ_MODEL_ID,
                    messages=messages,
                    temperature=Config.GROQ_TEMPERATURE,
                    max_tokens=Config.GROQ_MAX_TOKENS,
                    top_p=1.0
                )

            # Timebox the Groq call to prevent UI hangs
            with ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(_groq_call)
                try:
                    completion = future.result(timeout=30)
                except FuturesTimeout:
                    logger.error("Groq LLM call timed out; falling back to mock analysis")
                    return self._mock_analysis(log_entries)

            text = completion.choices[0].message.content if completion.choices else "{}"
            analysis = self._parse_llm_response(text, log_entries)
            logger.info("Groq analysis completed")
            return analysis
        except Exception as e:
            logger.error(f"Error during Groq analysis: {e}")
            return self._mock_analysis(log_entries)
    
    def _prepare_log_summary(self, log_entries: List[LogEntry]) -> str:
        """Prepare a concise summary of log entries for LLM analysis."""
        # Limit entries to avoid token limits
        max_entries = min(len(log_entries), 100)
        selected_entries = log_entries[:max_entries]
        
        summary_lines = []
        for entry in selected_entries:
            timestamp_str = entry.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            summary_lines.append(
                f"[{timestamp_str}] {entry.source}: {entry.message[:200]}..."
            )
        
        return "\n".join(summary_lines)
    
    def _create_forensic_prompt(self, log_summary: str) -> str:
        """Create a detailed forensic analysis prompt for Granite LLM."""
        prompt = f"""You are an expert cybersecurity forensic analyst. Analyze the following security logs and provide a structured assessment of potential threats and incidents.

LOG DATA:
{log_summary}

ANALYSIS REQUIREMENTS:
1. Identify potential Indicators of Compromise (IOCs) including:
   - Suspicious IP addresses
   - Malicious file hashes
   - Suspicious domains
   - Unusual user accounts or behaviors
   - Anomalous network traffic patterns

2. Map findings to MITRE ATT&CK framework:
   - Identify relevant tactics and techniques
   - Provide tactic IDs (TA####) and technique IDs (T####) where applicable

3. Assess overall incident severity: CRITICAL, HIGH, MEDIUM, LOW, or INFO

4. Identify suspicious patterns or attack chains

5. Provide analysis confidence score (0.0 to 1.0)

RESPONSE FORMAT (JSON):
{{
    "summary": "Brief summary of findings",
    "iocs": [
        {{
            "type": "ip|domain|hash|username|process",
            "value": "IOC value",
            "confidence": 0.0-1.0,
            "context": "Where/how found"
        }}
    ],
    "mitre_mappings": [
        {{
            "tactic_id": "TA####",
            "tactic_name": "Tactic name",
            "technique_id": "T####",
            "technique_name": "Technique name",
            "confidence": 0.0-1.0
        }}
    ],
    "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
    "confidence": 0.0-1.0,
    "suspicious_patterns": ["List of identified patterns"]
}}

Analyze the logs and respond ONLY with the JSON structure above:"""
        
        return prompt
    
    def _parse_llm_response(self, response: str, log_entries: List[LogEntry]) -> InitialAnalysis:
        """Parse LLM response into structured InitialAnalysis object."""
        try:
            # Extract JSON from response
            response_text = response.strip()
            if response_text.startswith("```json"):
                response_text = response_text.split("```json")[1].split("```")[0]
            elif response_text.startswith("```"):
                response_text = response_text.split("```")[1].split("```")[0]
            
            analysis_data = json.loads(response_text)
            
            # Convert to Pydantic models
            iocs = [
                IOC(
                    type=ioc.get("type", "unknown"),
                    value=ioc.get("value", ""),
                    confidence=float(ioc.get("confidence", 0.5)),
                    context=ioc.get("context")
                )
                for ioc in analysis_data.get("iocs", [])
            ]
            
            mitre_mappings = [
                MitreMapping(
                    tactic_id=mapping.get("tactic_id", ""),
                    tactic_name=mapping.get("tactic_name", ""),
                    technique_id=mapping.get("technique_id"),
                    technique_name=mapping.get("technique_name"),
                    confidence=float(mapping.get("confidence", 0.5))
                )
                for mapping in analysis_data.get("mitre_mappings", [])
            ]
            
            return InitialAnalysis(
                summary=analysis_data.get("summary", "No analysis summary available"),
                iocs=iocs,
                mitre_mappings=mitre_mappings,
                severity=SeverityLevel(analysis_data.get("severity", "info").lower()),
                confidence=float(analysis_data.get("confidence", 0.5)),
                suspicious_patterns=analysis_data.get("suspicious_patterns", [])
            )
            
        except Exception as e:
            logger.error(f"Error parsing LLM response: {e}")
            return self._mock_analysis(log_entries)
    
    def _mock_analysis(self, log_entries: List[LogEntry]) -> InitialAnalysis:
        """Provide mock analysis when LLM is unavailable."""
        logger.info("Using mock analysis - Granite LLM not available")
        
        # Simple pattern-based analysis for demonstration
        suspicious_ips = set()
        suspicious_processes = set()
        error_patterns = []
        
        for entry in log_entries:
            message_lower = entry.message.lower()
            
            # Look for suspicious patterns
            if any(pattern in message_lower for pattern in ['failed', 'denied', 'unauthorized']):
                error_patterns.append(f"Suspicious activity: {entry.message[:100]}")
            
            # Extract potential IP addresses (simple regex)
            import re
            ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', entry.message)
            for ip in ips:
                if not ip.startswith(('192.168.', '10.', '172.')):  # Skip private IPs
                    suspicious_ips.add(ip)
            
            # Look for process names
            if 'process' in message_lower or 'exe' in message_lower:
                processes = re.findall(r'(\w+\.exe|\w+\.bat|\w+\.ps1)', entry.message, re.IGNORECASE)
                suspicious_processes.update(processes)
        
        # Create mock IOCs
        mock_iocs = []
        for ip in list(suspicious_ips)[:5]:  # Limit to 5
            mock_iocs.append(IOC(
                type="ip",
                value=ip,
                confidence=0.6,
                context="Found in log entries"
            ))
        
        for process in list(suspicious_processes)[:3]:  # Limit to 3
            mock_iocs.append(IOC(
                type="process",
                value=process,
                confidence=0.4,
                context="Suspicious process activity"
            ))
        
        # Mock MITRE mapping
        mock_mitre = [
            MitreMapping(
                tactic_id="TA0001",
                tactic_name="Initial Access",
                technique_id="T1078",
                technique_name="Valid Accounts",
                confidence=0.5
            )
        ]
        
        # Determine severity based on patterns found
        severity = SeverityLevel.LOW
        if len(error_patterns) > 10:
            severity = SeverityLevel.HIGH
        elif len(error_patterns) > 5:
            severity = SeverityLevel.MEDIUM
        
        return InitialAnalysis(
            summary=f"Mock analysis completed. Found {len(mock_iocs)} IOCs and {len(error_patterns)} suspicious patterns.",
            iocs=mock_iocs,
            mitre_mappings=mock_mitre,
            severity=severity,
            confidence=0.3,  # Low confidence for mock analysis
            suspicious_patterns=error_patterns[:5]  # Limit patterns
        )

class PromptTemplates:
    """Collection of specialized prompts for different analysis types."""
    
    @staticmethod
    def get_malware_analysis_prompt() -> str:
        """Prompt template for malware-focused analysis."""
        return """Analyze these logs specifically for malware indicators:
- File execution patterns
- Registry modifications
- Network communications
- Process injections
- Persistence mechanisms

Focus on identifying:
1. Known malware signatures
2. Suspicious file behaviors
3. Command and control communications
4. Data exfiltration attempts
"""
    
    @staticmethod
    def get_lateral_movement_prompt() -> str:
        """Prompt template for lateral movement analysis."""
        return """Analyze these logs for lateral movement indicators:
- Authentication events across systems
- Remote access patterns
- Service account usage
- Network share access
- Administrative tool usage

Focus on identifying:
1. Credential reuse patterns
2. Privilege escalation attempts
3. Remote execution activities
4. Abnormal authentication flows
"""
    
    @staticmethod
    def get_data_exfiltration_prompt() -> str:
        """Prompt template for data exfiltration analysis."""
        return """Analyze these logs for data exfiltration indicators:
- Large data transfers
- Unusual network traffic
- Access to sensitive files
- Compression/archiving activities
- External communications

Focus on identifying:
1. Unusual data access patterns
2. Large file transfers
3. External network connections
4. Data staging activities
"""