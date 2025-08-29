"""
LLM Provider Configuration and Helper Functions
"""
import os
from typing import List, Dict, Any, Optional
from datetime import datetime
from loguru import logger

from data_models import LogEntry, InitialAnalysis, IOC, MitreMapping, SeverityLevel
from config import Config

# Import existing LLM analysis module
from llm_analysis import GraniteAnalyzer

class LLMProviderManager:
    """Manages different LLM providers for forensic analysis."""
    
    def __init__(self):
        self.providers = {
            "ibm_granite": {
                "name": "IBM Granite",
                "description": "IBM's Granite model via Watsonx.ai",
                "available": True,
                "analyzer_class": GraniteAnalyzer
            },
            "aws_bedrock": {
                "name": "AWS Bedrock",
                "description": "AWS Bedrock with Claude or other models",
                "available": self._check_bedrock_availability(),
                "analyzer_class": None  # Will be implemented
            },
            "openai": {
                "name": "OpenAI GPT",
                "description": "OpenAI GPT models via API",
                "available": self._check_openai_availability(),
                "analyzer_class": None  # Will be implemented
            }
        }
    
    def _check_bedrock_availability(self) -> bool:
        """Check if AWS Bedrock is available."""
        try:
            import boto3
            # Check if AWS credentials are configured
            if not (Config.AWS_ACCESS_KEY_ID and Config.AWS_SECRET_ACCESS_KEY):
                return False
            
            # Try to create a Bedrock client
            bedrock = boto3.client(
                'bedrock-runtime',
                aws_access_key_id=Config.AWS_ACCESS_KEY_ID,
                aws_secret_access_key=Config.AWS_SECRET_ACCESS_KEY,
                region_name=Config.AWS_DEFAULT_REGION
            )
            return True
        except Exception as e:
            logger.debug(f"AWS Bedrock not available: {e}")
            return False
    
    def _check_openai_availability(self) -> bool:
        """Check if OpenAI is available."""
        try:
            openai_api_key = os.getenv("OPENAI_API_KEY")
            return bool(openai_api_key)
        except Exception as e:
            logger.debug(f"OpenAI not available: {e}")
            return False
    
    def get_available_providers(self) -> Dict[str, Dict[str, Any]]:
        """Get list of available LLM providers."""
        return {k: v for k, v in self.providers.items() if v["available"]}
    
    def get_provider_info(self, provider_id: str) -> Optional[Dict[str, Any]]:
        """Get information about a specific provider."""
        return self.providers.get(provider_id)
    
    def analyze_logs(self, log_entries: List[LogEntry], provider_id: str = "ibm_granite") -> InitialAnalysis:
        """
        Analyze logs using the specified LLM provider.
        
        Args:
            log_entries: List of log entries to analyze
            provider_id: ID of the LLM provider to use
            
        Returns:
            InitialAnalysis object with results
        """
        if not log_entries:
            logger.warning("No log entries provided for analysis")
            return self._create_empty_analysis()
        
        provider_info = self.providers.get(provider_id)
        if not provider_info:
            logger.error(f"Unknown provider: {provider_id}")
            return self._create_empty_analysis()
        
        if not provider_info["available"]:
            logger.error(f"Provider {provider_id} is not available")
            return self._create_empty_analysis()
        
        try:
            if provider_id == "ibm_granite":
                return self._analyze_with_granite(log_entries)
            elif provider_id == "aws_bedrock":
                return self._analyze_with_bedrock(log_entries)
            elif provider_id == "openai":
                return self._analyze_with_openai(log_entries)
            else:
                logger.error(f"Provider {provider_id} not implemented")
                return self._create_empty_analysis()
                
        except Exception as e:
            logger.error(f"Error analyzing logs with {provider_id}: {e}")
            return self._create_empty_analysis()
    
    def _analyze_with_granite(self, log_entries: List[LogEntry]) -> InitialAnalysis:
        """Analyze logs using IBM Granite."""
        try:
            analyzer = GraniteAnalyzer()
            return analyzer.analyze_logs(log_entries)
        except Exception as e:
            logger.error(f"Error in Granite analysis: {e}")
            return self._create_empty_analysis()
    
    def _analyze_with_bedrock(self, log_entries: List[LogEntry]) -> InitialAnalysis:
        """Analyze logs using AWS Bedrock."""
        try:
            import boto3
            import json
            
            # Create Bedrock client
            bedrock = boto3.client(
                'bedrock-runtime',
                aws_access_key_id=Config.AWS_ACCESS_KEY_ID,
                aws_secret_access_key=Config.AWS_SECRET_ACCESS_KEY,
                region_name=Config.AWS_DEFAULT_REGION
            )
            
            # Prepare log summary for analysis
            log_summary = self._prepare_log_summary(log_entries)
            
            # Create forensic analysis prompt
            prompt = self._create_forensic_prompt(log_summary)
            
            # Use Claude model (you can change this to other Bedrock models)
            model_id = "anthropic.claude-3-sonnet-20240229-v1:0"
            
            # Prepare request body
            request_body = {
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": 4000,
                "messages": [
                    {
                        "role": "user",
                        "content": prompt
                    }
                ]
            }
            
            # Make request to Bedrock
            response = bedrock.invoke_model(
                modelId=model_id,
                body=json.dumps(request_body)
            )
            
            # Parse response
            response_body = json.loads(response['body'].read())
            content = response_body['content'][0]['text']
            
            # Parse LLM response into structured format
            analysis = self._parse_llm_response(content, log_entries)
            
            logger.info("AWS Bedrock analysis completed")
            return analysis
            
        except Exception as e:
            logger.error(f"Error in Bedrock analysis: {e}")
            return self._create_empty_analysis()
    
    def _analyze_with_openai(self, log_entries: List[LogEntry]) -> InitialAnalysis:
        """Analyze logs using OpenAI GPT."""
        try:
            import openai
            
            # Set OpenAI API key
            openai.api_key = os.getenv("OPENAI_API_KEY")
            if not openai.api_key:
                raise ValueError("OPENAI_API_KEY not configured")
            
            # Prepare log summary for analysis
            log_summary = self._prepare_log_summary(log_entries)
            
            # Create forensic analysis prompt
            prompt = self._create_forensic_prompt(log_summary)
            
            # Make request to OpenAI
            response = openai.ChatCompletion.create(
                model="gpt-4",
                messages=[
                    {"role": "system", "content": "You are an expert cybersecurity forensic analyst."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=4000,
                temperature=0.1
            )
            
            # Extract response content
            content = response.choices[0].message.content
            
            # Parse LLM response into structured format
            analysis = self._parse_llm_response(content, log_entries)
            
            logger.info("OpenAI analysis completed")
            return analysis
            
        except Exception as e:
            logger.error(f"Error in OpenAI analysis: {e}")
            return self._create_empty_analysis()
    
    def _prepare_log_summary(self, log_entries: List[LogEntry]) -> str:
        """Prepare a concise summary of log entries for LLM analysis."""
        # Limit entries to avoid token limits
        max_entries = min(len(log_entries), 100)
        selected_entries = log_entries[:max_entries]
        
        summary_lines = []
        summary_lines.append(f"Total log entries: {len(log_entries)}")
        summary_lines.append(f"Analyzing first {max_entries} entries:")
        summary_lines.append("")
        
        for i, entry in enumerate(selected_entries, 1):
            timestamp = entry.timestamp.strftime("%Y-%m-%d %H:%M:%S") if entry.timestamp else "Unknown"
            summary_lines.append(f"{i}. [{timestamp}] {entry.source} - {entry.event_type}: {entry.message}")
        
        return "\n".join(summary_lines)
    
    def _create_forensic_prompt(self, log_summary: str) -> str:
        """Create a forensic analysis prompt for LLM."""
        return f"""Analyze these security logs for potential threats and security incidents:

{log_summary}

Please provide a comprehensive forensic analysis including:

1. **Summary**: Brief overview of findings
2. **IOCs (Indicators of Compromise)**: IP addresses, domains, file hashes, etc.
3. **MITRE ATT&CK Mappings**: Tactics and techniques observed
4. **Severity Assessment**: Overall incident severity (critical/high/medium/low/info)
5. **Confidence Level**: Analysis confidence (0.0-1.0)
6. **Suspicious Patterns**: Unusual or suspicious activities

Format your response as JSON with the following structure:
{{
    "summary": "Brief analysis summary",
    "iocs": [
        {{"type": "ip", "value": "192.168.1.1", "confidence": 0.8, "context": "Suspicious connection"}}
    ],
    "mitre_mappings": [
        {{"tactic_id": "TA0001", "tactic_name": "Initial Access", "technique_id": "T1078", "technique_name": "Valid Accounts", "confidence": 0.7}}
    ],
    "severity": "high",
    "confidence": 0.75,
    "suspicious_patterns": ["pattern1", "pattern2"]
}}"""
    
    def _parse_llm_response(self, response: str, log_entries: List[LogEntry]) -> InitialAnalysis:
        """Parse LLM response into structured InitialAnalysis object."""
        try:
            import json
            import re
            
            # Try to extract JSON from response
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if json_match:
                data = json.loads(json_match.group())
            else:
                # Fallback parsing
                data = self._fallback_parse_response(response)
            
            # Extract IOCs
            iocs = []
            for ioc_data in data.get("iocs", []):
                iocs.append(IOC(
                    type=ioc_data.get("type", "unknown"),
                    value=ioc_data.get("value", ""),
                    confidence=float(ioc_data.get("confidence", 0.5)),
                    context=ioc_data.get("context", "")
                ))
            
            # Extract MITRE mappings
            mitre_mappings = []
            for mapping_data in data.get("mitre_mappings", []):
                mitre_mappings.append(MitreMapping(
                    tactic_id=mapping_data.get("tactic_id", ""),
                    tactic_name=mapping_data.get("tactic_name", ""),
                    technique_id=mapping_data.get("technique_id"),
                    technique_name=mapping_data.get("technique_name"),
                    confidence=float(mapping_data.get("confidence", 0.5))
                ))
            
            # Determine severity
            severity_str = data.get("severity", "info").lower()
            severity_map = {
                "critical": SeverityLevel.CRITICAL,
                "high": SeverityLevel.HIGH,
                "medium": SeverityLevel.MEDIUM,
                "low": SeverityLevel.LOW,
                "info": SeverityLevel.INFO
            }
            severity = severity_map.get(severity_str, SeverityLevel.INFO)
            
            return InitialAnalysis(
                summary=data.get("summary", "Analysis completed"),
                iocs=iocs,
                mitre_mappings=mitre_mappings,
                severity=severity,
                confidence=float(data.get("confidence", 0.5)),
                suspicious_patterns=data.get("suspicious_patterns", [])
            )
            
        except Exception as e:
            logger.error(f"Error parsing LLM response: {e}")
            return self._create_empty_analysis()
    
    def _fallback_parse_response(self, response: str) -> Dict[str, Any]:
        """Fallback parsing when JSON extraction fails."""
        # Simple pattern matching for common elements
        data = {
            "summary": "Analysis completed",
            "iocs": [],
            "mitre_mappings": [],
            "severity": "info",
            "confidence": 0.5,
            "suspicious_patterns": []
        }
        
        # Try to extract summary
        if "summary" in response.lower():
            lines = response.split('\n')
            for line in lines:
                if "summary" in line.lower() and ":" in line:
                    data["summary"] = line.split(":", 1)[1].strip()
                    break
        
        # Try to extract IP addresses
        import re
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        ips = re.findall(ip_pattern, response)
        for ip in ips[:5]:  # Limit to 5 IPs
            data["iocs"].append({
                "type": "ip",
                "value": ip,
                "confidence": 0.6,
                "context": "Found in log analysis"
            })
        
        return data
    
    def _create_empty_analysis(self) -> InitialAnalysis:
        """Create an empty analysis result."""
        return InitialAnalysis(
            summary="No analysis results available",
            iocs=[],
            mitre_mappings=[],
            severity=SeverityLevel.INFO,
            confidence=0.0,
            suspicious_patterns=[]
        )

# Global provider manager instance
provider_manager = LLMProviderManager()

# Convenience functions for backward compatibility
def analyze_with_granite(logs: List[LogEntry]) -> InitialAnalysis:
    """Analyze logs using IBM Granite."""
    return provider_manager.analyze_logs(logs, "ibm_granite")

def analyze_with_bedrock(logs: List[LogEntry]) -> InitialAnalysis:
    """Analyze logs using AWS Bedrock."""
    return provider_manager.analyze_logs(logs, "aws_bedrock")

def analyze_with_openai(logs: List[LogEntry]) -> InitialAnalysis:
    """Analyze logs using OpenAI GPT."""
    return provider_manager.analyze_logs(logs, "openai")

def get_available_providers() -> Dict[str, Dict[str, Any]]:
    """Get list of available LLM providers."""
    return provider_manager.get_available_providers()

def get_provider_info(provider_id: str) -> Optional[Dict[str, Any]]:
    """Get information about a specific provider."""
    return provider_manager.get_provider_info(provider_id)
