"""
Configuration settings for the Forensic AI Log Analyzer.
"""
import os
from typing import Dict, Any
from dotenv import load_dotenv

load_dotenv()

class Config:
    """Configuration class for the Forensic AI Log Analyzer."""
    
    # LLM Provider Selection
    LLM_PROVIDER = os.getenv("LLM_PROVIDER", "ibm").lower()  # "ibm" or "groq"

    # IBM Watsonx.ai Configuration
    IBM_API_KEY = os.getenv("IBM_API_KEY", "")
    IBM_PROJECT_ID = os.getenv("IBM_PROJECT_ID", "")
    IBM_URL = os.getenv("IBM_URL", "https://us-south.ml.cloud.ibm.com")
    
    # Groq Cloud Configuration
    GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
    GROQ_MODEL_ID = os.getenv("GROQ_MODEL_ID", "llama-3.1-8b-instant")
    GROQ_MAX_TOKENS = int(os.getenv("GROQ_MAX_TOKENS", "2000"))
    GROQ_TEMPERATURE = float(os.getenv("GROQ_TEMPERATURE", "0.1"))

    # AWS Configuration
    AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID", "")
    AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY", "")
    AWS_REGION = os.getenv("AWS_REGION", "us-east-1")
    
    # DynamoDB + Bedrock Configuration (replaces Kendra)
    DYNAMODB_TABLE_NAME = os.getenv("DYNAMODB_TABLE_NAME", "SecurityLogs")
    BEDROCK_EMBEDDING_MODEL = os.getenv("BEDROCK_EMBEDDING_MODEL", "amazon.titan-embed-text-v2:0")
    
    # VirusTotal Configuration
    VT_API_KEY = os.getenv("VT_API_KEY", "")
    
    # Application Settings
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
    MAX_LOG_ENTRIES = int(os.getenv("MAX_LOG_ENTRIES", "10000"))
    
    # ChromaDB Settings
    CHROMA_PERSIST_DIR = os.getenv("CHROMA_PERSIST_DIR", "./chroma_db")
    
    # MITRE ATT&CK Framework Mapping
    MITRE_TACTICS = {
        "TA0001": "Initial Access",
        "TA0002": "Execution",
        "TA0003": "Persistence",
        "TA0004": "Privilege Escalation",
        "TA0005": "Defense Evasion",
        "TA0006": "Credential Access",
        "TA0007": "Discovery",
        "TA0008": "Lateral Movement",
        "TA0009": "Collection",
        "TA0010": "Exfiltration",
        "TA0011": "Command and Control",
        "TA0040": "Impact"
    }
    
    # Granite LLM Configuration
    GRANITE_MODEL_ID = os.getenv("GRANITE_MODEL_ID", "ibm/granite-3-8b-instruct")
    GRANITE_PARAMETERS = {
        "decoding_method": "greedy",
        "max_new_tokens": 2000,
        "temperature": 0.1,
        "top_p": 1.0
    }
    
    @classmethod
    def validate_config(cls) -> Dict[str, bool]:
        """Validate configuration settings."""
        return {
            "ibm_configured": bool(cls.IBM_API_KEY and cls.IBM_PROJECT_ID),
            "groq_configured": bool(cls.GROQ_API_KEY),
            "aws_configured": bool(cls.AWS_ACCESS_KEY_ID and cls.AWS_SECRET_ACCESS_KEY),
            "vt_configured": bool(cls.VT_API_KEY)
        }