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
    GROQ_MODEL_ID = os.getenv("GROQ_MODEL_ID", "compound-beta")
    GROQ_MAX_TOKENS = int(os.getenv("GROQ_MAX_TOKENS", "2000"))
    GROQ_TEMPERATURE = float(os.getenv("GROQ_TEMPERATURE", "0.1"))

    # ChromaDB Configuration
    CHROMA_PERSIST_DIR = os.getenv("CHROMA_PERSIST_DIR", "./chroma_db")
    CHROMA_COLLECTION_NAME = os.getenv("CHROMA_COLLECTION_NAME", "security_logs")
    
    # VirusTotal Configuration
    VT_API_KEY = os.getenv("VT_API_KEY", "")
    
    # Application Settings
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
    MAX_LOG_ENTRIES = int(os.getenv("MAX_LOG_ENTRIES", "10000"))
    DEBUG_MODE = os.getenv("DEBUG_MODE", "false").lower() == "true"
    
    # AWS S3 Configuration
    AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID", "")
    AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY", "")
    AWS_DEFAULT_REGION = os.getenv("AWS_DEFAULT_REGION", "us-east-1")
    AWS_S3_BUCKET = os.getenv("AWS_S3_BUCKET", "")
    
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
            "chromadb_configured": True,  # ChromaDB works locally without credentials
            "vt_configured": bool(cls.VT_API_KEY),
            "s3_configured": bool(cls.AWS_ACCESS_KEY_ID and cls.AWS_SECRET_ACCESS_KEY and cls.AWS_S3_BUCKET)
        }
    
    @classmethod
    def validate_production_config(cls) -> Dict[str, Any]:
        """Validate production configuration settings."""
        validation = {
            "valid": True,
            "errors": [],
            "warnings": []
        }
        
        # Check required settings
        if not cls.IBM_API_KEY and not cls.GROQ_API_KEY:
            validation["errors"].append("No LLM provider configured (IBM or Groq)")
            validation["valid"] = False
        
        if cls.LLM_PROVIDER == "ibm" and not cls.IBM_PROJECT_ID:
            validation["errors"].append("IBM_PROJECT_ID required when using IBM provider")
            validation["valid"] = False
        
        # Check optional but recommended settings
        if not cls.VT_API_KEY:
            validation["warnings"].append("VirusTotal API key not configured - IOC enrichment disabled")
        
        if not cls.AWS_ACCESS_KEY_ID or not cls.AWS_SECRET_ACCESS_KEY:
            validation["warnings"].append("AWS credentials not configured - S3 storage disabled")
        
        # Check security settings
        if cls.DEBUG_MODE:
            validation["warnings"].append("DEBUG_MODE enabled - should be false in production")
        
        return validation