#!/usr/bin/env python3
"""
Production Health Check Script for Forensic AI Log Analyzer
"""
import sys
import os
import json
import time
import requests
from pathlib import Path
from typing import Dict, Any, List
from loguru import logger

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from config import Config
from llm_analysis import GraniteAnalyzer
from utilities import VirusTotalEnricher
from aws_s3_utils import is_s3_available

class HealthChecker:
    """Production health check for the Forensic AI Log Analyzer."""
    
    def __init__(self):
        self.checks = []
        self.overall_status = "healthy"
    
    def add_check(self, name: str, status: str, details: Dict[str, Any] = None):
        """Add a health check result."""
        check = {
            "name": name,
            "status": status,
            "timestamp": time.time(),
            "details": details or {}
        }
        self.checks.append(check)
        
        if status == "unhealthy":
            self.overall_status = "unhealthy"
        elif status == "degraded" and self.overall_status == "healthy":
            self.overall_status = "degraded"
    
    def check_configuration(self):
        """Check configuration validation."""
        try:
            validation = Config.validate_production_config()
            if validation["valid"]:
                self.add_check("configuration", "healthy", {
                    "warnings": len(validation["warnings"]),
                    "errors": len(validation["errors"])
                })
            else:
                self.add_check("configuration", "unhealthy", {
                    "errors": validation["errors"],
                    "warnings": validation["warnings"]
                })
        except Exception as e:
            self.add_check("configuration", "unhealthy", {"error": str(e)})
    
    def check_llm_connection(self):
        """Check LLM provider connectivity."""
        try:
            analyzer = GraniteAnalyzer()
            if analyzer.client or analyzer.groq_client:
                provider = Config.LLM_PROVIDER
                self.add_check("llm_connection", "healthy", {"provider": provider})
            else:
                self.add_check("llm_connection", "unhealthy", {"error": "No LLM client available"})
        except Exception as e:
            self.add_check("llm_connection", "unhealthy", {"error": str(e)})
    
    def check_virustotal(self):
        """Check VirusTotal API connectivity."""
        try:
            if not Config.VT_API_KEY:
                self.add_check("virustotal", "degraded", {"message": "API key not configured"})
                return
            
            vt = VirusTotalEnricher()
            if vt.client:
                self.add_check("virustotal", "healthy")
            else:
                self.add_check("virustotal", "unhealthy", {"error": "Client not initialized"})
        except Exception as e:
            self.add_check("virustotal", "unhealthy", {"error": str(e)})
    
    def check_aws_s3(self):
        """Check AWS S3 connectivity."""
        try:
            if not Config.AWS_ACCESS_KEY_ID:
                self.add_check("aws_s3", "degraded", {"message": "AWS credentials not configured"})
                return
            
            if is_s3_available():
                self.add_check("aws_s3", "healthy")
            else:
                self.add_check("aws_s3", "unhealthy", {"error": "S3 not available"})
        except Exception as e:
            self.add_check("aws_s3", "unhealthy", {"error": str(e)})
    
    def check_disk_space(self):
        """Check available disk space."""
        try:
            import shutil
            total, used, free = shutil.disk_usage(".")
            free_gb = free / (1024**3)
            
            if free_gb > 10:
                self.add_check("disk_space", "healthy", {"free_gb": round(free_gb, 2)})
            elif free_gb > 5:
                self.add_check("disk_space", "degraded", {"free_gb": round(free_gb, 2)})
            else:
                self.add_check("disk_space", "unhealthy", {"free_gb": round(free_gb, 2)})
        except Exception as e:
            self.add_check("disk_space", "unhealthy", {"error": str(e)})
    
    def check_log_files(self):
        """Check log file health."""
        try:
            log_dir = Path("logs")
            if not log_dir.exists():
                self.add_check("log_files", "degraded", {"message": "Log directory not found"})
                return
            
            log_files = list(log_dir.glob("*.log"))
            if not log_files:
                self.add_check("log_files", "degraded", {"message": "No log files found"})
                return
            
            # Check for recent log activity
            recent_logs = [f for f in log_files if time.time() - f.stat().st_mtime < 3600]
            
            if recent_logs:
                self.add_check("log_files", "healthy", {
                    "total_files": len(log_files),
                    "recent_files": len(recent_logs)
                })
            else:
                self.add_check("log_files", "degraded", {
                    "message": "No recent log activity",
                    "total_files": len(log_files)
                })
        except Exception as e:
            self.add_check("log_files", "unhealthy", {"error": str(e)})
    
    def check_chromadb(self):
        """Check ChromaDB health."""
        try:
            chroma_dir = Path(Config.CHROMA_PERSIST_DIR)
            if not chroma_dir.exists():
                self.add_check("chromadb", "degraded", {"message": "ChromaDB directory not found"})
                return
            
            # Check if ChromaDB files exist
            db_files = list(chroma_dir.rglob("*.bin")) + list(chroma_dir.rglob("*.sqlite*"))
            
            if db_files:
                self.add_check("chromadb", "healthy", {"files": len(db_files)})
            else:
                self.add_check("chromadb", "degraded", {"message": "No ChromaDB files found"})
        except Exception as e:
            self.add_check("chromadb", "unhealthy", {"error": str(e)})
    
    def check_web_dashboard(self):
        """Check web dashboard availability."""
        try:
            # Try to connect to Streamlit dashboard
            response = requests.get("http://localhost:8501/_stcore/health", timeout=5)
            if response.status_code == 200:
                self.add_check("web_dashboard", "healthy")
            else:
                self.add_check("web_dashboard", "unhealthy", {"status_code": response.status_code})
        except requests.exceptions.RequestException:
            self.add_check("web_dashboard", "degraded", {"message": "Dashboard not accessible"})
        except Exception as e:
            self.add_check("web_dashboard", "unhealthy", {"error": str(e)})
    
    def run_all_checks(self) -> Dict[str, Any]:
        """Run all health checks."""
        logger.info("Starting production health checks...")
        
        self.check_configuration()
        self.check_llm_connection()
        self.check_virustotal()
        self.check_aws_s3()
        self.check_disk_space()
        self.check_log_files()
        self.check_chromadb()
        self.check_web_dashboard()
        
        result = {
            "status": self.overall_status,
            "timestamp": time.time(),
            "checks": self.checks,
            "summary": {
                "total": len(self.checks),
                "healthy": len([c for c in self.checks if c["status"] == "healthy"]),
                "degraded": len([c for c in self.checks if c["status"] == "degraded"]),
                "unhealthy": len([c for c in self.checks if c["status"] == "unhealthy"])
            }
        }
        
        logger.info(f"Health check completed: {result['status']}")
        return result

def main():
    """Main health check function."""
    # Set up logging
    logger.remove()
    logger.add(sys.stderr, level="INFO", format="{time} | {level} | {message}")
    
    # Run health checks
    checker = HealthChecker()
    result = checker.run_all_checks()
    
    # Output results
    if len(sys.argv) > 1 and sys.argv[1] == "--json":
        print(json.dumps(result, indent=2))
    else:
        print(f"Overall Status: {result['status'].upper()}")
        print(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(result['timestamp']))}")
        print(f"Summary: {result['summary']['healthy']} healthy, {result['summary']['degraded']} degraded, {result['summary']['unhealthy']} unhealthy")
        print("\nDetailed Results:")
        
        for check in result['checks']:
            status_icon = "✓" if check['status'] == "healthy" else "⚠" if check['status'] == "degraded" else "✗"
            print(f"  {status_icon} {check['name']}: {check['status']}")
            if check['details']:
                for key, value in check['details'].items():
                    print(f"    {key}: {value}")
    
    # Exit with appropriate code
    if result['status'] == "unhealthy":
        sys.exit(1)
    elif result['status'] == "degraded":
        sys.exit(2)
    else:
        sys.exit(0)

if __name__ == "__main__":
    main()
