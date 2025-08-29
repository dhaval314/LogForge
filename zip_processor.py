"""
ZIP File Processor for LogForge - Handles extraction and categorization of log files from ZIP archives.
"""

import os
import zipfile
import tempfile
import shutil
from pathlib import Path
from typing import List, Dict, Any, Tuple, Optional
from loguru import logger
from datetime import datetime

class LogFileCategorizer:
    """Categorizes log files based on their content and filename patterns."""
    
    # File extension patterns for different log types
    LOG_PATTERNS = {
        "network": [
            "*.pcap", "*.pcapng", "*.cap", "*.tcpdump",
            "*network*", "*traffic*", "*packet*", "*netflow*",
            "*firewall*", "*ids*", "*ips*", "*wireshark*"
        ],
        "system": [
            "*.evtx", "*.evt", "*system*", "*syslog*", "*sys*",
            "*windows*", "*event*", "*security*", "*application*"
        ],
        "process": [
            "*process*", "*proc*", "*task*", "*ps*", "*tasklist*",
            "*processlist*", "*running*", "*services*"
        ],
        "services": [
            "*service*", "*daemon*", "*init*", "*systemd*",
            "*windows_service*", "*service_log*"
        ],
        "authentication": [
            "*auth*", "*login*", "*user*", "*password*", "*credential*",
            "*ldap*", "*kerberos*", "*sso*", "*mfa*"
        ],
        "malware": [
            "*malware*", "*virus*", "*antivirus*", "*av*", "*edr*",
            "*xdr*", "*threat*", "*detection*", "*quarantine*"
        ],
        "web": [
            "*web*", "*http*", "*https*", "*apache*", "*nginx*",
            "*iis*", "*access*", "*error*", "*proxy*"
        ],
        "database": [
            "*db*", "*database*", "*sql*", "*mysql*", "*postgres*",
            "*oracle*", "*mssql*", "*mongodb*", "*redis*"
        ],
        "application": [
            "*app*", "*application*", "*custom*", "*business*",
            "*enterprise*", "*software*", "*program*"
        ],
        "general": [
            "*.log", "*.txt", "*.csv", "*.json", "*.xml",
            "*log*", "*output*", "*debug*", "*trace*"
        ]
    }
    
    @classmethod
    def categorize_file(cls, filename: str, content_sample: str = "") -> str:
        """
        Categorize a file based on its filename and optional content sample.
        
        Args:
            filename: Name of the file
            content_sample: First few lines of file content for better categorization
            
        Returns:
            Category name (network, system, process, etc.)
        """
        filename_lower = filename.lower()
        
        # Check each category's patterns
        for category, patterns in cls.LOG_PATTERNS.items():
            for pattern in patterns:
                if pattern.startswith("*") and pattern.endswith("*"):
                    # Wildcard pattern
                    if pattern[1:-1] in filename_lower:
                        return category
                elif pattern.startswith("*"):
                    # Ends with pattern
                    if filename_lower.endswith(pattern[1:]):
                        return category
                elif pattern.endswith("*"):
                    # Starts with pattern
                    if filename_lower.startswith(pattern[:-1]):
                        return category
                else:
                    # Exact match
                    if filename_lower == pattern:
                        return category
        
        # Content-based categorization if filename didn't match
        if content_sample:
            content_lower = content_sample.lower()
            
            # Network-related content
            if any(keyword in content_lower for keyword in ["ip", "tcp", "udp", "packet", "connection", "port"]):
                return "network"
            
            # Process-related content
            if any(keyword in content_lower for keyword in ["process", "pid", "task", "service", "running"]):
                return "process"
            
            # Authentication-related content
            if any(keyword in content_lower for keyword in ["login", "user", "password", "auth", "credential"]):
                return "authentication"
            
            # System-related content
            if any(keyword in content_lower for keyword in ["system", "event", "error", "warning", "info"]):
                return "system"
        
        # Default to general if no specific category found
        return "general"

class ZIPProcessor:
    """Processes ZIP files containing log files for forensic analysis."""
    
    def __init__(self, max_file_size_mb: int = 100, max_total_size_mb: int = 500):
        """
        Initialize ZIP processor.
        
        Args:
            max_file_size_mb: Maximum size for individual files in MB
            max_total_size_mb: Maximum total size for all extracted files in MB
        """
        self.max_file_size = max_file_size_mb * 1024 * 1024  # Convert to bytes
        self.max_total_size = max_total_size_mb * 1024 * 1024  # Convert to bytes
        self.categorizer = LogFileCategorizer()
    
    def extract_and_categorize(self, zip_file_path: str) -> Dict[str, Any]:
        """
        Extract ZIP file and categorize the contents.
        
        Args:
            zip_file_path: Path to the ZIP file
            
        Returns:
            Dictionary containing extraction results and categorized files
        """
        results = {
            "success": False,
            "error": None,
            "extracted_files": [],
            "categorized_files": {},
            "total_size": 0,
            "file_count": 0,
            "temp_dir": None
        }
        
        try:
            # Create temporary directory for extraction
            temp_dir = tempfile.mkdtemp(prefix="logforge_zip_")
            results["temp_dir"] = temp_dir
            
            logger.info(f"Extracting ZIP file: {zip_file_path}")
            
            with zipfile.ZipFile(zip_file_path, 'r') as zip_ref:
                # Get file list and validate
                file_list = zip_ref.namelist()
                total_size = 0
                
                # Calculate total size and validate individual files
                for file_info in zip_ref.infolist():
                    if file_info.file_size > self.max_file_size:
                        raise ValueError(f"File {file_info.filename} exceeds maximum size limit of {self.max_file_size / (1024*1024):.1f} MB")
                    total_size += file_info.file_size
                
                if total_size > self.max_total_size:
                    raise ValueError(f"Total ZIP contents exceed maximum size limit of {self.max_total_size / (1024*1024):.1f} MB")
                
                # Extract files
                zip_ref.extractall(temp_dir)
                
                # Process extracted files
                extracted_files = []
                categorized_files = {}
                
                for root, dirs, files in os.walk(temp_dir):
                    for file in files:
                        file_path = os.path.join(root, file)
                        relative_path = os.path.relpath(file_path, temp_dir)
                        
                        # Get file info
                        file_size = os.path.getsize(file_path)
                        file_info = {
                            "name": file,
                            "path": file_path,
                            "relative_path": relative_path,
                            "size_bytes": file_size,
                            "size_mb": file_size / (1024 * 1024),
                            "category": "unknown"
                        }
                        
                        # Read sample content for categorization
                        content_sample = ""
                        try:
                            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                content_sample = f.read(1000)  # Read first 1000 characters
                        except Exception as e:
                            logger.warning(f"Could not read content sample from {file}: {e}")
                        
                        # Categorize file
                        category = self.categorizer.categorize_file(file, content_sample)
                        file_info["category"] = category
                        
                        # Add to lists
                        extracted_files.append(file_info)
                        
                        if category not in categorized_files:
                            categorized_files[category] = []
                        categorized_files[category].append(file_info)
                
                results.update({
                    "success": True,
                    "extracted_files": extracted_files,
                    "categorized_files": categorized_files,
                    "total_size": total_size,
                    "file_count": len(extracted_files)
                })
                
                logger.info(f"Successfully extracted {len(extracted_files)} files from ZIP")
                
        except Exception as e:
            results["error"] = str(e)
            logger.error(f"Failed to extract ZIP file: {e}")
            
            # Cleanup temp directory on error
            if results["temp_dir"] and os.path.exists(results["temp_dir"]):
                shutil.rmtree(results["temp_dir"])
        
        return results
    
    def cleanup_temp_dir(self, temp_dir: str):
        """Clean up temporary directory."""
        try:
            if temp_dir and os.path.exists(temp_dir):
                shutil.rmtree(temp_dir)
                logger.info(f"Cleaned up temporary directory: {temp_dir}")
        except Exception as e:
            logger.error(f"Failed to cleanup temporary directory {temp_dir}: {e}")
    
    def get_readable_files(self, extracted_files: List[Dict[str, Any]]) -> List[str]:
        """
        Get list of file paths that can be read as text for log analysis.
        
        Args:
            extracted_files: List of extracted file information
            
        Returns:
            List of file paths that can be processed
        """
        readable_files = []
        
        for file_info in extracted_files:
            file_path = file_info["path"]
            
            # Skip directories and non-text files
            if os.path.isdir(file_path):
                continue
            
            # Check file extension
            file_ext = Path(file_path).suffix.lower()
            if file_ext in ['.txt', '.log', '.csv', '.json', '.xml', '.evtx', '.evt']:
                readable_files.append(file_path)
            elif file_ext == '':  # No extension, try to read anyway
                readable_files.append(file_path)
        
        return readable_files
    
    def generate_summary_report(self, results: Dict[str, Any]) -> str:
        """
        Generate a summary report of the ZIP extraction results.
        
        Args:
            results: Results from extract_and_categorize method
            
        Returns:
            Formatted summary report
        """
        if not results["success"]:
            return f"Extraction failed: {results['error']}"
        
        report_lines = [
            "📦 ZIP File Extraction Summary",
            "=" * 40,
            f"Successfully extracted {results['file_count']} files",
            f"Total size: {results['total_size'] / (1024*1024):.2f} MB",
            "",
            "File Categories:"
        ]
        
        for category, files in results["categorized_files"].items():
            category_size = sum(f["size_bytes"] for f in files)
            report_lines.append(f"  • {category.title()}: {len(files)} files ({category_size / (1024*1024):.2f} MB)")
        
        report_lines.extend([
            "",
            "📋 File Details:",
            "-" * 20
        ])
        
        for file_info in results["extracted_files"][:10]:  # Show first 10 files
            report_lines.append(f"  • {file_info['name']} ({file_info['category']}) - {file_info['size_mb']:.2f} MB")
        
        if len(results["extracted_files"]) > 10:
            report_lines.append(f"  ... and {len(results['extracted_files']) - 10} more files")
        
        return "\n".join(report_lines)

def process_zip_file(zip_file_path: str, max_file_size_mb: int = 100, max_total_size_mb: int = 500) -> Dict[str, Any]:
    """
    Convenience function to process a ZIP file.
    
    Args:
        zip_file_path: Path to the ZIP file
        max_file_size_mb: Maximum size for individual files in MB
        max_total_size_mb: Maximum total size for all extracted files in MB
        
    Returns:
        Processing results dictionary
    """
    processor = ZIPProcessor(max_file_size_mb, max_total_size_mb)
    return processor.extract_and_categorize(zip_file_path)
