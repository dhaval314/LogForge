"""
Security Utilities Module - VirusTotal, YARA, and other security tools integration.
"""
import hashlib
import time
from datetime import datetime
from typing import Dict, Any, List, Optional, Union
from pathlib import Path
from loguru import logger

# VirusTotal integration
try:
    import vt
except ImportError:
    logger.warning("vt-py not available, VirusTotal integration disabled")
    vt = None

# YARA integration
try:
    import yara
except ImportError:
    logger.warning("yara-python not available, YARA scanning disabled")
    yara = None

# Scapy for network analysis
try:
    from scapy.all import rdpcap, IP, TCP, UDP
except ImportError:
    logger.warning("scapy not available, PCAP analysis disabled")
    rdpcap = None

from data_models import EnrichmentData, LogEntry
from config import Config

class VirusTotalEnricher:
    """VirusTotal API integration for IOC reputation checking."""
    
    def __init__(self):
        self.client = None
        self.api_key = Config.VT_API_KEY
        self.rate_limit_delay = 15  # VT free API allows 4 requests per minute
        self._initialize_client()
    
    def _initialize_client(self):
        """Initialize VirusTotal API client."""
        if not vt or not self.api_key:
            logger.warning("VirusTotal not available or API key not configured")
            return
        
        try:
            # Validate API key format (basic check)
            if len(self.api_key) < 10:
                raise ValueError("VirusTotal API key appears to be invalid (too short)")
            
            self.client = vt.Client(self.api_key)
            
            # Test the connection with a simple query
            try:
                # Test with a known safe IP
                test_ip = "8.8.8.8"
                self.client.get_object(f"/ip_addresses/{test_ip}")
                logger.info("VirusTotal client initialized and tested successfully")
            except Exception as test_error:
                logger.warning(f"VirusTotal connection test failed: {test_error}")
                # Don't fail completely, just warn
                
        except Exception as e:
            logger.error(f"Failed to initialize VirusTotal client: {e}")
            self.client = None
    
    def check_ioc(self, ioc_value: str, ioc_type: str) -> Optional[EnrichmentData]:
        """
        Check IOC reputation with VirusTotal.
        
        Args:
            ioc_value: The IOC value (IP, domain, hash, etc.)
            ioc_type: Type of IOC (ip, domain, hash)
            
        Returns:
            EnrichmentData with VirusTotal results or None
        """
        if not self.client:
            return None
        
        try:
            logger.debug(f"Checking {ioc_type} {ioc_value} with VirusTotal")
            
            # Rate limiting
            time.sleep(self.rate_limit_delay)
            
            # Query based on IOC type
            if ioc_type == "ip":
                obj = self.client.get_object(f"/ip_addresses/{ioc_value}")
            elif ioc_type == "domain":
                obj = self.client.get_object(f"/domains/{ioc_value}")
            elif ioc_type == "hash":
                obj = self.client.get_object(f"/files/{ioc_value}")
            else:
                logger.warning(f"Unsupported IOC type for VT: {ioc_type}")
                return None
            
            # Extract relevant data
            vt_data = self._parse_vt_response(obj, ioc_type)
            
            # Create enrichment data
            enrichment = EnrichmentData(
                source="virustotal",
                ioc_value=ioc_value,
                reputation_score=vt_data.get("reputation_score"),
                additional_context=vt_data,
                last_updated=datetime.now()
            )
            
            logger.debug(f"VirusTotal check completed for {ioc_value}")
            return enrichment
            
        except vt.error.APIError as e:
            if e.code == "NotFoundError":
                logger.debug(f"IOC {ioc_value} not found in VirusTotal")
            else:
                logger.error(f"VirusTotal API error for {ioc_value}: {e}")
            return None
        except Exception as e:
            logger.error(f"Error checking VirusTotal for {ioc_value}: {e}")
            return None
        finally:
            # Ensure we don't leave the client hanging
            pass
    
    def _parse_vt_response(self, vt_obj: Any, ioc_type: str) -> Dict[str, Any]:
        """Parse VirusTotal API response."""
        try:
            parsed_data = {
                "ioc_type": ioc_type,
                "vt_object_id": getattr(vt_obj, 'id', 'unknown')
            }
            
            if ioc_type in ["ip", "domain"]:
                # Network IOC data
                if hasattr(vt_obj, 'last_analysis_stats'):
                    stats = vt_obj.last_analysis_stats
                    malicious = stats.get('malicious', 0)
                    suspicious = stats.get('suspicious', 0)
                    total = sum(stats.values())
                    
                    parsed_data.update({
                        "malicious_vendors": malicious,
                        "suspicious_vendors": suspicious,
                        "total_vendors": total,
                        "reputation_score": 1.0 - ((malicious + suspicious * 0.5) / max(total, 1))
                    })
                
                # Additional network attributes
                if hasattr(vt_obj, 'country'):
                    parsed_data["country"] = vt_obj.country
                
                if hasattr(vt_obj, 'as_owner'):
                    parsed_data["as_owner"] = vt_obj.as_owner
                
                if hasattr(vt_obj, 'categories'):
                    parsed_data["categories"] = vt_obj.categories
            
            elif ioc_type == "hash":
                # File hash data
                if hasattr(vt_obj, 'last_analysis_stats'):
                    stats = vt_obj.last_analysis_stats
                    malicious = stats.get('malicious', 0)
                    suspicious = stats.get('suspicious', 0)
                    total = sum(stats.values())
                    
                    parsed_data.update({
                        "malicious_vendors": malicious,
                        "suspicious_vendors": suspicious,
                        "total_vendors": total,
                        "reputation_score": 1.0 - ((malicious + suspicious * 0.5) / max(total, 1))
                    })
                
                # File attributes
                if hasattr(vt_obj, 'meaningful_name'):
                    parsed_data["file_name"] = vt_obj.meaningful_name
                
                if hasattr(vt_obj, 'size'):
                    parsed_data["file_size"] = vt_obj.size
                
                if hasattr(vt_obj, 'file_type'):
                    parsed_data["file_type"] = vt_obj.file_type
            
            return parsed_data
            
        except Exception as e:
            logger.error(f"Error parsing VT response: {e}")
            return {"error": str(e)}
    
    def close(self):
        """Close VirusTotal client."""
        if self.client:
            try:
                self.client.close()
            except Exception as e:
                logger.error(f"Error closing VT client: {e}")

class YaraScanner:
    """YARA rule engine for malware detection."""
    
    def __init__(self, rules_directory: str = None):
        self.rules_directory = Path(rules_directory) if rules_directory else Path("yara_rules")
        self.compiled_rules = None
        self.malware_hashes = self._load_malware_hashes()
        self._initialize_rules()
    
    def _initialize_rules(self):
        """Initialize YARA rules."""
        if not yara:
            logger.warning("YARA not available")
            return
        
        try:
            # Create sample YARA rules if directory doesn't exist
            if not self.rules_directory.exists():
                self.rules_directory.mkdir(parents=True)
                self._create_sample_rules()
            
            # Compile YARA rules
            rule_files = list(self.rules_directory.glob("*.yar"))
            if rule_files:
                # For simplicity, compile the first rule file found
                self.compiled_rules = yara.compile(str(rule_files[0]))
                logger.info(f"YARA rules compiled from {rule_files[0]}")
            else:
                logger.warning("No YARA rule files found")
                
        except Exception as e:
            logger.error(f"Error initializing YARA rules: {e}")
    
    def _create_sample_rules(self):
        """Create sample YARA rules for demonstration."""
        sample_rule = '''
rule SuspiciousPowerShell {
    meta:
        description = "Detects suspicious PowerShell patterns"
        author = "Forensic AI Analyzer"
        
    strings:
        $powershell1 = "powershell" nocase
        $encoded1 = "EncodedCommand" nocase
        $encoded2 = "-enc" nocase
        $bypass1 = "ExecutionPolicy Bypass" nocase
        $download1 = "DownloadString" nocase
        $download2 = "IEX" nocase
        
    condition:
        $powershell1 and (
            ($encoded1 or $encoded2) or
            $bypass1 or
            ($download1 and $download2)
        )
}

rule SuspiciousNetworkActivity {
    meta:
        description = "Detects suspicious network activity patterns"
        
    strings:
        $curl1 = "curl" nocase
        $wget1 = "wget" nocase
        $nc1 = "netcat" nocase
        $nc2 = "nc -" nocase
        $reverse1 = "/bin/sh" nocase
        $reverse2 = "/bin/bash" nocase
        
    condition:
        ($curl1 or $wget1) or
        ($nc1 or $nc2) and ($reverse1 or $reverse2)
}
'''
        
        rule_file = self.rules_directory / "sample_rules.yar"
        with open(rule_file, 'w') as f:
            f.write(sample_rule)
        
        logger.info(f"Created sample YARA rules: {rule_file}")
    
    def _load_malware_hashes(self) -> Dict[str, str]:
        """Load known malware hashes for simulation."""
        return {
            "5d41402abc4b2a76b9719d911017c592": "hello_world_malware_sample",
            "098f6bcd4621d373cade4e832627b4f6": "test_malware_signature",
            "6d7fce9fee471194aa8b5b6e47267f03": "suspicious_executable",
        }
    
    def scan_for_patterns(self, log_entries: List[LogEntry]) -> List[Dict[str, Any]]:
        """
        Scan log entries for malware patterns using YARA rules.
        
        Args:
            log_entries: List of log entries to scan
            
        Returns:
            List of YARA matches
        """
        matches = []
        
        try:
            # Check for known malware hashes first
            hash_matches = self._check_hash_patterns(log_entries)
            matches.extend(hash_matches)
            
            # YARA rule scanning
            if self.compiled_rules:
                yara_matches = self._scan_with_yara(log_entries)
                matches.extend(yara_matches)
            else:
                # Fallback pattern matching
                pattern_matches = self._pattern_based_scanning(log_entries)
                matches.extend(pattern_matches)
            
            logger.info(f"YARA scanning completed: {len(matches)} matches found")
            return matches
            
        except Exception as e:
            logger.error(f"Error during YARA scanning: {e}")
            return []
    
    def _check_hash_patterns(self, log_entries: List[LogEntry]) -> List[Dict[str, Any]]:
        """Check log entries for known malware hashes."""
        matches = []
        
        for entry in log_entries:
            message = entry.message.lower()
            
            # Look for potential hash values (MD5, SHA1, SHA256)
            import re
            hash_patterns = [
                r'\b[a-f0-9]{32}\b',  # MD5
                r'\b[a-f0-9]{40}\b',  # SHA1
                r'\b[a-f0-9]{64}\b'   # SHA256
            ]
            
            for pattern in hash_patterns:
                found_hashes = re.findall(pattern, message)
                for hash_value in found_hashes:
                    if hash_value in self.malware_hashes:
                        matches.append({
                            "rule_name": "KnownMalwareHash",
                            "pattern": hash_value,
                            "description": f"Known malware hash: {self.malware_hashes[hash_value]}",
                            "log_entry": entry.message,
                            "timestamp": entry.timestamp,
                            "source": entry.source,
                            "confidence": 0.9
                        })
        
        return matches
    
    def _scan_with_yara(self, log_entries: List[LogEntry]) -> List[Dict[str, Any]]:
        """Scan using compiled YARA rules."""
        matches = []
        
        try:
            # Combine all log messages for scanning
            combined_text = "\n".join([entry.message for entry in log_entries])
            
            # Run YARA scan
            yara_matches = self.compiled_rules.match(data=combined_text.encode('utf-8', errors='ignore'))
            
            for match in yara_matches:
                matches.append({
                    "rule_name": match.rule,
                    "pattern": match.rule,
                    "description": match.meta.get('description', 'YARA rule match'),
                    "strings": [str(string) for string in match.strings],
                    "confidence": 0.8,
                    "yara_match": True
                })
                
        except Exception as e:
            logger.error(f"Error in YARA rule scanning: {e}")
        
        return matches
    
    def _pattern_based_scanning(self, log_entries: List[LogEntry]) -> List[Dict[str, Any]]:
        """Fallback pattern-based scanning when YARA is not available."""
        matches = []
        
        # Define suspicious patterns
        suspicious_patterns = {
            "powershell_encoded": {
                "pattern": r"powershell.*(-enc|-encodedcommand)",
                "description": "Encoded PowerShell command execution",
                "confidence": 0.8
            },
            "suspicious_network": {
                "pattern": r"(curl|wget|nc|netcat).*(-e|/bin/sh|/bin/bash)",
                "description": "Suspicious network tool usage",
                "confidence": 0.7
            },
            "privilege_escalation": {
                "pattern": r"(sudo|su|runas).*-.*",
                "description": "Potential privilege escalation attempt",
                "confidence": 0.6
            },
            "file_execution": {
                "pattern": r"\.(exe|bat|ps1|sh|py).*executed",
                "description": "Executable file execution",
                "confidence": 0.5
            },
            "registry_modification": {
                "pattern": r"registry.*modified|reg.*add|regedit",
                "description": "Windows registry modification",
                "confidence": 0.6
            }
        }
        
        import re
        
        for entry in log_entries:
            message = entry.message.lower()
            
            for pattern_name, pattern_info in suspicious_patterns.items():
                if re.search(pattern_info["pattern"], message, re.IGNORECASE):
                    matches.append({
                        "rule_name": f"Pattern_{pattern_name}",
                        "pattern": pattern_name,
                        "description": pattern_info["description"],
                        "log_entry": entry.message,
                        "timestamp": entry.timestamp,
                        "source": entry.source,
                        "confidence": pattern_info["confidence"]
                    })
        
        return matches

class PCAPAnalyzer:
    """Network packet analysis using Scapy."""
    
    def __init__(self):
        self.scapy_available = rdpcap is not None
        if not self.scapy_available:
            logger.warning("Scapy not available, PCAP analysis disabled")
    
    def analyze_pcap(self, pcap_file: Union[str, Path]) -> Dict[str, Any]:
        """
        Analyze PCAP file for suspicious network activity.
        
        Args:
            pcap_file: Path to PCAP file
            
        Returns:
            Dictionary with analysis results
        """
        if not self.scapy_available:
            return {"error": "Scapy not available"}
        
        try:
            pcap_path = Path(pcap_file)
            if not pcap_path.exists():
                return {"error": f"PCAP file not found: {pcap_file}"}
            
            logger.info(f"Analyzing PCAP file: {pcap_file}")
            
            # Read PCAP file
            packets = rdpcap(str(pcap_path))
            
            # Analyze packets
            analysis = {
                "total_packets": len(packets),
                "protocols": {},
                "top_talkers": {},
                "suspicious_connections": [],
                "dns_queries": [],
                "file_transfers": []
            }
            
            # Process packets
            for packet in packets:
                self._analyze_packet(packet, analysis)
            
            # Generate summary
            analysis["summary"] = self._generate_pcap_summary(analysis)
            
            logger.info(f"PCAP analysis completed: {len(packets)} packets analyzed")
            return analysis
            
        except Exception as e:
            logger.error(f"Error analyzing PCAP {pcap_file}: {e}")
            return {"error": str(e)}
    
    def _analyze_packet(self, packet: Any, analysis: Dict[str, Any]):
        """Analyze individual packet."""
        try:
            # Protocol analysis
            if hasattr(packet, 'proto'):
                proto_name = packet.proto
                analysis["protocols"][proto_name] = analysis["protocols"].get(proto_name, 0) + 1
            
            # IP analysis
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                
                # Track top talkers
                analysis["top_talkers"][src_ip] = analysis["top_talkers"].get(src_ip, 0) + 1
                analysis["top_talkers"][dst_ip] = analysis["top_talkers"].get(dst_ip, 0) + 1
                
                # Check for suspicious connections
                if self._is_suspicious_connection(src_ip, dst_ip, packet):
                    analysis["suspicious_connections"].append({
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "timestamp": packet.time,
                        "reason": "Suspicious IP or port"
                    })
            
            # DNS analysis
            if packet.haslayer("DNS"):
                dns_layer = packet["DNS"]
                if hasattr(dns_layer, 'qd') and dns_layer.qd:
                    query_name = dns_layer.qd.qname.decode('utf-8', errors='ignore')
                    analysis["dns_queries"].append({
                        "query": query_name,
                        "timestamp": packet.time
                    })
            
            # File transfer detection (simplified)
            if TCP in packet:
                if packet[TCP].dport in [21, 22, 80, 443, 993, 995]:  # Common file transfer ports
                    if len(packet) > 1000:  # Large packet indicating file transfer
                        analysis["file_transfers"].append({
                            "src_ip": packet[IP].src if IP in packet else "unknown",
                            "dst_ip": packet[IP].dst if IP in packet else "unknown",
                            "port": packet[TCP].dport,
                            "size": len(packet),
                            "timestamp": packet.time
                        })
                        
        except Exception as e:
            logger.debug(f"Error analyzing packet: {e}")
    
    def _is_suspicious_connection(self, src_ip: str, dst_ip: str, packet: Any) -> bool:
        """Check if connection is suspicious."""
        try:
            # Check for private to public IP connections
            if self._is_private_ip(src_ip) and not self._is_private_ip(dst_ip):
                return True
            
            # Check for suspicious ports
            if TCP in packet:
                suspicious_ports = [4444, 5555, 6666, 1337, 31337]  # Common backdoor ports
                if packet[TCP].dport in suspicious_ports or packet[TCP].sport in suspicious_ports:
                    return True
            
            # Check for suspicious IP ranges (simplified)
            suspicious_ranges = ["10.0.0.", "169.254."]  # Example suspicious ranges
            for range_prefix in suspicious_ranges:
                if dst_ip.startswith(range_prefix):
                    return True
            
            return False
            
        except Exception:
            return False
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP address is private."""
        try:
            return (ip.startswith("192.168.") or 
                   ip.startswith("10.") or 
                   ip.startswith("172.16.") or 
                   ip.startswith("172.17.") or 
                   ip.startswith("172.18.") or 
                   ip.startswith("172.19.") or 
                   ip.startswith("172.2") or 
                   ip.startswith("172.30.") or 
                   ip.startswith("172.31."))
        except Exception:
            return False
    
    def _generate_pcap_summary(self, analysis: Dict[str, Any]) -> str:
        """Generate summary of PCAP analysis."""
        try:
            summary_parts = []
            
            summary_parts.append(f"Total packets analyzed: {analysis['total_packets']}")
            
            # Top protocols
            if analysis["protocols"]:
                top_protocols = sorted(analysis["protocols"].items(), key=lambda x: x[1], reverse=True)[:5]
                summary_parts.append(f"Top protocols: {', '.join([f'{p}({c})' for p, c in top_protocols])}")
            
            # Suspicious activity
            sus_count = len(analysis["suspicious_connections"])
            if sus_count > 0:
                summary_parts.append(f"Suspicious connections detected: {sus_count}")
            
            # DNS activity
            dns_count = len(analysis["dns_queries"])
            if dns_count > 0:
                summary_parts.append(f"DNS queries observed: {dns_count}")
            
            # File transfers
            transfer_count = len(analysis["file_transfers"])
            if transfer_count > 0:
                summary_parts.append(f"Potential file transfers: {transfer_count}")
            
            return ". ".join(summary_parts)
            
        except Exception as e:
            logger.error(f"Error generating PCAP summary: {e}")
            return "PCAP summary generation failed"

class HashCalculator:
    """Utility for calculating file hashes."""
    
    @staticmethod
    def calculate_hash(file_path: Union[str, Path], algorithm: str = "sha256") -> Optional[str]:
        """
        Calculate hash of a file.
        
        Args:
            file_path: Path to file
            algorithm: Hash algorithm (md5, sha1, sha256)
            
        Returns:
            Hash value as hex string or None on error
        """
        try:
            file_path = Path(file_path)
            if not file_path.exists():
                logger.error(f"File not found for hashing: {file_path}")
                return None
            
            # Select hash algorithm
            if algorithm.lower() == "md5":
                hasher = hashlib.md5()
            elif algorithm.lower() == "sha1":
                hasher = hashlib.sha1()
            elif algorithm.lower() == "sha256":
                hasher = hashlib.sha256()
            else:
                logger.error(f"Unsupported hash algorithm: {algorithm}")
                return None
            
            # Calculate hash
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hasher.update(chunk)
            
            hash_value = hasher.hexdigest()
            logger.debug(f"Calculated {algorithm} hash for {file_path}: {hash_value}")
            return hash_value
            
        except Exception as e:
            logger.error(f"Error calculating hash for {file_path}: {e}")
            return None
    
    @staticmethod
    def calculate_multiple_hashes(file_path: Union[str, Path]) -> Dict[str, Optional[str]]:
        """Calculate multiple hashes for a file."""
        return {
            "md5": HashCalculator.calculate_hash(file_path, "md5"),
            "sha1": HashCalculator.calculate_hash(file_path, "sha1"),
            "sha256": HashCalculator.calculate_hash(file_path, "sha256")
        }

class NetworkUtils:
    """Network-related utility functions."""
    
    @staticmethod
    def is_valid_ip(ip_string: str) -> bool:
        """Check if string is a valid IP address."""
        try:
            import ipaddress
            ipaddress.ip_address(ip_string)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def is_private_ip(ip_string: str) -> bool:
        """Check if IP address is in private range."""
        try:
            import ipaddress
            ip = ipaddress.ip_address(ip_string)
            return ip.is_private
        except ValueError:
            return False
    
    @staticmethod
    def extract_ips_from_text(text: str) -> List[str]:
        """Extract IP addresses from text using regex."""
        import re
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        potential_ips = re.findall(ip_pattern, text)
        
        # Validate extracted IPs
        valid_ips = []
        for ip in potential_ips:
            if NetworkUtils.is_valid_ip(ip):
                valid_ips.append(ip)
        
        return valid_ips
    
    @staticmethod
    def extract_domains_from_text(text: str) -> List[str]:
        """Extract domain names from text using regex."""
        import re
        # Simple domain pattern - in production use more sophisticated regex
        domain_pattern = r'\b[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+'
        domains = re.findall(domain_pattern, text)
        
        # Clean up the regex results
        clean_domains = []
        for match in domains:
            if isinstance(match, tuple):
                # Reconstruct domain from tuple match
                domain = text[text.find(match[0]):text.find(match[0]) + len(match[0]) + len(match[1]) + 1]
                clean_domains.append(domain)
            else:
                clean_domains.append(match)
        
        return clean_domains

class ForensicUtils:
    """General forensic analysis utilities."""
    
    @staticmethod
    def extract_timestamps(text: str) -> List[datetime]:
        """Extract timestamps from text."""
        import dateparser
        import re
        
        # Common timestamp patterns
        timestamp_patterns = [
            r'\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}',
            r'\d{2}/\d{2}/\d{4}\s\d{2}:\d{2}:\d{2}',
            r'\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}',
        ]
        
        timestamps = []
        for pattern in timestamp_patterns:
            matches = re.findall(pattern, text)
            for match in matches:
                parsed_time = dateparser.parse(match)
                if parsed_time:
                    timestamps.append(parsed_time)
        
        return timestamps
    
    @staticmethod
    def calculate_time_delta(start_time: datetime, end_time: datetime) -> Dict[str, Any]:
        """Calculate time difference between two timestamps."""
        try:
            delta = end_time - start_time
            return {
                "total_seconds": delta.total_seconds(),
                "days": delta.days,
                "hours": delta.seconds // 3600,
                "minutes": (delta.seconds % 3600) // 60,
                "seconds": delta.seconds % 60,
                "human_readable": str(delta)
            }
        except Exception as e:
            logger.error(f"Error calculating time delta: {e}")
            return {"error": str(e)}
    
    @staticmethod
    def entropy_analysis(text: str) -> float:
        """Calculate entropy of text (for detecting encoded/encrypted content)."""
        try:
            import math
            from collections import Counter
            
            if not text:
                return 0.0
            
            # Count character frequencies
            char_counts = Counter(text)
            text_length = len(text)
            
            # Calculate entropy
            entropy = 0.0
            for count in char_counts.values():
                probability = count / text_length
                entropy -= probability * math.log2(probability)
            
            return entropy
            
        except Exception as e:
            logger.error(f"Error calculating entropy: {e}")
            return 0.0
    
    @staticmethod
    def detect_base64(text: str) -> bool:
        """Detect if text contains base64 encoded content."""
        try:
            import base64
            import re
            
            # Look for base64-like patterns
            b64_pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
            matches = re.findall(b64_pattern, text)
            
            for match in matches:
                try:
                    # Try to decode - if successful, likely base64
                    decoded = base64.b64decode(match, validate=True)
                    if len(decoded) > 0:
                        return True
                except Exception:
                    continue
            
            return False
            
        except Exception as e:
            logger.debug(f"Error in base64 detection: {e}")
            return False