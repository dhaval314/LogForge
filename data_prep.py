"""
Data Preparation Kit - Log Ingestion & Parsing Module
"""
import json
import subprocess
import tempfile
import signal
import threading
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional, Union
import pandas as pd
import dateparser
from loguru import logger
try:
    from Evtx.Evtx import Evtx
    from Evtx.Views import evtx_file_xml_view
except ImportError:
    logger.warning("python-evtx not available, Windows Event Log parsing disabled")
    Evtx = None

from data_models import LogEntry, LogEntryType, SeverityLevel

def timeout_handler(signum, frame):
    """Handler for timeout signal."""
    raise TimeoutError("Operation timed out")

class LogParser:
    """
    Main log parsing class that handles multiple log formats.
    """
    
    def __init__(self, skip_evtx_files=False):
        self.supported_formats = ['.csv', '.json', '.evtx', '.log', '.txt']
        self.skip_evtx_files = skip_evtx_files
        
    def parse_logs(self, file_path: Union[str, Path]) -> List[LogEntry]:
        """
        Parse logs from various file formats.
        
        Args:
            file_path: Path to the log file
            
        Returns:
            List of standardized LogEntry objects
        """
        file_path = Path(file_path)
        
        if not file_path.exists():
            raise FileNotFoundError(f"Log file not found: {file_path}")
            
        logger.info(f"Parsing log file: {file_path}")
        
        try:
            if file_path.suffix.lower() == '.csv':
                return self._parse_csv(file_path)
            elif file_path.suffix.lower() == '.json':
                return self._parse_json(file_path)
            elif file_path.suffix.lower() == '.evtx':
                if self.skip_evtx_files:
                    logger.info(f"Skipping EVTX file {file_path} as configured")
                    return []
                return self._parse_evtx(file_path)
            else:
                return self._parse_generic_text(file_path)
                
        except Exception as e:
            logger.error(f"Error parsing {file_path}: {e}")
            raise
    
    def _parse_csv(self, file_path: Path) -> List[LogEntry]:
        """Parse CSV log files using pandas."""
        try:
            # Try different encoding options
            encodings = ['utf-8', 'latin-1', 'cp1252', 'iso-8859-1']
            df = None
            
            for encoding in encodings:
                try:
                    df = pd.read_csv(file_path, encoding=encoding, on_bad_lines='skip')
                    break
                except UnicodeDecodeError:
                    continue
                except Exception as e:
                    logger.debug(f"Failed to read CSV with {encoding} encoding: {e}")
                    continue
            
            if df is None:
                logger.error(f"Could not read CSV file {file_path} with any encoding")
                return []
            
            # Handle empty DataFrames
            if df.empty:
                logger.warning(f"CSV file {file_path} is empty")
                return []
            
            # Handle DataFrames with no columns
            if len(df.columns) == 0:
                logger.warning(f"CSV file {file_path} has no columns")
                return []
            
            logger.info(f"Loaded {len(df)} entries from CSV: {file_path}")
            
            entries = []
            for _, row in df.iterrows():
                try:
                    # Try to identify timestamp column
                    timestamp_col = self._identify_timestamp_column(df.columns)
                    timestamp_value = row.get(timestamp_col, '') if timestamp_col in row else ''
                    timestamp = self._normalize_timestamp(timestamp_value)
                    
                    # Extract message content
                    message_col = self._identify_message_column(df.columns)
                    message_value = row.get(message_col, '') if message_col in row else str(row.to_dict())
                    message = str(message_value)
                    
                    entry = LogEntry(
                        timestamp=timestamp or datetime.now(),
                        source=str(file_path.name),
                        event_type=LogEntryType.GENERIC,
                        message=message,
                        raw_data=row.to_dict(),
                        severity=self._infer_severity(message)
                    )
                    entries.append(entry)
                    
                except Exception as row_error:
                    logger.debug(f"Error processing row in {file_path}: {row_error}")
                    continue
                
            return entries
            
        except Exception as e:
            logger.error(f"Error parsing CSV {file_path}: {e}")
            return []
    
    def _parse_json(self, file_path: Path) -> List[LogEntry]:
        """Parse JSON log files with multiple encoding support."""
        # Try different encodings
        encodings = ['utf-8', 'utf-8-sig', 'latin-1', 'cp1252', 'iso-8859-1']
        
        for encoding in encodings:
            try:
                with open(file_path, 'r', encoding=encoding) as f:
                    data = json.load(f)
                
                if isinstance(data, dict):
                    data = [data]  # Single entry
                elif not isinstance(data, list):
                    logger.error(f"Unexpected JSON structure in {file_path}")
                    return []
                    
                logger.info(f"Loaded {len(data)} entries from JSON: {file_path} (encoding: {encoding})")
                
                entries = []
                for item in data:
                    # Extract timestamp
                    timestamp_value = (item.get('timestamp') or 
                                     item.get('time') or 
                                     item.get('@timestamp') or 
                                     item.get('datetime') or 
                                     datetime.now().isoformat())
                    
                    timestamp = self._normalize_timestamp(timestamp_value)
                    
                    # Extract message
                    message = (item.get('message') or 
                              item.get('msg') or 
                              item.get('description') or 
                              json.dumps(item))
                    
                    entry = LogEntry(
                        timestamp=timestamp or datetime.now(),
                        source=str(file_path.name),
                        event_type=self._classify_log_type(item),
                        event_id=item.get('event_id') or item.get('id'),
                        message=message,
                        raw_data=item,
                        severity=self._infer_severity(message)
                    )
                    entries.append(entry)
                    
                return entries
                
            except UnicodeDecodeError:
                logger.debug(f"Failed to decode {file_path} with {encoding} encoding, trying next...")
                continue
            except json.JSONDecodeError as e:
                logger.debug(f"Failed to parse JSON in {file_path} with {encoding} encoding: {e}")
                continue
            except Exception as e:
                logger.debug(f"Unexpected error parsing {file_path} with {encoding} encoding: {e}")
                continue
        
        # If all encodings fail, check if it's a binary file
        try:
            with open(file_path, 'rb') as f:
                first_bytes = f.read(4)
                if first_bytes.startswith(b'\xff\xfe') or first_bytes.startswith(b'\xfe\xff'):
                    logger.warning(f"File {file_path} appears to be a binary file (UTF-16 BOM detected), skipping")
                elif first_bytes.startswith(b'\xef\xbb\xbf'):
                    logger.warning(f"File {file_path} has UTF-8 BOM but failed to parse, skipping")
                else:
                    logger.warning(f"File {file_path} appears to be binary or corrupted, skipping")
        except Exception:
            logger.warning(f"Could not read file {file_path} to determine encoding")
        
        logger.error(f"Failed to parse JSON {file_path} with all attempted encodings")
        return []
    
    def _parse_evtx(self, file_path: Path) -> List[LogEntry]:
        """Parse Windows Event Log files (.evtx)."""
        if not Evtx:
            logger.error("python-evtx not available")
            return []
            
        try:
            # Check file size to avoid processing extremely large files
            file_size = file_path.stat().st_size
            if file_size > 500 * 1024 * 1024:  # 500MB limit
                logger.warning(f"EVTX file {file_path} is too large ({file_size / (1024*1024):.1f} MB), skipping")
                return []
            
            entries = []
            record_count = 0
            max_records = 5000  # Reduced limit to prevent hanging
            
            logger.info(f"Starting EVTX parsing for {file_path} (size: {file_size / (1024*1024):.1f} MB)")
            
            # Use a timeout to prevent hanging
            timeout_seconds = 300  # 5 minutes timeout
            
            def parse_evtx_with_timeout():
                nonlocal entries, record_count
                try:
                    with Evtx(str(file_path)) as log:
                        for record in log.records():
                            try:
                                record_count += 1
                                
                                # Limit the number of records to prevent hanging
                                if record_count > max_records:
                                    logger.warning(f"Reached maximum record limit ({max_records}) for {file_path}")
                                    break
                                
                                xml_data = record.xml()
                                # Parse key fields from Windows Event Log
                                event_data = self._parse_windows_event_xml(xml_data)
                                
                                entry = LogEntry(
                                    timestamp=event_data.get('timestamp') or datetime.now(),
                                    source=f"Windows Event Log: {file_path.name}",
                                    event_type=LogEntryType.WINDOWS_EVENT,
                                    event_id=event_data.get('event_id'),
                                    message=event_data.get('message', ''),
                                    raw_data=event_data,
                                    severity=self._map_windows_severity(event_data.get('level', ''))
                                )
                                entries.append(entry)
                                
                                # Log progress every 500 records
                                if record_count % 500 == 0:
                                    logger.info(f"Processed {record_count} records from {file_path}")
                                
                            except Exception as e:
                                logger.debug(f"Skipping malformed record {record_count} in {file_path}: {e}")
                                continue
                                
                except Exception as e:
                    logger.error(f"Error in EVTX parsing thread: {e}")
            
            # Run parsing in a separate thread with timeout
            parsing_thread = threading.Thread(target=parse_evtx_with_timeout)
            parsing_thread.daemon = True
            parsing_thread.start()
            
            # Wait for the thread to complete with timeout
            parsing_thread.join(timeout=timeout_seconds)
            
            if parsing_thread.is_alive():
                logger.warning(f"EVTX parsing timed out after {timeout_seconds} seconds for {file_path}")
                return entries  # Return what we have so far
            
            logger.info(f"Parsed {len(entries)} Windows Event Log entries from {file_path} (processed {record_count} records)")
            return entries
            
        except Exception as e:
            logger.error(f"Error parsing EVTX {file_path}: {e}")
            return []
    
    def _parse_generic_text(self, file_path: Path) -> List[LogEntry]:
        """Parse generic text log files."""
        try:
            entries = []
            
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    
                    # Try to extract timestamp from line
                    timestamp = self._extract_timestamp_from_line(line)
                    
                    entry = LogEntry(
                        timestamp=timestamp or datetime.now(),
                        source=f"{file_path.name}:L{line_num}",
                        event_type=LogEntryType.GENERIC,
                        message=line,
                        raw_data={'line_number': line_num, 'raw_line': line},
                        severity=self._infer_severity(line)
                    )
                    entries.append(entry)
            
            logger.info(f"Parsed {len(entries)} lines from text file: {file_path}")
            return entries
            
        except Exception as e:
            logger.error(f"Error parsing text file {file_path}: {e}")
            return []
    
    def _normalize_timestamp(self, timestamp_str: Any) -> Optional[datetime]:
        """Normalize timestamp to ISO format using dateparser."""
        if not timestamp_str:
            return None
            
        try:
            # Handle various timestamp formats
            if isinstance(timestamp_str, (int, float)):
                return datetime.fromtimestamp(timestamp_str)
            
            parsed = dateparser.parse(str(timestamp_str))
            if parsed:
                logger.debug(f"Normalized timestamp: {timestamp_str} -> {parsed}")
                return parsed
                
        except Exception as e:
            logger.debug(f"Could not parse timestamp '{timestamp_str}': {e}")
            
        return None
    
    def _identify_timestamp_column(self, columns) -> str:
        """Identify the most likely timestamp column."""
        timestamp_candidates = ['timestamp', 'time', 'datetime', 'date', 'created_at', '@timestamp']
        
        # Convert pandas Index to list for proper comparison
        columns_list = list(columns) if hasattr(columns, '__iter__') else []
        
        # Check if columns list is empty
        if not columns_list:
            return 'timestamp'
        
        for candidate in timestamp_candidates:
            if candidate in columns_list:
                return candidate
        
        # Fallback to first column
        return columns_list[0]
    
    def _identify_message_column(self, columns) -> str:
        """Identify the most likely message column."""
        message_candidates = ['message', 'msg', 'description', 'text', 'content', 'log']
        
        # Convert pandas Index to list for proper comparison
        columns_list = list(columns) if hasattr(columns, '__iter__') else []
        
        # Check if columns list is empty
        if not columns_list:
            return 'message'
        
        for candidate in message_candidates:
            if candidate in columns_list:
                return candidate
        
        # Return a column that's not the timestamp
        timestamp_col = self._identify_timestamp_column(columns)
        for col in columns_list:
            if col != timestamp_col:
                return col
        
        return columns_list[-1]
    
    def _classify_log_type(self, log_entry: Dict[str, Any]) -> LogEntryType:
        """Classify the type of log entry based on its content."""
        entry_str = json.dumps(log_entry).lower()
        
        if any(term in entry_str for term in ['event_id', 'eventid', 'windows']):
            return LogEntryType.WINDOWS_EVENT
        elif any(term in entry_str for term in ['syslog', 'rsyslog']):
            return LogEntryType.SYSLOG
        elif any(term in entry_str for term in ['access', 'request', 'response', 'http']):
            return LogEntryType.ACCESS_LOG
        elif any(term in entry_str for term in ['firewall', 'iptables', 'deny', 'allow']):
            return LogEntryType.FIREWALL
        elif any(term in entry_str for term in ['dns', 'query', 'resolve']):
            return LogEntryType.DNS
        else:
            return LogEntryType.GENERIC
    
    def _infer_severity(self, message: str) -> SeverityLevel:
        """Infer severity level from message content."""
        message_lower = message.lower()
        
        if any(term in message_lower for term in ['critical', 'fatal', 'emergency']):
            return SeverityLevel.CRITICAL
        elif any(term in message_lower for term in ['error', 'failed', 'failure', 'denied']):
            return SeverityLevel.HIGH
        elif any(term in message_lower for term in ['warning', 'warn', 'suspicious']):
            return SeverityLevel.MEDIUM
        elif any(term in message_lower for term in ['notice', 'info']):
            return SeverityLevel.LOW
        else:
            return SeverityLevel.INFO
    
    def _map_windows_severity(self, level: str) -> SeverityLevel:
        """Map Windows Event Log levels to severity."""
        level_mapping = {
            '1': SeverityLevel.CRITICAL,  # Critical
            '2': SeverityLevel.HIGH,      # Error
            '3': SeverityLevel.MEDIUM,    # Warning
            '4': SeverityLevel.INFO,      # Information
            '5': SeverityLevel.LOW        # Verbose
        }
        return level_mapping.get(str(level), SeverityLevel.INFO)
    
    def _parse_windows_event_xml(self, xml_data: str) -> Dict[str, Any]:
        """Parse Windows Event Log XML data."""
        # Simplified XML parsing - in production, use proper XML parser
        import re
        
        event_data = {}
        
        # Extract Event ID
        event_id_match = re.search(r'<EventID[^>]*>(\d+)</EventID>', xml_data)
        if event_id_match:
            event_data['event_id'] = event_id_match.group(1)
        
        # Extract Level
        level_match = re.search(r'<Level>(\d+)</Level>', xml_data)
        if level_match:
            event_data['level'] = level_match.group(1)
        
        # Extract TimeCreated
        time_match = re.search(r'SystemTime="([^"]+)"', xml_data)
        if time_match:
            event_data['timestamp'] = self._normalize_timestamp(time_match.group(1))
        
        # Extract Provider
        provider_match = re.search(r'<Provider[^>]*Name="([^"]+)"', xml_data)
        if provider_match:
            event_data['provider'] = provider_match.group(1)
        
        # Use XML as message for now
        event_data['message'] = xml_data[:500] + '...' if len(xml_data) > 500 else xml_data
        
        return event_data
    
    def _extract_timestamp_from_line(self, line: str) -> Optional[datetime]:
        """Extract timestamp from a log line."""
        # Common log timestamp patterns
        timestamp_patterns = [
            r'\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}',  # ISO format
            r'\d{2}/\d{2}/\d{4}\s\d{2}:\d{2}:\d{2}',      # MM/DD/YYYY format
            r'\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}',       # syslog format
        ]
        
        import re
        for pattern in timestamp_patterns:
            match = re.search(pattern, line)
            if match:
                return self._normalize_timestamp(match.group())
        
        return None

class TimelineCreator:
    """Create unified timeline from parsed logs using log2timeline (plaso)."""
    
    @staticmethod
    def create_timeline(log_directory: Path, output_file: Path = None) -> List[Dict[str, Any]]:
        """
        Create a timeline using log2timeline.py (placeholder implementation).
        
        Args:
            log_directory: Directory containing log files
            output_file: Output file for timeline
            
        Returns:
            List of timeline events
        """
        logger.info(f"Creating timeline for directory: {log_directory}")
        
        # Placeholder implementation - in production, execute actual log2timeline
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as tmp:
                timeline_file = Path(tmp.name)
            
            # Simulate log2timeline execution
            # In production: subprocess.run(['log2timeline.py', ...])
            logger.warning("log2timeline integration not implemented - using placeholder")
            
            # Return placeholder timeline
            return [
                {
                    'timestamp': datetime.now().isoformat(),
                    'source': 'placeholder',
                    'description': 'Timeline creation placeholder',
                    'parser': 'forensic_analyzer'
                }
            ]
            
        except Exception as e:
            logger.error(f"Error creating timeline: {e}")
            return []