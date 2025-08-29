"""
Results Storage Module for LogForge - Handles persistent storage of forensic analysis results.
"""

import os
import json
import sqlite3
import tempfile
import shutil
from pathlib import Path
from typing import List, Dict, Any, Optional, Union
from datetime import datetime
from loguru import logger
from dataclasses import asdict, is_dataclass

class ResultsStorage:
    """Handles persistent storage of forensic analysis results."""
    
    def __init__(self, db_path: str = "forensic_results.db"):
        """
        Initialize the results storage system.
        
        Args:
            db_path: Path to the SQLite database file
        """
        self.db_path = db_path
        self._init_database()
    
    def _init_database(self):
        """Initialize the database with required tables."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Create analysis results table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS analysis_results (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        case_id TEXT NOT NULL,
                        case_name TEXT,
                        analysis_date TEXT NOT NULL,
                        file_count INTEGER DEFAULT 0,
                        log_entries_count INTEGER DEFAULT 0,
                        severity TEXT,
                        confidence REAL,
                        executive_summary TEXT,
                        iocs_count INTEGER DEFAULT 0,
                        mitre_mappings_count INTEGER DEFAULT 0,
                        recommendations_count INTEGER DEFAULT 0,
                        file_paths TEXT,  -- JSON array of original file paths
                        zip_file_path TEXT,  -- Path to uploaded ZIP if any
                        analysis_config TEXT,  -- JSON of analysis configuration
                        status TEXT DEFAULT 'completed',
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    )
                """)
                
                # Create detailed results table for storing full analysis data
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS detailed_results (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        analysis_id INTEGER NOT NULL,
                        result_type TEXT NOT NULL,  -- 'iocs', 'mitre', 'timeline', 'recommendations'
                        result_data TEXT NOT NULL,  -- JSON data
                        created_at TEXT NOT NULL,
                        FOREIGN KEY (analysis_id) REFERENCES analysis_results (id) ON DELETE CASCADE
                    )
                """)
                
                # Create file storage table for uploaded files
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS stored_files (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        analysis_id INTEGER NOT NULL,
                        original_name TEXT NOT NULL,
                        file_type TEXT,
                        file_category TEXT,
                        file_size INTEGER,
                        stored_path TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        FOREIGN KEY (analysis_id) REFERENCES analysis_results (id) ON DELETE CASCADE
                    )
                """)
                
                # Create indexes for better performance
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_case_id ON analysis_results(case_id)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_analysis_date ON analysis_results(analysis_date)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_analysis_id ON detailed_results(analysis_id)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_result_type ON detailed_results(result_type)")
                
                conn.commit()
                logger.info(f"Database initialized: {self.db_path}")
                
        except Exception as e:
            logger.error(f"Failed to initialize database: {e}")
            raise
    
    def save_analysis_result(self, 
                           case_id: str,
                           case_name: str,
                           analysis_result: Any,
                           file_paths: List[str],
                           zip_file_path: Optional[str] = None,
                           analysis_config: Optional[Dict] = None) -> int:
        """
        Save a complete analysis result to the database.
        
        Args:
            case_id: Unique case identifier
            case_name: Human-readable case name
            analysis_result: The forensic analysis result object
            file_paths: List of original file paths analyzed
            zip_file_path: Path to uploaded ZIP file if any
            analysis_config: Analysis configuration used
            
        Returns:
            Analysis ID of the saved result
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Extract basic information from analysis result
                executive_summary = getattr(analysis_result, 'executive_summary', 'No summary available')
                total_events = getattr(analysis_result, 'total_events', 0)
                
                # Extract severity and confidence from analysis
                severity = "unknown"
                confidence = 0.0
                if hasattr(analysis_result, 'analysis') and analysis_result.analysis:
                    if hasattr(analysis_result.analysis, 'initial_analysis') and analysis_result.analysis.initial_analysis:
                        severity = getattr(analysis_result.analysis.initial_analysis, 'severity', 'unknown')
                        if hasattr(severity, 'value'):
                            severity = severity.value
                        confidence = getattr(analysis_result.analysis.initial_analysis, 'confidence', 0.0)
                
                # Count IOCs and MITRE mappings
                iocs_count = 0
                mitre_count = 0
                recommendations_count = 0
                
                if hasattr(analysis_result, 'analysis') and analysis_result.analysis:
                    if hasattr(analysis_result.analysis, 'initial_analysis') and analysis_result.analysis.initial_analysis:
                        iocs = getattr(analysis_result.analysis.initial_analysis, 'iocs', [])
                        iocs_count = len(iocs) if iocs else 0
                        
                        mitre = getattr(analysis_result.analysis.initial_analysis, 'mitre_mappings', [])
                        mitre_count = len(mitre) if mitre else 0
                    
                    recommendations = getattr(analysis_result.analysis, 'recommendations', [])
                    recommendations_count = len(recommendations) if recommendations else 0
                
                # Insert main analysis record
                now = datetime.now().isoformat()
                cursor.execute("""
                    INSERT INTO analysis_results (
                        case_id, case_name, analysis_date, file_count, log_entries_count,
                        severity, confidence, executive_summary, iocs_count, mitre_mappings_count,
                        recommendations_count, file_paths, zip_file_path, analysis_config,
                        created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    case_id, case_name, now, len(file_paths), total_events,
                    severity, confidence, executive_summary, iocs_count, mitre_count,
                    recommendations_count, json.dumps(file_paths), zip_file_path,
                    json.dumps(analysis_config) if analysis_config else None,
                    now, now
                ))
                
                analysis_id = cursor.lastrowid
                
                # Store detailed results
                self._store_detailed_results(cursor, analysis_id, analysis_result)
                
                # Store file information
                self._store_file_info(cursor, analysis_id, file_paths, zip_file_path)
                
                conn.commit()
                logger.info(f"Saved analysis result with ID: {analysis_id}")
                return analysis_id
                
        except Exception as e:
            logger.error(f"Failed to save analysis result: {e}")
            raise
    
    def _store_detailed_results(self, cursor, analysis_id: int, analysis_result: Any):
        """Store detailed analysis results in separate table."""
        now = datetime.now().isoformat()
        
        # Store IOCs
        if hasattr(analysis_result, 'analysis') and analysis_result.analysis:
            if hasattr(analysis_result.analysis, 'initial_analysis') and analysis_result.analysis.initial_analysis:
                iocs = getattr(analysis_result.analysis.initial_analysis, 'iocs', [])
                if iocs:
                    ioc_data = [self._safe_to_dict(ioc) for ioc in iocs]
                    cursor.execute("""
                        INSERT INTO detailed_results (analysis_id, result_type, result_data, created_at)
                        VALUES (?, ?, ?, ?)
                    """, (analysis_id, 'iocs', json.dumps(ioc_data), now))
                
                # Store MITRE mappings
                mitre = getattr(analysis_result.analysis.initial_analysis, 'mitre_mappings', [])
                if mitre:
                    mitre_data = [self._safe_to_dict(mapping) for mapping in mitre]
                    cursor.execute("""
                        INSERT INTO detailed_results (analysis_id, result_type, result_data, created_at)
                        VALUES (?, ?, ?, ?)
                    """, (analysis_id, 'mitre', json.dumps(mitre_data), now))
            
            # Store recommendations
            recommendations = getattr(analysis_result.analysis, 'recommendations', [])
            if recommendations:
                rec_data = [str(rec) for rec in recommendations]
                cursor.execute("""
                    INSERT INTO detailed_results (analysis_id, result_type, result_data, created_at)
                    VALUES (?, ?, ?, ?)
                """, (analysis_id, 'recommendations', json.dumps(rec_data), now))
        
        # Store timeline
        timeline = getattr(analysis_result, 'timeline', [])
        if timeline:
            timeline_data = [self._safe_to_dict(event) for event in timeline]
            cursor.execute("""
                INSERT INTO detailed_results (analysis_id, result_type, result_data, created_at)
                VALUES (?, ?, ?, ?)
            """, (analysis_id, 'timeline', json.dumps(timeline_data), now))
        
        # Store full analysis result
        full_result = self._safe_to_dict(analysis_result)
        cursor.execute("""
            INSERT INTO detailed_results (analysis_id, result_type, result_data, created_at)
            VALUES (?, ?, ?, ?)
        """, (analysis_id, 'full_result', json.dumps(full_result), now))
    
    def _store_file_info(self, cursor, analysis_id: int, file_paths: List[str], zip_file_path: Optional[str]):
        """Store information about analyzed files."""
        now = datetime.now().isoformat()
        
        for file_path in file_paths:
            if os.path.exists(file_path):
                file_name = os.path.basename(file_path)
                file_size = os.path.getsize(file_path)
                
                # Determine file type and category
                file_ext = Path(file_path).suffix.lower()
                file_type = file_ext if file_ext else "unknown"
                
                # Try to categorize the file
                try:
                    from zip_processor import LogFileCategorizer
                    category = LogFileCategorizer.categorize_file(file_name)
                except:
                    category = "general"
                
                cursor.execute("""
                    INSERT INTO stored_files (analysis_id, original_name, file_type, file_category, file_size, stored_path, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (analysis_id, file_name, file_type, category, file_size, file_path, now))
    
    def get_all_analyses(self, limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
        """
        Get all saved analyses with pagination.
        
        Args:
            limit: Maximum number of results to return
            offset: Number of results to skip
            
        Returns:
            List of analysis summaries
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                cursor.execute("""
                    SELECT * FROM analysis_results 
                    ORDER BY created_at DESC 
                    LIMIT ? OFFSET ?
                """, (limit, offset))
                
                results = []
                for row in cursor.fetchall():
                    result = dict(row)
                    # Parse JSON fields
                    if result['file_paths']:
                        result['file_paths'] = json.loads(result['file_paths'])
                    if result['analysis_config']:
                        result['analysis_config'] = json.loads(result['analysis_config'])
                    
                    results.append(result)
                
                return results
                
        except Exception as e:
            logger.error(f"Failed to get analyses: {e}")
            return []
    
    def get_analysis_by_id(self, analysis_id: int) -> Optional[Dict[str, Any]]:
        """
        Get a specific analysis by ID.
        
        Args:
            analysis_id: The analysis ID to retrieve
            
        Returns:
            Complete analysis data or None if not found
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                # Get main analysis record
                cursor.execute("SELECT * FROM analysis_results WHERE id = ?", (analysis_id,))
                row = cursor.fetchone()
                
                if not row:
                    return None
                
                analysis = dict(row)
                
                # Parse JSON fields
                if analysis['file_paths']:
                    analysis['file_paths'] = json.loads(analysis['file_paths'])
                if analysis['analysis_config']:
                    analysis['analysis_config'] = json.loads(analysis['analysis_config'])
                
                # Get detailed results
                cursor.execute("SELECT * FROM detailed_results WHERE analysis_id = ?", (analysis_id,))
                detailed_results = {}
                for row in cursor.fetchall():
                    result_type = row['result_type']
                    result_data = json.loads(row['result_data'])
                    detailed_results[result_type] = result_data
                
                analysis['detailed_results'] = detailed_results
                
                # Get file information
                cursor.execute("SELECT * FROM stored_files WHERE analysis_id = ?", (analysis_id,))
                files = [dict(row) for row in cursor.fetchall()]
                analysis['files'] = files
                
                return analysis
                
        except Exception as e:
            logger.error(f"Failed to get analysis {analysis_id}: {e}")
            return None
    
    def search_analyses(self, query: str, limit: int = 20) -> List[Dict[str, Any]]:
        """
        Search analyses by case ID, case name, or content.
        
        Args:
            query: Search query
            limit: Maximum number of results
            
        Returns:
            List of matching analyses
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                cursor.execute("""
                    SELECT * FROM analysis_results 
                    WHERE case_id LIKE ? OR case_name LIKE ? OR executive_summary LIKE ?
                    ORDER BY created_at DESC 
                    LIMIT ?
                """, (f"%{query}%", f"%{query}%", f"%{query}%", limit))
                
                results = []
                for row in cursor.fetchall():
                    result = dict(row)
                    if result['file_paths']:
                        result['file_paths'] = json.loads(result['file_paths'])
                    if result['analysis_config']:
                        result['analysis_config'] = json.loads(result['analysis_config'])
                    
                    results.append(result)
                
                return results
                
        except Exception as e:
            logger.error(f"Failed to search analyses: {e}")
            return []
    
    def delete_analysis(self, analysis_id: int) -> bool:
        """
        Delete an analysis and all its associated data.
        
        Args:
            analysis_id: The analysis ID to delete
            
        Returns:
            True if successful, False otherwise
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Delete the analysis (cascading will handle related records)
                cursor.execute("DELETE FROM analysis_results WHERE id = ?", (analysis_id,))
                
                if cursor.rowcount > 0:
                    conn.commit()
                    logger.info(f"Deleted analysis {analysis_id}")
                    return True
                else:
                    logger.warning(f"Analysis {analysis_id} not found for deletion")
                    return False
                    
        except Exception as e:
            logger.error(f"Failed to delete analysis {analysis_id}: {e}")
            return False
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get overall statistics about stored analyses.
        
        Returns:
            Dictionary with statistics
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Total analyses
                cursor.execute("SELECT COUNT(*) FROM analysis_results")
                total_analyses = cursor.fetchone()[0]
                
                # Recent analyses (last 30 days)
                cursor.execute("""
                    SELECT COUNT(*) FROM analysis_results 
                    WHERE created_at >= date('now', '-30 days')
                """)
                recent_analyses = cursor.fetchone()[0]
                
                # Total files analyzed
                cursor.execute("SELECT COUNT(*) FROM stored_files")
                total_files = cursor.fetchone()[0]
                
                # Total IOCs found
                cursor.execute("SELECT SUM(iocs_count) FROM analysis_results")
                total_iocs = cursor.fetchone()[0] or 0
                
                # Total MITRE mappings
                cursor.execute("SELECT SUM(mitre_mappings_count) FROM analysis_results")
                total_mitre = cursor.fetchone()[0] or 0
                
                # Average confidence
                cursor.execute("SELECT AVG(confidence) FROM analysis_results WHERE confidence > 0")
                avg_confidence = cursor.fetchone()[0] or 0.0
                
                # Severity distribution
                cursor.execute("""
                    SELECT severity, COUNT(*) FROM analysis_results 
                    GROUP BY severity
                """)
                severity_dist = dict(cursor.fetchall())
                
                return {
                    'total_analyses': total_analyses,
                    'recent_analyses': recent_analyses,
                    'total_files': total_files,
                    'total_iocs': total_iocs,
                    'total_mitre_mappings': total_mitre,
                    'average_confidence': round(avg_confidence, 2),
                    'severity_distribution': severity_dist
                }
                
        except Exception as e:
            logger.error(f"Failed to get statistics: {e}")
            return {}
    
    def _safe_to_dict(self, obj: Any) -> Any:
        """Safely convert objects to dictionaries for JSON serialization."""
        try:
            # Handle datetime objects specifically
            if isinstance(obj, datetime):
                return obj.isoformat()
            if is_dataclass(obj):
                return asdict(obj)
            if hasattr(obj, "model_dump"):
                # For Pydantic models, we need to recursively process the result
                # and ensure datetime objects are converted
                dumped = obj.model_dump()
                # Process the dumped result to convert any datetime objects
                return self._process_dict_for_json(dumped)
            if hasattr(obj, "dict") and callable(getattr(obj, "dict")):
                return obj.dict()
            if isinstance(obj, (list, tuple)):
                return [self._safe_to_dict(x) for x in obj]
            if isinstance(obj, dict):
                return self._process_dict_for_json(obj)
            # Handle custom objects with attributes
            if hasattr(obj, '__dict__'):
                return {k: self._safe_to_dict(v) for k, v in obj.__dict__.items()}
            return str(obj)
        except Exception:
            return str(obj)
    
    def _process_dict_for_json(self, obj: Any) -> Any:
        """Process objects to ensure they are JSON serializable."""
        if isinstance(obj, datetime):
            return obj.isoformat()
        elif isinstance(obj, (list, tuple)):
            return [self._process_dict_for_json(x) for x in obj]
        elif isinstance(obj, dict):
            return {k: self._process_dict_for_json(v) for k, v in obj.items()}
        else:
            return obj

# Global instance for easy access
_results_storage = None

def get_results_storage() -> ResultsStorage:
    """Get the global results storage instance."""
    global _results_storage
    if _results_storage is None:
        _results_storage = ResultsStorage()
    return _results_storage
