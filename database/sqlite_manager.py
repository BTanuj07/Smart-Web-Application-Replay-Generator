"""
SQLite Database Manager - Alternative to PostgreSQL
Provides the same functionality as db_manager.py but uses SQLite for easier setup.
No external database server required.
"""

import sqlite3
import json
import os
from typing import List, Dict, Optional, Any
from datetime import datetime, timedelta

class SQLiteDatabaseManager:
    def __init__(self, db_path: str = "attack_replay.db"):
        self.db_path = db_path
        self.db_available = True
        self._create_tables()
    
    def get_connection(self):
        """Get SQLite database connection."""
        return sqlite3.connect(self.db_path)
    
    def _create_tables(self):
        """Create required tables if they don't exist."""
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            
            # Analysis History Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS analysis_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    filename TEXT NOT NULL,
                    total_lines INTEGER NOT NULL DEFAULT 0,
                    total_attacks INTEGER NOT NULL DEFAULT 0,
                    unique_ips INTEGER NOT NULL DEFAULT 0,
                    attack_breakdown TEXT,
                    attacks_data TEXT,
                    analyzed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # AI Threat Analysis Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS ai_threat_analysis (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    pattern_signature TEXT NOT NULL UNIQUE,
                    threat_level TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    attack_type TEXT,
                    reasoning TEXT,
                    indicators TEXT,
                    severity TEXT,
                    ai_provider TEXT,
                    occurrence_count INTEGER DEFAULT 1,
                    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    upgrade_reason TEXT,
                    sample_log_entry TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Custom Patterns Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS custom_patterns (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    attack_type TEXT NOT NULL,
                    pattern_regex TEXT NOT NULL,
                    description TEXT,
                    is_active BOOLEAN DEFAULT 1,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Unknown Attacks Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS unknown_attacks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    url TEXT NOT NULL,
                    ip TEXT NOT NULL,
                    timestamp TEXT,
                    method TEXT,
                    user_agent TEXT,
                    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    frequency INTEGER DEFAULT 1,
                    UNIQUE(url, ip)
                )
            """)
            
            # Create indexes
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_analysis_history_analyzed_at ON analysis_history(analyzed_at)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_analysis_history_filename ON analysis_history(filename)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_custom_patterns_active ON custom_patterns(is_active)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_custom_patterns_attack_type ON custom_patterns(attack_type)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_ai_threat_analysis_pattern ON ai_threat_analysis(pattern_signature)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_ai_threat_analysis_threat_level ON ai_threat_analysis(threat_level)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_ai_threat_analysis_last_seen ON ai_threat_analysis(last_seen)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_unknown_attacks_frequency ON unknown_attacks(frequency)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_unknown_attacks_detected_at ON unknown_attacks(detected_at)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_unknown_attacks_ip ON unknown_attacks(ip)")
            
            # Insert sample custom patterns if table is empty
            cursor.execute("SELECT COUNT(*) FROM custom_patterns")
            if cursor.fetchone()[0] == 0:
                sample_patterns = [
                    ('Custom SQL Injection', r'(sleep\s*\(\s*\d+\s*\)|benchmark\s*\()', 'Time-based SQL injection patterns'),
                    ('Custom XSS', r'(fromCharCode|unescape|decodeURI)', 'Encoded XSS patterns'),
                    ('Custom Command Injection', r'(whoami|id\s|pwd\s)', 'System information gathering commands')
                ]
                
                cursor.executemany("""
                    INSERT INTO custom_patterns (attack_type, pattern_regex, description)
                    VALUES (?, ?, ?)
                """, sample_patterns)
            
            conn.commit()
        finally:
            conn.close()
    
    def save_analysis(self, filename: str, total_lines: int, total_attacks: int, 
                     unique_ips: int, attack_breakdown: Dict, attacks_data: List[Dict]) -> int:
        """Save analysis results to database."""
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO analysis_history 
                (filename, total_lines, total_attacks, unique_ips, attack_breakdown, attacks_data)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (filename, total_lines, total_attacks, unique_ips, 
                  json.dumps(attack_breakdown), json.dumps(attacks_data)))
            
            analysis_id = cursor.lastrowid
            conn.commit()
            return analysis_id
        finally:
            conn.close()
    
    def get_analysis_by_id(self, analysis_id: int) -> Dict:
        """Get specific analysis with full attack data."""
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, filename, total_lines, total_attacks, unique_ips, 
                       attack_breakdown, attacks_data, analyzed_at
                FROM analysis_history
                WHERE id = ?
            """, (analysis_id,))
            
            row = cursor.fetchone()
            if row:
                return {
                    'id': row[0],
                    'filename': row[1],
                    'total_lines': row[2],
                    'total_attacks': row[3],
                    'unique_ips': row[4],
                    'attack_breakdown': json.loads(row[5]) if row[5] else {},
                    'attacks_data': json.loads(row[6]) if row[6] else [],
                    'analyzed_at': row[7]
                }
            return None
        finally:
            conn.close()
    
    def get_analysis_history(self, limit: int = 50) -> List[Dict]:
        """Get analysis history."""
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, filename, total_lines, total_attacks, unique_ips, 
                       attack_breakdown, analyzed_at
                FROM analysis_history
                ORDER BY analyzed_at DESC
                LIMIT ?
            """, (limit,))
            
            results = []
            for row in cursor.fetchall():
                results.append({
                    'id': row[0],
                    'filename': row[1],
                    'total_lines': row[2],
                    'total_attacks': row[3],
                    'unique_ips': row[4],
                    'attack_breakdown': json.loads(row[5]) if row[5] else {},
                    'analyzed_at': row[6]
                })
            return results
        finally:
            conn.close()
    
    def get_timeline_data(self, days: int = 30) -> List[Dict]:
        """Get timeline data for visualization."""
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            
            # Calculate date threshold
            threshold_date = (datetime.now() - timedelta(days=days)).strftime('%Y-%m-%d')
            
            cursor.execute("""
                SELECT DATE(analyzed_at) as date,
                       SUM(total_attacks) as attacks,
                       SUM(unique_ips) as unique_ips
                FROM analysis_history
                WHERE DATE(analyzed_at) >= ?
                GROUP BY DATE(analyzed_at)
                ORDER BY date
            """, (threshold_date,))
            
            results = []
            for row in cursor.fetchall():
                results.append({
                    'date': row[0],
                    'attacks': row[1],
                    'unique_ips': row[2]
                })
            return results
        finally:
            conn.close()
    
    def add_custom_pattern(self, attack_type: str, pattern_regex: str, 
                          description: str = "") -> int:
        """Add a custom attack pattern."""
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO custom_patterns (attack_type, pattern_regex, description)
                VALUES (?, ?, ?)
            """, (attack_type, pattern_regex, description))
            
            pattern_id = cursor.lastrowid
            conn.commit()
            return pattern_id
        finally:
            conn.close()
    
    def get_custom_patterns(self, active_only: bool = True) -> List[Dict]:
        """Get custom attack patterns."""
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            
            if active_only:
                cursor.execute("""
                    SELECT id, attack_type, pattern_regex, description, is_active, created_at
                    FROM custom_patterns
                    WHERE is_active = 1
                    ORDER BY attack_type, created_at
                """)
            else:
                cursor.execute("""
                    SELECT id, attack_type, pattern_regex, description, is_active, created_at
                    FROM custom_patterns
                    ORDER BY attack_type, created_at
                """)
            
            results = []
            for row in cursor.fetchall():
                results.append({
                    'id': row[0],
                    'attack_type': row[1],
                    'pattern_regex': row[2],
                    'description': row[3],
                    'is_active': bool(row[4]),
                    'created_at': row[5]
                })
            return results
        finally:
            conn.close()
    
    def update_custom_pattern_status(self, pattern_id: int, is_active: bool):
        """Update the active status of a custom pattern."""
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE custom_patterns
                SET is_active = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            """, (1 if is_active else 0, pattern_id))
            conn.commit()
        finally:
            conn.close()
    
    def update_custom_pattern(self, pattern_id: int, attack_type: str = None, 
                             pattern_regex: str = None, description: str = None,
                             is_active: bool = None):
        """Update a custom pattern."""
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            
            updates = []
            params = []
            
            if attack_type is not None:
                updates.append("attack_type = ?")
                params.append(attack_type)
            if pattern_regex is not None:
                updates.append("pattern_regex = ?")
                params.append(pattern_regex)
            if description is not None:
                updates.append("description = ?")
                params.append(description)
            if is_active is not None:
                updates.append("is_active = ?")
                params.append(1 if is_active else 0)
            
            updates.append("updated_at = CURRENT_TIMESTAMP")
            params.append(pattern_id)
            
            cursor.execute(f"""
                UPDATE custom_patterns
                SET {', '.join(updates)}
                WHERE id = ?
            """, params)
            
            conn.commit()
        finally:
            conn.close()
    
    def save_ai_analysis(self, pattern_signature: str, log_entry: Dict[str, Any], 
                        analysis: Dict[str, Any], occurrence_count: int = 1):
        """Save AI threat analysis to database."""
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            
            # Convert lists/dicts to JSON strings
            indicators_json = json.dumps(analysis.get('indicators', []))
            log_entry_json = json.dumps(log_entry)
            
            cursor.execute("""
                INSERT OR REPLACE INTO ai_threat_analysis 
                (pattern_signature, threat_level, confidence, attack_type, reasoning, 
                 indicators, severity, ai_provider, occurrence_count, sample_log_entry,
                 first_seen, last_seen, upgrade_reason)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 
                        COALESCE((SELECT first_seen FROM ai_threat_analysis WHERE pattern_signature = ?), CURRENT_TIMESTAMP),
                        CURRENT_TIMESTAMP, ?)
            """, (
                pattern_signature,
                analysis.get('threat_level', 'benign'),
                analysis.get('confidence', 0.0),
                analysis.get('attack_type', ''),
                analysis.get('reasoning', ''),
                indicators_json,
                analysis.get('severity', 'low'),
                analysis.get('ai_provider', ''),
                occurrence_count,
                log_entry_json,
                pattern_signature,  # For the COALESCE subquery
                analysis.get('upgrade_reason', '')
            ))
            
            conn.commit()
        finally:
            conn.close()
    
    def get_ai_analysis(self, pattern_signature: str) -> Optional[Dict[str, Any]]:
        """Get AI analysis for a pattern signature."""
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT threat_level, confidence, attack_type, reasoning, indicators, 
                       severity, ai_provider, occurrence_count, first_seen, last_seen,
                       upgrade_reason, sample_log_entry
                FROM ai_threat_analysis 
                WHERE pattern_signature = ?
            """, (pattern_signature,))
            
            row = cursor.fetchone()
            if row:
                return {
                    'threat_level': row[0],
                    'confidence': row[1],
                    'attack_type': row[2],
                    'reasoning': row[3],
                    'indicators': json.loads(row[4]) if row[4] else [],
                    'severity': row[5],
                    'ai_provider': row[6],
                    'occurrence_count': row[7],
                    'first_seen': row[8],
                    'last_seen': row[9],
                    'upgrade_reason': row[10],
                    'sample_log_entry': json.loads(row[11]) if row[11] else {}
                }
            return None
        finally:
            conn.close()
    
    def update_ai_analysis(self, pattern_signature: str, analysis: Dict[str, Any], 
                          occurrence_count: int):
        """Update existing AI analysis."""
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            
            indicators_json = json.dumps(analysis.get('indicators', []))
            
            cursor.execute("""
                UPDATE ai_threat_analysis 
                SET threat_level = ?, confidence = ?, attack_type = ?, reasoning = ?,
                    indicators = ?, severity = ?, occurrence_count = ?, last_seen = CURRENT_TIMESTAMP,
                    upgrade_reason = ?, updated_at = CURRENT_TIMESTAMP
                WHERE pattern_signature = ?
            """, (
                analysis.get('threat_level', 'benign'),
                analysis.get('confidence', 0.0),
                analysis.get('attack_type', ''),
                analysis.get('reasoning', ''),
                indicators_json,
                analysis.get('severity', 'low'),
                occurrence_count,
                analysis.get('upgrade_reason', ''),
                pattern_signature
            ))
            
            conn.commit()
        finally:
            conn.close()
    
    def get_ai_threat_statistics(self) -> Dict[str, Any]:
        """Get AI threat analysis statistics."""
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            
            # Get threat level counts
            cursor.execute("""
                SELECT threat_level, COUNT(*) as count
                FROM ai_threat_analysis
                GROUP BY threat_level
            """)
            threat_counts = dict(cursor.fetchall())
            
            # Get escalated threats count
            cursor.execute("""
                SELECT COUNT(*) 
                FROM ai_threat_analysis 
                WHERE upgrade_reason IS NOT NULL AND upgrade_reason != ''
            """)
            escalated_count = cursor.fetchone()[0]
            
            # Get recent analysis count (last 7 days)
            cursor.execute("""
                SELECT COUNT(*) 
                FROM ai_threat_analysis 
                WHERE last_seen >= datetime('now', '-7 days')
            """)
            recent_count = cursor.fetchone()[0]
            
            # Get AI provider usage
            cursor.execute("""
                SELECT ai_provider, COUNT(*) as count
                FROM ai_threat_analysis
                WHERE ai_provider IS NOT NULL
                GROUP BY ai_provider
            """)
            provider_counts = dict(cursor.fetchall())
            
            return {
                'threat_level_counts': threat_counts,
                'escalated_threats': escalated_count,
                'recent_analysis_count': recent_count,
                'ai_provider_usage': provider_counts,
                'total_patterns': sum(threat_counts.values())
            }
        finally:
            conn.close()
    
    def get_escalated_threats(self, days: int = 7) -> List[Dict[str, Any]]:
        """Get threats that have been escalated in the last N days."""
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT pattern_signature, threat_level, confidence, attack_type, 
                       reasoning, severity, occurrence_count, first_seen, last_seen,
                       upgrade_reason, sample_log_entry
                FROM ai_threat_analysis 
                WHERE upgrade_reason IS NOT NULL 
                  AND upgrade_reason != ''
                  AND last_seen >= datetime('now', '-{} days')
                ORDER BY last_seen DESC
            """.format(days))
            
            results = []
            for row in cursor.fetchall():
                results.append({
                    'pattern_signature': row[0],
                    'threat_level': row[1],
                    'confidence': row[2],
                    'attack_type': row[3],
                    'reasoning': row[4],
                    'severity': row[5],
                    'occurrence_count': row[6],
                    'first_seen': row[7],
                    'last_seen': row[8],
                    'upgrade_reason': row[9],
                    'sample_log_entry': json.loads(row[10]) if row[10] else {}
                })
            
            return results
        finally:
            conn.close()
    
    def delete_custom_pattern(self, pattern_id: int):
        """Delete a custom pattern."""
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM custom_patterns WHERE id = ?", (pattern_id,))
            conn.commit()
        finally:
            conn.close()
    
    def track_unknown_attack(self, url: str, ip: str, timestamp: str, 
                            method: str, user_agent: str):
        """Track an unknown attack pattern."""
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            
            # Try to insert, if exists update frequency
            cursor.execute("""
                INSERT OR IGNORE INTO unknown_attacks 
                (url, ip, timestamp, method, user_agent)
                VALUES (?, ?, ?, ?, ?)
            """, (url, ip, timestamp, method, user_agent))
            
            if cursor.rowcount == 0:
                # Record exists, update frequency
                cursor.execute("""
                    UPDATE unknown_attacks 
                    SET frequency = frequency + 1,
                        detected_at = CURRENT_TIMESTAMP
                    WHERE url = ? AND ip = ?
                """, (url, ip))
            
            conn.commit()
        finally:
            conn.close()
    
    def get_unknown_attacks(self, limit: int = 100) -> List[Dict]:
        """Get unknown attack patterns."""
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, url, ip, timestamp, method, user_agent, detected_at, frequency
                FROM unknown_attacks
                ORDER BY frequency DESC, detected_at DESC
                LIMIT ?
            """, (limit,))
            
            results = []
            for row in cursor.fetchall():
                results.append({
                    'id': row[0],
                    'url': row[1],
                    'ip': row[2],
                    'timestamp': row[3],
                    'method': row[4],
                    'user_agent': row[5],
                    'detected_at': row[6],
                    'frequency': row[7]
                })
            return results
        finally:
            conn.close()
    
    def clear_unknown_attacks(self):
        """Clear all unknown attack records."""
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM unknown_attacks")
            conn.commit()
        finally:
            conn.close()