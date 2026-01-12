#!/usr/bin/env python3
"""
ML Manager for integrating machine learning anomaly detection
with the existing attack detection system
"""

import logging
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime

try:
    from .anomaly_detector import MLAnomalyDetector
    from .feature_extractor import LogFeatureExtractor
    from .behavioral_analyzer import BehavioralAnalyzer
    from .ai_threat_analyzer import AIThreatAnalyzer
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False

class MLManager:
    """Manages ML-based anomaly detection integration."""
    
    def __init__(self, db_manager=None):
        self.db_manager = db_manager
        self.anomaly_detector = None
        self.behavioral_analyzer = None
        self.ai_threat_analyzer = None
        self.is_enabled = False
        
        if ML_AVAILABLE:
            try:
                self.anomaly_detector = MLAnomalyDetector()
                self.behavioral_analyzer = BehavioralAnalyzer()
                self.ai_threat_analyzer = AIThreatAnalyzer(db_manager)
                self.is_enabled = True
                logging.info("ML anomaly detection and AI threat analysis initialized successfully")
            except Exception as e:
                logging.error(f"Failed to initialize ML anomaly detection: {e}")
                self.is_enabled = False
        else:
            logging.warning("ML dependencies not available. Install scikit-learn to enable ML features.")
    
    def is_available(self) -> bool:
        """Check if ML functionality is available."""
        return self.is_enabled and self.anomaly_detector is not None
    
    def train_on_normal_traffic(self, log_entries: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Train ML models on normal traffic patterns."""
        if not self.is_available():
            return {'error': 'ML functionality not available'}
        
        try:
            # Filter out any known attacks from training data
            normal_entries = [entry for entry in log_entries if not self._is_known_attack(entry)]
            
            if len(normal_entries) < 10:
                return {'error': 'Insufficient normal traffic data for training (minimum 10 entries required)'}
            
            training_results = self.anomaly_detector.train(normal_entries)
            
            # Save training info to database if available
            if self.db_manager:
                try:
                    self.db_manager.save_ml_training_info(training_results)
                except Exception as e:
                    logging.warning(f"Could not save ML training info to database: {e}")
            
            return {
                'success': True,
                'training_samples': len(normal_entries),
                'total_samples': len(log_entries),
                'filtered_attacks': len(log_entries) - len(normal_entries),
                'training_stats': training_results
            }
            
        except Exception as e:
            logging.error(f"ML training failed: {e}")
            return {'error': f'Training failed: {str(e)}'}
    
    def detect_anomalies(self, log_entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect anomalies in log entries using ML models."""
        if not self.is_available():
            return []
        
        if not self.anomaly_detector.is_trained:
            logging.warning("ML models not trained. Cannot detect anomalies.")
            return []
        
        try:
            anomaly_results = self.anomaly_detector.predict_anomalies(log_entries)
            
            # Process results and add additional context
            processed_results = []
            for result in anomaly_results:
                if result['is_anomaly']:
                    # Check for similar patterns in memory
                    similar_patterns = self.anomaly_detector.detect_similar_patterns(
                        result['log_entry'], threshold=0.7
                    )
                    
                    processed_result = {
                        'log_entry': result['log_entry'],
                        'anomaly_score': result['anomaly_score'],
                        'confidence': result['confidence'],
                        'model_scores': result['model_scores'],
                        'similar_patterns': similar_patterns,
                        'is_learned_pattern': len(similar_patterns) > 0,
                        'detection_type': 'ml_anomaly'
                    }
                    
                    processed_results.append(processed_result)
            
            return processed_results
            
        except Exception as e:
            logging.error(f"ML anomaly detection failed: {e}")
            return []
    
    def learn_from_feedback(self, log_entry: Dict[str, Any], is_attack: bool, 
                          attack_type: str = None) -> bool:
        """Learn from user feedback to improve detection."""
        if not self.is_available():
            return False
        
        try:
            self.anomaly_detector.learn_from_feedback(log_entry, is_attack, attack_type)
            
            # Save feedback to database if available
            if self.db_manager:
                try:
                    self.db_manager.save_ml_feedback(log_entry, is_attack, attack_type)
                except Exception as e:
                    logging.warning(f"Could not save ML feedback to database: {e}")
            
            return True
            
        except Exception as e:
            logging.error(f"ML feedback learning failed: {e}")
            return False
    
    def get_suspicious_patterns(self, min_attack_ratio: float = 0.3) -> List[Dict[str, Any]]:
        """Get patterns that have been marked as suspicious through learning."""
        if not self.is_available():
            return []
        
        suspicious_patterns = []
        
        for pattern_key, pattern_data in self.anomaly_detector.pattern_memory.items():
            attack_ratio = pattern_data['attack_count'] / pattern_data['count']
            
            if attack_ratio >= min_attack_ratio:
                suspicious_patterns.append({
                    'pattern_key': pattern_key,
                    'attack_ratio': attack_ratio,
                    'total_count': pattern_data['count'],
                    'attack_count': pattern_data['attack_count'],
                    'examples': pattern_data['examples'][:3],  # Limit examples
                    'confidence': min(attack_ratio * 2, 1.0)  # Scale confidence
                })
        
        return sorted(suspicious_patterns, key=lambda x: x['attack_ratio'], reverse=True)
    
    def analyze_with_ml(self, log_entries: List[Dict[str, Any]], 
                       enable_learning: bool = False) -> Dict[str, Any]:
        """Comprehensive ML analysis of log entries."""
        if not self.is_available():
            return {
                'ml_enabled': False,
                'anomalies': [],
                'behavioral_anomalies': [],
                'suspicious_patterns': [],
                'training_needed': True
            }
        
        results = {
            'ml_enabled': True,
            'model_trained': self.anomaly_detector.is_trained,
            'anomalies': [],
            'behavioral_anomalies': [],
            'suspicious_patterns': [],
            'training_needed': not self.anomaly_detector.is_trained
        }
        
        # Behavioral analysis (works without training)
        if self.behavioral_analyzer:
            try:
                behavioral_anomalies = self.behavioral_analyzer.analyze_request_sequence(log_entries)
                results['behavioral_anomalies'] = behavioral_anomalies
                results['behavioral_anomaly_count'] = len(behavioral_anomalies)
            except Exception as e:
                logging.error(f"Behavioral analysis failed: {e}")
                results['behavioral_anomalies'] = []
                results['behavioral_anomaly_count'] = 0
        
        # ML-based anomaly detection (requires training)
        if self.anomaly_detector.is_trained:
            anomalies = self.detect_anomalies(log_entries)
            results['anomalies'] = anomalies
            results['anomaly_count'] = len(anomalies)
        
        # Get suspicious patterns from learning
        suspicious_patterns = self.get_suspicious_patterns()
        results['suspicious_patterns'] = suspicious_patterns
        results['suspicious_pattern_count'] = len(suspicious_patterns)
        
        # AI-powered threat analysis for unknown patterns
        if self.ai_threat_analyzer:
            try:
                # Filter entries that weren't detected by traditional methods or ML
                unknown_entries = []
                for entry in log_entries:
                    # Simple heuristic: if status code suggests error/suspicious activity
                    status = entry.get('status', '')
                    if status and status not in ['200', '201', '204', '301', '302', '304']:
                        unknown_entries.append(entry)
                
                if unknown_entries:
                    ai_results = self.analyze_unknown_patterns_with_ai(unknown_entries)
                    results['ai_threat_analysis'] = ai_results
                    results['ai_threat_count'] = len(ai_results)
                else:
                    results['ai_threat_analysis'] = []
                    results['ai_threat_count'] = 0
                    
            except Exception as e:
                logging.error(f"AI threat analysis failed: {e}")
                results['ai_threat_analysis'] = []
                results['ai_threat_count'] = 0
        else:
            results['ai_threat_analysis'] = []
            results['ai_threat_count'] = 0
        
        # Auto-training on normal traffic if enabled and needed
        if enable_learning and not self.anomaly_detector.is_trained:
            training_result = self.train_on_normal_traffic(log_entries)
            results['auto_training'] = training_result
            
            # Retry anomaly detection after training
            if training_result.get('success'):
                anomalies = self.detect_anomalies(log_entries)
                results['anomalies'] = anomalies
                results['anomaly_count'] = len(anomalies)
                results['model_trained'] = True
                results['training_needed'] = False
        
        return results
        
    def get_model_info(self) -> Dict[str, Any]:
        """Get information about ML models."""
        if not self.is_available():
            return {'ml_available': False}
        
        info = self.anomaly_detector.get_model_info()
        info['ml_available'] = True
        info['ai_threat_analyzer_available'] = self.ai_threat_analyzer is not None
        
        return info
    
    def analyze_unknown_patterns_with_ai(self, log_entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyze unknown patterns using AI for progressive threat learning."""
        if not self.is_available() or not self.ai_threat_analyzer:
            return []
        
        ai_results = []
        pattern_occurrence_counts = {}
        
        try:
            for log_entry in log_entries:
                # Create pattern signature for tracking occurrences
                pattern_signature = self.ai_threat_analyzer._create_pattern_signature(log_entry)
                
                # Count occurrences
                pattern_occurrence_counts[pattern_signature] = pattern_occurrence_counts.get(pattern_signature, 0) + 1
                occurrence_count = pattern_occurrence_counts[pattern_signature]
                
                # Analyze with AI (handles progressive learning internally)
                ai_analysis = self.ai_threat_analyzer.analyze_unknown_pattern(
                    log_entry, occurrence_count
                )
                
                if ai_analysis and ai_analysis.get('threat_level') != 'benign':
                    ai_result = {
                        'log_entry': log_entry,
                        'ai_analysis': ai_analysis,
                        'pattern_signature': pattern_signature,
                        'occurrence_count': occurrence_count,
                        'detection_type': 'ai_threat_analysis'
                    }
                    ai_results.append(ai_result)
            
            return ai_results
            
        except Exception as e:
            logging.error(f"AI threat analysis failed: {e}")
            return []
    
    def get_ai_threat_statistics(self) -> Dict[str, Any]:
        """Get AI threat analysis statistics."""
        if not self.is_available() or not self.ai_threat_analyzer:
            return {}
        
        return self.ai_threat_analyzer.get_threat_statistics()
    
    def get_escalated_threats(self, days: int = 7) -> List[Dict[str, Any]]:
        """Get threats that have been escalated by AI analysis."""
        if not self.is_available() or not self.ai_threat_analyzer:
            return []
        
        return self.ai_threat_analyzer.get_escalated_threats(days)
    
    def _is_known_attack(self, log_entry: Dict[str, Any]) -> bool:
        """Check if log entry is a known attack (to filter from training data)."""
        # This is a simple heuristic - in practice, you might want to use
        # the existing attack detector to identify known attacks
        url = log_entry.get('url', '').lower()
        
        # Basic patterns that indicate obvious attacks
        attack_indicators = [
            'union select', 'or 1=1', '<script', 'javascript:', 
            '../etc/passwd', 'cmd.exe', 'powershell',
            'alert(', 'eval(', 'document.cookie'
        ]
        
        return any(indicator in url for indicator in attack_indicators)
    
    def export_ml_data(self) -> Dict[str, Any]:
        """Export ML training data and patterns for backup/analysis."""
        if not self.is_available():
            return {}
        
        return {
            'model_info': self.get_model_info(),
            'pattern_memory': self.anomaly_detector.pattern_memory,
            'export_timestamp': datetime.now().isoformat()
        }
    
    def import_ml_data(self, ml_data: Dict[str, Any]) -> bool:
        """Import ML training data and patterns."""
        if not self.is_available():
            return False
        
        try:
            if 'pattern_memory' in ml_data:
                self.anomaly_detector.pattern_memory.update(ml_data['pattern_memory'])
                self.anomaly_detector._save_pattern_memory()
            
            return True
            
        except Exception as e:
            logging.error(f"Failed to import ML data: {e}")
            return False