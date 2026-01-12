from typing import List, Dict, Tuple
from parser.log_parser import LogParser
from detector.attack_detector import AttackDetector
from database.db_manager import DatabaseManager

class BatchProcessor:
    def __init__(self, db_manager: DatabaseManager = None):
        self.db_manager = db_manager
        self.parser = LogParser()
    
    def process_multiple_files(self, files: List[Tuple[str, str]], enable_learning: bool = False, 
                             enable_ml: bool = False, enable_ai_analysis: bool = False) -> List[Dict]:
        """
        Process multiple files with enhanced AI/ML capabilities.
        
        Args:
            files: List of (filename, content) tuples
            enable_learning: Enable pattern learning for unknown attacks
            enable_ml: Enable ML-based anomaly detection
            enable_ai_analysis: Enable AI-powered progressive threat learning
        """
        results = []
        
        # Enable AI analysis automatically if ML is enabled (they work together)
        if enable_ai_analysis:
            enable_ml = True
        
        detector = AttackDetector(
            db_manager=self.db_manager, 
            enable_learning=enable_learning,
            enable_ml=enable_ml
        )
        
        for filename, content in files:
            try:
                parsed_logs = self.parser.parse_log_file(content)
                analysis = detector.analyze_logs(parsed_logs)
                
                total_lines = len(content.split('\n'))
                
                # Enhanced analysis results with AI/ML data
                result_data = {
                    'filename': filename,
                    'success': True,
                    'total_lines': total_lines,
                    'parsed_lines': len(parsed_logs),
                    'analysis': analysis,
                    'error': None,
                    'ml_enabled': analysis.get('ml_enabled', False),
                    'ai_enabled': enable_ai_analysis
                }
                
                # Add ML/AI specific statistics
                if analysis.get('ml_results'):
                    ml_results = analysis['ml_results']
                    result_data.update({
                        'ml_anomaly_count': ml_results.get('anomaly_count', 0),
                        'behavioral_anomaly_count': ml_results.get('behavioral_anomaly_count', 0),
                        'ai_threat_count': ml_results.get('ai_threat_count', 0),
                        'suspicious_pattern_count': ml_results.get('suspicious_pattern_count', 0)
                    })
                
                # Save to database if available
                if self.db_manager:
                    try:
                        analysis_id = self.db_manager.save_analysis(
                            filename=filename,
                            total_lines=total_lines,
                            total_attacks=analysis.get('total_attacks', 0),
                            unique_ips=analysis.get('unique_ips', 0),
                            attack_breakdown=analysis.get('attack_type_counts', {}),
                            attacks_data=analysis.get('attacks', [])
                        )
                        result_data['analysis_id'] = analysis_id
                    except Exception:
                        pass
                
                results.append(result_data)
                
            except Exception as e:
                results.append({
                    'filename': filename,
                    'success': False,
                    'error': str(e),
                    'analysis': None,
                    'ml_enabled': False,
                    'ai_enabled': False
                })
        
        return results
    
    def get_batch_summary(self, results: List[Dict]) -> Dict:
        """Enhanced batch summary with AI/ML statistics."""
        total_files = len(results)
        successful = sum(1 for r in results if r['success'])
        failed = total_files - successful
        
        total_attacks = 0
        total_lines = 0
        all_attack_types = {}
        unique_ips = set()
        
        # AI/ML specific counters
        total_ml_anomalies = 0
        total_behavioral_anomalies = 0
        total_ai_threats = 0
        total_suspicious_patterns = 0
        ml_enabled_files = 0
        ai_enabled_files = 0
        
        for result in results:
            if result['success'] and result['analysis']:
                analysis = result['analysis']
                total_attacks += analysis.get('total_attacks', 0)
                total_lines += result.get('total_lines', 0)
                
                # Count ML/AI enabled files
                if result.get('ml_enabled', False):
                    ml_enabled_files += 1
                if result.get('ai_enabled', False):
                    ai_enabled_files += 1
                
                # Add ML/AI specific counts
                total_ml_anomalies += result.get('ml_anomaly_count', 0)
                total_behavioral_anomalies += result.get('behavioral_anomaly_count', 0)
                total_ai_threats += result.get('ai_threat_count', 0)
                total_suspicious_patterns += result.get('suspicious_pattern_count', 0)
                
                # Aggregate attack types
                for attack_type, count in analysis.get('attack_type_counts', {}).items():
                    all_attack_types[attack_type] = all_attack_types.get(attack_type, 0) + count
                
                # Collect unique IPs
                for ip in analysis.get('ip_attacks', {}).keys():
                    unique_ips.add(ip)
        
        summary = {
            'total_files': total_files,
            'successful': successful,
            'failed': failed,
            'total_attacks': total_attacks,
            'total_lines': total_lines,
            'attack_type_counts': all_attack_types,
            'unique_ips': len(unique_ips),
            # Enhanced AI/ML statistics
            'ml_enabled_files': ml_enabled_files,
            'ai_enabled_files': ai_enabled_files,
            'total_ml_anomalies': total_ml_anomalies,
            'total_behavioral_anomalies': total_behavioral_anomalies,
            'total_ai_threats': total_ai_threats,
            'total_suspicious_patterns': total_suspicious_patterns,
            'advanced_detection_enabled': ml_enabled_files > 0 or ai_enabled_files > 0
        }
        
        return summary
    
    def get_ai_threat_summary(self, results: List[Dict]) -> Dict:
        """Get detailed AI threat analysis summary across all files."""
        if not self.db_manager:
            return {}
        
        try:
            # Get AI threat statistics from database
            ai_stats = self.db_manager.get_ai_threat_statistics()
            escalated_threats = self.db_manager.get_escalated_threats(days=1)
            
            # Aggregate AI results from batch processing
            ai_threats_by_level = {'suspicious': 0, 'malicious': 0, 'benign': 0}
            ai_providers_used = set()
            
            for result in results:
                if result['success'] and result.get('analysis', {}).get('ml_results', {}).get('ai_threat_analysis'):
                    for ai_result in result['analysis']['ml_results']['ai_threat_analysis']:
                        threat_level = ai_result.get('ai_analysis', {}).get('threat_level', 'benign')
                        ai_threats_by_level[threat_level] = ai_threats_by_level.get(threat_level, 0) + 1
                        
                        provider = ai_result.get('ai_analysis', {}).get('ai_provider')
                        if provider:
                            ai_providers_used.add(provider)
            
            return {
                'database_stats': ai_stats,
                'recent_escalated': len(escalated_threats),
                'batch_ai_threats': ai_threats_by_level,
                'ai_providers_used': list(ai_providers_used),
                'escalated_threats_details': escalated_threats[:5]  # Top 5 recent escalations
            }
            
        except Exception as e:
            return {'error': str(e)}
