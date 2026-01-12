import re
from typing import Dict, List, Set, Optional

# Try to import ML functionality
try:
    from ml.ml_manager import MLManager
    from ml.ai_threat_analyzer import AIThreatAnalyzer
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False

class AttackDetector:
    def __init__(self, db_manager=None, enable_learning=False, enable_ml=False):
        self.db_manager = db_manager
        self.enable_learning = enable_learning
        self.enable_ml = enable_ml
        
        # Initialize ML manager if available and enabled
        self.ml_manager = None
        self.ai_threat_analyzer = None
        if ML_AVAILABLE and enable_ml:
            try:
                self.ml_manager = MLManager(db_manager)
                if self.ml_manager.is_available():
                    print("✅ ML-based anomaly detection enabled")
                    # AI threat analyzer is initialized within MLManager
                    self.ai_threat_analyzer = self.ml_manager.ai_threat_analyzer
                else:
                    print("⚠️  ML dependencies available but initialization failed")
                    self.ml_manager = None
            except Exception as e:
                print(f"⚠️  Failed to initialize ML manager: {e}")
                self.ml_manager = None
        elif enable_ml and not ML_AVAILABLE:
            print("⚠️  ML requested but dependencies not available. Install scikit-learn to enable ML features.")
        
        self.attack_patterns = {
            'SQL Injection': [
                r"(\bUNION\b.*\bSELECT\b)",
                r"(\bOR\b\s+[\d'\"]+\s*=\s*[\d'\"]+)",
                r"(--\s*$|#\s*$|\/\*.*\*\/)",  # Comments at end of line
                r"('--)",  # Quote followed by comment
                r"(\"--)",  # Double quote followed by comment
                r"(';--)",  # Quote semicolon comment
                r"(\bDROP\b\s+\bTABLE\b)",
                r"(\bINSERT\b\s+\bINTO\b)",
                r"(\bDELETE\b\s+\bFROM\b)",
                r"(\bUPDATE\b\s+.*\bSET\b)",
                r"(';|\";\s*--)",
                r"(\bEXEC\b\s*\(|\bEXECUTE\b)",
                r"(@@version|user\(\)|database\(\))",
                r"(information_schema|mysql\.user)",
                r"(\bAND\b\s+[\d'\"]+\s*=\s*[\d'\"]+)",
                r"(admin'|root'|user')",  # Common SQL injection attempts
                r"('.*OR.*')",  # Quote OR quote patterns
                r"(\d+\s*=\s*\d+)",  # Numeric equality tests
                r"(1=1|0=0)",  # Classic boolean tests
            ],
            'XSS': [
                r"(<script[^>]*>.*?</script>)",
                r"(<script[^>]*>)",
                r"(javascript:)",
                r"(onerror\s*=)",
                r"(onload\s*=)",
                r"(onclick\s*=)",
                r"(onmouseover\s*=)",
                r"(<iframe[^>]*>)",
                r"(<img[^>]*onerror)",
                r"(<svg[^>]*onload)",
                r"(alert\s*\()",
                r"(eval\s*\()",
                r"(document\.cookie)",
                r"(String\.fromCharCode)"
            ],
            'Directory Traversal': [
                r"(\.\./|\.\.\\)",
                r"(%2e%2e/|%2e%2e\\|%2e%2e%2f)",
                r"(\.\.;/|\.\.;\\)",
                r"(/etc/passwd|/etc/shadow)",
                r"(c:\\windows\\|c:/windows/)",
                r"(\.\.%5c|\.\.%2f)",
                r"(/\.\.%00|\\\.\.%00)"
            ],
            'Command Injection': [
                r"(;\s*ls\b|;\s*dir\b)",
                r"(\|\s*cat\b|\|\s*type\b)",
                r"(;\s*wget\b|;\s*curl\b)",
                r"(`.*`)",
                r"(\$\(.*\))",
                r"(;\s*rm\b|;\s*del\b)",
                r"(;\s*nc\b|;\s*netcat\b)",
                r"(&&\s*[a-zA-Z_][a-zA-Z0-9_]*)",  # More specific: && followed by command
                r"(\|\|\s*[a-zA-Z_][a-zA-Z0-9_]*)",  # More specific: || followed by command
                r"(;\s*chmod\b|;\s*chown\b)",
                r"(/bin/bash|/bin/sh|cmd\.exe)",
                r"(system\s*\(|exec\s*\(|shell_exec\s*\()",  # Function calls
            ],
            'File Inclusion': [
                r"(php://filter|php://input)",
                r"(file://|expect://)",
                r"(data://text/plain)",
                r"(\?page=.*\.\./)",
                r"(\?file=.*\.\./)",
                r"(\?include=.*\.\./)",
                r"(\?path=.*\.\./)",
                r"(\.php\?.*=http://)",
                r"(\.php\?.*=ftp://)"
            ],
            # NEW ATTACK TYPES - Add your custom patterns here
            'JWT Token Manipulation': [
                r"(jwt=eyJ[A-Za-z0-9+/=]+\.[A-Za-z0-9+/=]+\.[A-Za-z0-9+/=]+)",
                r"(token=eyJ[A-Za-z0-9+/=]+)",
                r"(Bearer\s+eyJ[A-Za-z0-9+/=]+)",
                r"(authorization.*eyJ[A-Za-z0-9+/=]+)"
            ],
            'API Rate Limiting Bypass': [
                r"(X-Forwarded-For.*,.*,.*)",  # Multiple IPs
                r"(X-Real-IP.*[0-9]{1,3}\.[0-9]{1,3})",
                r"(User-Agent.*bot.*bot)",  # Multiple bot signatures
                r"(/api/.*\?.*limit=999\d+)"  # Excessive limits
            ],
            'NoSQL Injection': [
                r"(\$ne|\$gt|\$lt|\$regex)",  # MongoDB operators
                r"({\s*\$where)",  # MongoDB $where
                r"(\.find\s*\()",  # NoSQL queries
                r"(ObjectId\s*\()"  # MongoDB ObjectId
            ],
            'LDAP Injection': [
                r"(\*\)\(.*=)",  # LDAP wildcard injection
                r"(\)\(.*\|)",  # LDAP OR injection
                r"(\)\(&\(.*=)",  # LDAP AND injection
                r"(cn=.*\*.*\))"  # LDAP enumeration
            ],
            'XML/XXE Injection': [
                r"(<!ENTITY.*SYSTEM)",  # XXE entity
                r"(<!DOCTYPE.*\[)",  # DTD declaration
                r"(&[a-zA-Z]+;.*&[a-zA-Z]+;)",  # Multiple entities
                r"(SYSTEM\s+[\"']file://)"  # File system access
            ]
        }
        
        self.compiled_patterns = {}
        for attack_type, patterns in self.attack_patterns.items():
            self.compiled_patterns[attack_type] = [
                re.compile(pattern, re.IGNORECASE) for pattern in patterns
            ]
        
        if self.db_manager:
            self.load_custom_patterns()
    
    def load_custom_patterns(self):
        if not self.db_manager:
            return
        
        try:
            custom_patterns = self.db_manager.get_custom_patterns(active_only=True)
            for pattern_data in custom_patterns:
                attack_type = pattern_data['attack_type']
                pattern_regex = pattern_data['pattern_regex']
                
                if attack_type not in self.compiled_patterns:
                    self.compiled_patterns[attack_type] = []
                
                try:
                    compiled = re.compile(pattern_regex, re.IGNORECASE)
                    self.compiled_patterns[attack_type].append(compiled)
                except re.error:
                    pass
        except Exception:
            pass

    def detect_attacks(self, log_entry: Dict[str, str]) -> List[Dict[str, any]]:
        detected_attacks = []
        url = log_entry.get('url', '')
        
        for attack_type, patterns in self.compiled_patterns.items():
            for pattern in patterns:
                match = pattern.search(url)
                if match:
                    detected_attacks.append({
                        'attack_type': attack_type,
                        'matched_pattern': pattern.pattern,
                        'matched_payload': match.group(0),
                        'full_url': url,
                        'ip': log_entry.get('ip', ''),
                        'timestamp': log_entry.get('timestamp', ''),
                        'method': log_entry.get('method', ''),
                        'user_agent': log_entry.get('user_agent', ''),
                        'status': log_entry.get('status', ''),
                        'line_number': log_entry.get('line_number', 0)
                    })
                    break
        
        return detected_attacks

    def analyze_logs(self, parsed_logs: List[Dict[str, str]]) -> Dict[str, any]:
        all_attacks = []
        attack_type_counts = {}
        ip_attacks = {}
        unknown_count = 0
        ml_results = {}
        
        # Traditional pattern-based detection
        for log_entry in parsed_logs:
            attacks = self.detect_attacks(log_entry)
            if attacks:
                all_attacks.extend(attacks)
                
                for attack in attacks:
                    attack_type = attack['attack_type']
                    attack_type_counts[attack_type] = attack_type_counts.get(attack_type, 0) + 1
                    
                    ip = attack['ip']
                    if ip not in ip_attacks:
                        ip_attacks[ip] = []
                    ip_attacks[ip].append(attack_type)
            elif self.enable_learning and self.db_manager:
                status_code = log_entry.get('status', '')
                if status_code and status_code not in ['200', '201', '204', '301', '302', '304']:
                    try:
                        self.db_manager.track_unknown_attack(
                            url=log_entry.get('url', ''),
                            ip=log_entry.get('ip', ''),
                            timestamp=log_entry.get('timestamp', ''),
                            method=log_entry.get('method', ''),
                            user_agent=log_entry.get('user_agent', '')
                        )
                        unknown_count += 1
                    except Exception:
                        pass
        
        # ML-based anomaly detection
        if self.ml_manager and self.ml_manager.is_available():
            try:
                ml_results = self.ml_manager.analyze_with_ml(
                    parsed_logs, 
                    enable_learning=self.enable_learning
                )
                
                # Add ML-detected anomalies to results
                if ml_results.get('anomalies'):
                    for anomaly in ml_results['anomalies']:
                        # Convert ML anomaly to attack format
                        ml_attack = {
                            'attack_type': 'ML Anomaly',
                            'matched_pattern': f"ML Score: {anomaly['anomaly_score']:.3f}",
                            'matched_payload': anomaly['log_entry'].get('url', ''),
                            'full_url': anomaly['log_entry'].get('url', ''),
                            'ip': anomaly['log_entry'].get('ip', ''),
                            'timestamp': anomaly['log_entry'].get('timestamp', ''),
                            'method': anomaly['log_entry'].get('method', ''),
                            'user_agent': anomaly['log_entry'].get('user_agent', ''),
                            'status': anomaly['log_entry'].get('status', ''),
                            'line_number': anomaly['log_entry'].get('line_number', 0),
                            'ml_data': {
                                'anomaly_score': anomaly['anomaly_score'],
                                'confidence': anomaly['confidence'],
                                'model_scores': anomaly['model_scores'],
                                'similar_patterns': anomaly.get('similar_patterns', []),
                                'is_learned_pattern': anomaly.get('is_learned_pattern', False)
                            }
                        }
                        
                        all_attacks.append(ml_attack)
                        attack_type_counts['ML Anomaly'] = attack_type_counts.get('ML Anomaly', 0) + 1
                        
                        # Add to IP attacks
                        ip = ml_attack['ip']
                        if ip not in ip_attacks:
                            ip_attacks[ip] = []
                        ip_attacks[ip].append('ML Anomaly')
                
                # Add behavioral anomalies as separate category
                if ml_results.get('behavioral_anomalies'):
                    for anomaly in ml_results['behavioral_anomalies']:
                        # Convert behavioral anomaly to attack format
                        behavioral_attack = {
                            'attack_type': 'Behavioral Anomaly',
                            'matched_pattern': f"{anomaly['type']}: {anomaly['description']}",
                            'matched_payload': anomaly.get('evidence', {}).get('sample_urls', [''])[0] if anomaly.get('evidence', {}).get('sample_urls') else '',
                            'full_url': anomaly.get('evidence', {}).get('sample_urls', [''])[0] if anomaly.get('evidence', {}).get('sample_urls') else '',
                            'ip': anomaly.get('ip', ''),
                            'timestamp': '',  # Behavioral anomalies span multiple requests
                            'method': '',
                            'user_agent': '',
                            'status': '',
                            'line_number': 0,
                            'behavioral_data': {
                                'anomaly_type': anomaly['type'],
                                'description': anomaly['description'],
                                'evidence': anomaly.get('evidence', {}),
                                'severity': anomaly.get('severity', 'medium'),
                                'confidence': anomaly.get('confidence', 0.5)
                            }
                        }
                        
                        all_attacks.append(behavioral_attack)
                        attack_type_counts['Behavioral Anomaly'] = attack_type_counts.get('Behavioral Anomaly', 0) + 1
                        
                        # Add to IP attacks
                        ip = behavioral_attack['ip']
                        if ip and ip not in ip_attacks:
                            ip_attacks[ip] = []
                        if ip:
                            ip_attacks[ip].append('Behavioral Anomaly')
                
                # Add AI threat analysis results
                if ml_results.get('ai_threat_analysis'):
                    for ai_result in ml_results['ai_threat_analysis']:
                        ai_analysis = ai_result['ai_analysis']
                        log_entry = ai_result['log_entry']
                        
                        # Convert AI threat to attack format
                        ai_attack = {
                            'attack_type': f"AI Threat ({ai_analysis.get('threat_level', 'unknown').title()})",
                            'matched_pattern': f"AI Analysis: {ai_analysis.get('attack_type', 'unknown')}",
                            'matched_payload': log_entry.get('url', ''),
                            'full_url': log_entry.get('url', ''),
                            'ip': log_entry.get('ip', ''),
                            'timestamp': log_entry.get('timestamp', ''),
                            'method': log_entry.get('method', ''),
                            'user_agent': log_entry.get('user_agent', ''),
                            'status': log_entry.get('status', ''),
                            'line_number': log_entry.get('line_number', 0),
                            'ai_data': {
                                'threat_level': ai_analysis.get('threat_level', 'unknown'),
                                'confidence': ai_analysis.get('confidence', 0.0),
                                'attack_type': ai_analysis.get('attack_type', 'unknown'),
                                'reasoning': ai_analysis.get('reasoning', ''),
                                'indicators': ai_analysis.get('indicators', []),
                                'severity': ai_analysis.get('severity', 'low'),
                                'ai_provider': ai_analysis.get('ai_provider', 'unknown'),
                                'occurrence_count': ai_result.get('occurrence_count', 1),
                                'upgrade_reason': ai_analysis.get('upgrade_reason', ''),
                                'pattern_signature': ai_result.get('pattern_signature', '')
                            }
                        }
                        
                        all_attacks.append(ai_attack)
                        attack_type = ai_attack['attack_type']
                        attack_type_counts[attack_type] = attack_type_counts.get(attack_type, 0) + 1
                        
                        # Add to IP attacks
                        ip = ai_attack['ip']
                        if ip not in ip_attacks:
                            ip_attacks[ip] = []
                        ip_attacks[ip].append(attack_type)
                if ml_results.get('suspicious_patterns'):
                    for pattern in ml_results['suspicious_patterns']:
                        # Find log entries matching this pattern
                        for example in pattern.get('examples', []):
                            if example.get('is_attack', False):
                                pattern_attack = {
                                    'attack_type': 'Suspicious Pattern',
                                    'matched_pattern': f"Learned Pattern (Confidence: {pattern['confidence']:.2f})",
                                    'matched_payload': example['log_entry'].get('url', ''),
                                    'full_url': example['log_entry'].get('url', ''),
                                    'ip': example['log_entry'].get('ip', ''),
                                    'timestamp': example['log_entry'].get('timestamp', ''),
                                    'method': example['log_entry'].get('method', ''),
                                    'user_agent': example['log_entry'].get('user_agent', ''),
                                    'status': example['log_entry'].get('status', ''),
                                    'line_number': example['log_entry'].get('line_number', 0),
                                    'pattern_data': pattern
                                }
                                
                                all_attacks.append(pattern_attack)
                                attack_type_counts['Suspicious Pattern'] = attack_type_counts.get('Suspicious Pattern', 0) + 1
                                
                                # Add to IP attacks
                                ip = pattern_attack['ip']
                                if ip not in ip_attacks:
                                    ip_attacks[ip] = []
                                ip_attacks[ip].append('Suspicious Pattern')
                
            except Exception as e:
                print(f"ML analysis failed: {e}")
                ml_results = {'error': str(e)}
        
        result = {
            'total_attacks': len(all_attacks),
            'attacks': all_attacks,
            'attack_type_counts': attack_type_counts,
            'ip_attacks': ip_attacks,
            'unique_ips': len(ip_attacks),
            'unknown_tracked': unknown_count
        }
        
        # Add ML results if available
        if ml_results:
            result['ml_results'] = ml_results
            result['ml_enabled'] = True
        else:
            result['ml_enabled'] = False
        
        return result
    
    def provide_ml_feedback(self, log_entry: Dict[str, str], is_attack: bool, 
                           attack_type: str = None) -> bool:
        """Provide feedback to ML system for learning."""
        if self.ml_manager and self.ml_manager.is_available():
            return self.ml_manager.learn_from_feedback(log_entry, is_attack, attack_type)
        return False
    
    def get_ml_info(self) -> Dict[str, any]:
        """Get ML system information."""
        if self.ml_manager and self.ml_manager.is_available():
            return self.ml_manager.get_model_info()
        return {'ml_available': False}
    
    def train_ml_models(self, log_entries: List[Dict[str, str]]) -> Dict[str, any]:
        """Train ML models on provided log entries."""
        if self.ml_manager and self.ml_manager.is_available():
            return self.ml_manager.train_on_normal_traffic(log_entries)
        return {'error': 'ML not available'}
