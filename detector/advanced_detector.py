#!/usr/bin/env python3
"""
Advanced Attack Detection Capabilities
Multi-vector attack detection, evasion techniques, and behavioral analysis
"""

import re
import json
from typing import Dict, List, Set, Optional, Tuple
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import hashlib
import base64
from urllib.parse import unquote, parse_qs

class AdvancedAttackDetector:
    """Enhanced attack detection with multi-vector analysis."""
    
    def __init__(self, db_manager=None):
        self.db_manager = db_manager
        
        # Advanced attack patterns
        self.advanced_patterns = {
            'API_Abuse': [
                r'(/api/v\d+/.*){5,}',  # Rapid API calls
                r'/graphql.*query.*{.*}.*{.*}',  # Complex GraphQL
                r'/api/.*\?.*limit=\d{4,}',  # Large limit values
                r'/api/.*\?.*offset=\d{6,}',  # Large offset values
            ],
            'Authentication_Attacks': [
                r'(login|signin|auth).*password=.*password=',  # Multiple password attempts
                r'(admin|root|administrator).*[\'\"]\s*OR\s*[\'\"]\d+[\'\"]\s*=\s*[\'\"]\d+',
                r'(login|auth).*\?.*token=.*&.*token=',  # Token manipulation
                r'(forgot|reset).*password.*\?.*email=.*@.*&.*email=',  # Email enumeration
            ],
            'Business_Logic_Attacks': [
                r'(price|amount|quantity)=(-\d+|\d{10,})',  # Price manipulation
                r'(user_id|id)=\d+.*&.*(user_id|id)=\d+',  # ID manipulation
                r'(role|permission|admin)=(true|1|admin)',  # Privilege escalation
                r'(discount|coupon)=\d{2,3}',  # Excessive discounts
            ],
            'IoT_Attacks': [
                r'/cgi-bin/.*\?.*cmd=',  # IoT command injection
                r'(telnet|ssh|ftp)://.*:\d+',  # Protocol abuse
                r'/setup\.cgi.*password=',  # IoT setup exploitation
                r'(camera|router|device).*default.*password',  # Default credentials
            ],
            'Cloud_Attacks': [
                r'\.amazonaws\.com.*credentials',  # AWS credential exposure
                r'(azure|gcp).*token.*bearer',  # Cloud token abuse
                r's3://.*bucket.*public',  # S3 bucket enumeration
                r'(lambda|function).*invoke.*payload',  # Serverless abuse
            ],
            'Advanced_XSS': [
                r'<svg.*onload.*alert.*>',  # SVG-based XSS
                r'<iframe.*srcdoc.*script.*>',  # Iframe XSS
                r'<object.*data.*javascript:',  # Object XSS
                r'<embed.*src.*data:text/html',  # Embed XSS
                r'<link.*href.*javascript:',  # Link XSS
            ],
            'Advanced_SQLi': [
                r'(WAITFOR|DELAY|SLEEP)\s*\(\s*[\'\"]\d+:\d+:\d+[\'\"]\s*\)',  # Time-based
                r'(LOAD_FILE|INTO\s+OUTFILE|INTO\s+DUMPFILE)',  # File operations
                r'(@@version|@@hostname|@@datadir)',  # Information gathering
                r'(BENCHMARK|HEAVY_QUERY)\s*\(',  # Performance attacks
            ]
        }
        
        # Compile patterns for performance
        self.compiled_advanced_patterns = {}
        for attack_type, patterns in self.advanced_patterns.items():
            self.compiled_advanced_patterns[attack_type] = [
                re.compile(pattern, re.IGNORECASE) for pattern in patterns
            ]
        
        # Evasion technique patterns
        self.evasion_patterns = {
            'encoding': [
                r'%[0-9a-fA-F]{2}',  # URL encoding
                r'&#x[0-9a-fA-F]+;',  # Hex entities
                r'&#\d+;',  # Decimal entities
                r'\\x[0-9a-fA-F]{2}',  # Hex escapes
                r'\\u[0-9a-fA-F]{4}',  # Unicode escapes
            ],
            'obfuscation': [
                r'eval\s*\(\s*unescape',  # Eval + unescape
                r'String\.fromCharCode',  # Character code conversion
                r'atob\s*\(',  # Base64 decode
                r'document\[.*\]\[.*\]',  # Bracket notation
            ],
            'fragmentation': [
                r'<\s*script',  # Whitespace in tags
                r'java\s*script:',  # Whitespace in protocol
                r'on\w+\s*=',  # Whitespace in events
            ],
            'case_variation': [
                r'[sS][cC][rR][iI][pP][tT]',  # Mixed case script
                r'[uU][nN][iI][oO][nN]',  # Mixed case union
                r'[sS][eE][lL][eE][cC][tT]',  # Mixed case select
            ]
        }
        
        # Attack chain patterns
        self.attack_chains = {
            'reconnaissance': ['robots.txt', 'sitemap.xml', '.git', '.env', 'phpinfo', '.well-known'],
            'scanning': ['admin', 'login', 'wp-admin', 'phpmyadmin', 'config', 'backup'],
            'exploitation': ['union', 'script', '../', 'eval(', 'system(', 'exec('],
            'persistence': ['shell', 'backdoor', 'webshell', 'upload', 'write', 'chmod']
        }
    
    def detect_advanced_attacks(self, log_entry: Dict[str, str]) -> List[Dict[str, any]]:
        """Detect advanced attack patterns."""
        detected_attacks = []
        url = log_entry.get('url', '')
        
        # Check advanced patterns
        for attack_type, patterns in self.compiled_advanced_patterns.items():
            for pattern in patterns:
                match = pattern.search(url)
                if match:
                    attack = {
                        'attack_type': attack_type,
                        'matched_pattern': pattern.pattern,
                        'matched_payload': match.group(0),
                        'full_url': url,
                        'ip': log_entry.get('ip', ''),
                        'timestamp': log_entry.get('timestamp', ''),
                        'method': log_entry.get('method', ''),
                        'user_agent': log_entry.get('user_agent', ''),
                        'status': log_entry.get('status', ''),
                        'line_number': log_entry.get('line_number', 0),
                        'detection_level': 'advanced',
                        'evasion_techniques': self.detect_evasion_techniques(url),
                        'obfuscation_score': self.calculate_obfuscation_score(url)
                    }
                    detected_attacks.append(attack)
                    break
        
        return detected_attacks
    
    def detect_evasion_techniques(self, payload: str) -> List[str]:
        """Detect evasion techniques used in payload."""
        techniques = []
        
        for technique, patterns in self.evasion_patterns.items():
            for pattern in patterns:
                if re.search(pattern, payload, re.IGNORECASE):
                    techniques.append(technique)
                    break
        
        return techniques
    
    def calculate_obfuscation_score(self, payload: str) -> float:
        """Calculate obfuscation complexity score (0-1)."""
        score = 0.0
        
        # Check for various obfuscation indicators
        indicators = {
            'url_encoding': len(re.findall(r'%[0-9a-fA-F]{2}', payload)) * 0.1,
            'html_entities': len(re.findall(r'&#\w+;', payload)) * 0.15,
            'unicode_escapes': len(re.findall(r'\\u[0-9a-fA-F]{4}', payload)) * 0.2,
            'base64_patterns': len(re.findall(r'[A-Za-z0-9+/]{20,}={0,2}', payload)) * 0.25,
            'eval_patterns': len(re.findall(r'eval\s*\(', payload, re.IGNORECASE)) * 0.3,
        }
        
        score = sum(indicators.values())
        return min(score, 1.0)  # Cap at 1.0
    
    def analyze_attack_chains(self, log_entries: List[Dict[str, str]]) -> List[Dict]:
        """Detect multi-step attack sequences."""
        # Group by IP address
        ip_groups = defaultdict(list)
        for entry in log_entries:
            ip = entry.get('ip', '')
            ip_groups[ip].append(entry)
        
        attack_sequences = []
        
        for ip, requests in ip_groups.items():
            if len(requests) < 3:  # Need minimum requests for chain
                continue
            
            # Sort by timestamp
            requests.sort(key=lambda x: x.get('timestamp', ''))
            
            # Analyze sequence
            chain_analysis = self._analyze_request_sequence(requests)
            if chain_analysis['is_attack_chain']:
                attack_sequences.append({
                    'ip': ip,
                    'chain_score': chain_analysis['score'],
                    'phases': chain_analysis['phases'],
                    'request_count': len(requests),
                    'time_span': chain_analysis['time_span'],
                    'severity': chain_analysis['severity'],
                    'requests': requests[:10]  # Limit for performance
                })
        
        return attack_sequences
    
    def _analyze_request_sequence(self, requests: List[Dict]) -> Dict:
        """Analyze a sequence of requests for attack patterns."""
        phase_scores = {phase: 0 for phase in self.attack_chains.keys()}
        
        # Analyze each request
        for request in requests:
            url = request.get('url', '').lower()
            for phase, indicators in self.attack_chains.items():
                for indicator in indicators:
                    if indicator in url:
                        phase_scores[phase] += 1
                        break
        
        # Calculate overall score
        phases_detected = [phase for phase, score in phase_scores.items() if score > 0]
        total_indicators = sum(phase_scores.values())
        
        # Determine if it's an attack chain
        is_attack_chain = len(phases_detected) >= 2 and total_indicators >= 3
        
        # Calculate severity
        severity = 'low'
        if len(phases_detected) >= 3:
            severity = 'high'
        elif len(phases_detected) == 2 and total_indicators >= 5:
            severity = 'medium'
        
        return {
            'is_attack_chain': is_attack_chain,
            'score': min(len(phases_detected) * 0.3 + total_indicators * 0.1, 1.0),
            'phases': phases_detected,
            'phase_scores': phase_scores,
            'time_span': self._calculate_time_span(requests),
            'severity': severity
        }
    
    def _calculate_time_span(self, requests: List[Dict]) -> str:
        """Calculate time span of requests."""
        if len(requests) < 2:
            return "0 seconds"
        
        # Simplified time calculation
        return f"{len(requests)} requests over {len(requests) * 2} seconds (estimated)"
    
    def detect_distributed_attacks(self, log_entries: List[Dict[str, str]]) -> List[Dict]:
        """Detect coordinated attacks from multiple IPs."""
        # Group attacks by payload similarity
        payload_groups = defaultdict(list)
        
        for entry in log_entries:
            url = entry.get('url', '')
            # Create a hash of the attack pattern (simplified)
            pattern_hash = hashlib.md5(
                re.sub(r'\d+', 'NUM', url).encode()
            ).hexdigest()[:8]
            payload_groups[pattern_hash].append(entry)
        
        distributed_attacks = []
        
        for pattern_hash, entries in payload_groups.items():
            if len(entries) < 3:  # Need multiple requests
                continue
            
            # Check if from different IPs
            unique_ips = set(entry.get('ip', '') for entry in entries)
            if len(unique_ips) >= 2:  # Distributed attack
                distributed_attacks.append({
                    'pattern_hash': pattern_hash,
                    'unique_ips': len(unique_ips),
                    'total_requests': len(entries),
                    'ips': list(unique_ips),
                    'sample_payload': entries[0].get('url', ''),
                    'time_range': self._get_time_range(entries),
                    'severity': 'high' if len(unique_ips) > 5 else 'medium'
                })
        
        return distributed_attacks
    
    def _get_time_range(self, entries: List[Dict]) -> str:
        """Get time range for entries."""
        if not entries:
            return "Unknown"
        
        timestamps = [entry.get('timestamp', '') for entry in entries]
        return f"From {min(timestamps)} to {max(timestamps)}"

class BehavioralAnalyzer:
    """Analyze behavioral patterns in attacks."""
    
    def __init__(self):
        self.user_agent_patterns = {
            'bot': ['bot', 'crawler', 'spider', 'scraper'],
            'scanner': ['sqlmap', 'nikto', 'nmap', 'burp', 'zap'],
            'legitimate': ['mozilla', 'chrome', 'firefox', 'safari', 'edge']
        }
    
    def analyze_user_behavior(self, log_entries: List[Dict]) -> Dict:
        """Analyze user behavior patterns."""
        ip_behavior = defaultdict(lambda: {
            'request_count': 0,
            'unique_urls': set(),
            'user_agents': set(),
            'methods': set(),
            'status_codes': set(),
            'attack_types': set(),
            'time_pattern': [],
            'behavior_score': 0.0
        })
        
        # Analyze each entry
        for entry in log_entries:
            ip = entry.get('ip', '')
            behavior = ip_behavior[ip]
            
            behavior['request_count'] += 1
            behavior['unique_urls'].add(entry.get('url', ''))
            behavior['user_agents'].add(entry.get('user_agent', ''))
            behavior['methods'].add(entry.get('method', ''))
            behavior['status_codes'].add(entry.get('status', ''))
            behavior['time_pattern'].append(entry.get('timestamp', ''))
        
        # Calculate behavior scores
        for ip, behavior in ip_behavior.items():
            behavior['behavior_score'] = self._calculate_behavior_score(behavior)
            behavior['classification'] = self._classify_behavior(behavior)
            
            # Convert sets to lists for JSON serialization
            behavior['unique_urls'] = list(behavior['unique_urls'])[:10]  # Limit for performance
            behavior['user_agents'] = list(behavior['user_agents'])
            behavior['methods'] = list(behavior['methods'])
            behavior['status_codes'] = list(behavior['status_codes'])
        
        return dict(ip_behavior)
    
    def _calculate_behavior_score(self, behavior: Dict) -> float:
        """Calculate suspicious behavior score (0-1)."""
        score = 0.0
        
        # High request frequency
        if behavior['request_count'] > 100:
            score += 0.3
        elif behavior['request_count'] > 50:
            score += 0.2
        
        # Multiple user agents (suspicious)
        if len(behavior['user_agents']) > 3:
            score += 0.2
        
        # Scanner user agents
        for ua in behavior['user_agents']:
            if any(scanner in ua.lower() for scanner in self.user_agent_patterns['scanner']):
                score += 0.3
                break
        
        # High error rate
        error_codes = [code for code in behavior['status_codes'] if code.startswith(('4', '5'))]
        if len(error_codes) / len(behavior['status_codes']) > 0.5:
            score += 0.2
        
        return min(score, 1.0)
    
    def _classify_behavior(self, behavior: Dict) -> str:
        """Classify behavior type."""
        score = behavior['behavior_score']
        
        if score > 0.7:
            return 'highly_suspicious'
        elif score > 0.4:
            return 'suspicious'
        elif score > 0.2:
            return 'potentially_suspicious'
        else:
            return 'normal'