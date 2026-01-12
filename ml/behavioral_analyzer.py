#!/usr/bin/env python3
"""
Behavioral Analyzer for detecting subtle attack patterns
Focuses on behavioral anomalies rather than payload-based detection
"""

from typing import Dict, List, Any, Tuple
from collections import defaultdict, Counter
from datetime import datetime
import re

class BehavioralAnalyzer:
    """Analyzes behavioral patterns to detect subtle attacks."""
    
    def __init__(self):
        self.ip_behavior = defaultdict(list)
        self.request_patterns = []
        self.time_windows = defaultdict(list)
    
    def analyze_request_sequence(self, log_entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyze sequence of requests for behavioral anomalies."""
        anomalies = []
        
        # Group requests by IP
        ip_requests = defaultdict(list)
        for entry in log_entries:
            ip = entry.get('ip', '')
            if ip:
                ip_requests[ip].append(entry)
        
        # Analyze each IP's behavior
        for ip, requests in ip_requests.items():
            ip_anomalies = self._analyze_ip_behavior(ip, requests)
            anomalies.extend(ip_anomalies)
        
        # Analyze cross-IP patterns
        cross_ip_anomalies = self._analyze_cross_ip_patterns(log_entries)
        anomalies.extend(cross_ip_anomalies)
        
        return anomalies
    
    def _analyze_ip_behavior(self, ip: str, requests: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyze behavior patterns for a specific IP."""
        anomalies = []
        
        if len(requests) < 1:
            return anomalies
        
        # Sort requests by timestamp
        sorted_requests = sorted(requests, key=lambda x: x.get('timestamp', ''))
        
        # Detect rapid sequential requests (for multiple requests)
        if len(requests) >= 2:
            rapid_sequence = self._detect_rapid_sequence(ip, sorted_requests)
            if rapid_sequence:
                anomalies.append(rapid_sequence)
            
            # Detect parameter enumeration
            param_enum = self._detect_parameter_enumeration(ip, sorted_requests)
            if param_enum:
                anomalies.append(param_enum)
            
            # Detect time-based patterns
            time_pattern = self._detect_time_based_automation(ip, sorted_requests)
            if time_pattern:
                anomalies.append(time_pattern)
        
        # Analyze individual requests for suspicious patterns
        for request in requests:
            # Detect unusual HTTP methods
            method_anomaly = self._detect_unusual_method(ip, request)
            if method_anomaly:
                anomalies.append(method_anomaly)
            
            # Detect buffer overflow attempts
            buffer_anomaly = self._detect_buffer_overflow_attempt(ip, request)
            if buffer_anomaly:
                anomalies.append(buffer_anomaly)
            
            # Detect internal API access
            api_anomaly = self._detect_internal_api_access(ip, request)
            if api_anomaly:
                anomalies.append(api_anomaly)
            
            # Detect parameter pollution
            pollution_anomaly = self._detect_parameter_pollution(ip, request)
            if pollution_anomaly:
                anomalies.append(pollution_anomaly)
        
        # Detect unusual request progression for multiple requests
        if len(requests) >= 3:
            progression = self._detect_unusual_progression(ip, sorted_requests)
            if progression:
                anomalies.append(progression)
        
        return anomalies
    
    def _detect_rapid_sequence(self, ip: str, requests: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Detect rapid sequential requests with minimal variation."""
        if len(requests) < 3:
            return None
        
        # Check for requests within same timestamp (indicating rapid fire)
        timestamp_groups = defaultdict(list)
        for req in requests:
            timestamp_groups[req.get('timestamp', '')].append(req)
        
        # Find groups with multiple requests at same timestamp
        rapid_groups = {ts: reqs for ts, reqs in timestamp_groups.items() if len(reqs) > 1}
        
        if rapid_groups:
            total_rapid = sum(len(reqs) for reqs in rapid_groups.values())
            
            # Analyze the pattern
            urls = [req.get('url', '') for reqs in rapid_groups.values() for req in reqs]
            url_similarity = self._calculate_url_similarity(urls)
            
            if url_similarity > 0.8:  # High similarity indicates automation
                return {
                    'type': 'rapid_sequential_requests',
                    'ip': ip,
                    'description': f'Rapid sequential requests with high similarity',
                    'evidence': {
                        'rapid_request_count': total_rapid,
                        'url_similarity': url_similarity,
                        'sample_urls': urls[:3],
                        'timestamps': list(rapid_groups.keys())
                    },
                    'severity': 'medium',
                    'confidence': min(0.9, url_similarity + 0.1)
                }
        
        return None
    
    def _detect_parameter_enumeration(self, ip: str, requests: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Detect parameter enumeration attacks."""
        if len(requests) < 3:
            return None
        
        # Look for requests with similar base URLs but different parameters
        base_urls = []
        param_patterns = []
        
        for req in requests:
            url = req.get('url', '')
            if '?' in url:
                base_url, params = url.split('?', 1)
                base_urls.append(base_url)
                param_patterns.append(params)
            else:
                base_urls.append(url)
                param_patterns.append('')
        
        # Check if same base URL with different parameters
        base_url_counts = Counter(base_urls)
        most_common_base = base_url_counts.most_common(1)
        
        if most_common_base and most_common_base[0][1] >= 3:
            # Same base URL accessed multiple times
            base_url = most_common_base[0][0]
            
            # Analyze parameter patterns
            relevant_params = [param_patterns[i] for i, url in enumerate(base_urls) if url == base_url]
            
            # Check for enumeration patterns (single character differences, sequential values)
            if self._is_parameter_enumeration(relevant_params):
                return {
                    'type': 'parameter_enumeration',
                    'ip': ip,
                    'description': f'Parameter enumeration detected on {base_url}',
                    'evidence': {
                        'base_url': base_url,
                        'request_count': most_common_base[0][1],
                        'parameter_patterns': relevant_params[:5],  # Show first 5
                        'enumeration_type': self._classify_enumeration_type(relevant_params)
                    },
                    'severity': 'high',
                    'confidence': 0.85
                }
        
        return None
    
    def _detect_time_based_automation(self, ip: str, requests: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Detect time-based automation patterns."""
        if len(requests) < 4:
            return None
        
        # Extract timestamps and calculate intervals
        timestamps = []
        for req in requests:
            ts = req.get('timestamp', '')
            # Try to extract time components
            if ':' in ts:
                try:
                    # Extract time part from Apache log format
                    time_part = ts.split(':')[1:4]  # hour:minute:second
                    if len(time_part) >= 3:
                        hour = int(time_part[0])
                        minute = int(time_part[1])
                        second = int(time_part[2].split()[0])  # Remove timezone
                        total_seconds = hour * 3600 + minute * 60 + second
                        timestamps.append(total_seconds)
                except (ValueError, IndexError):
                    continue
        
        if len(timestamps) < 4:
            return None
        
        # Calculate intervals between requests
        intervals = []
        for i in range(1, len(timestamps)):
            interval = timestamps[i] - timestamps[i-1]
            intervals.append(interval)
        
        # Check for regular intervals (indicating automation)
        if len(set(intervals)) == 1 and intervals[0] > 0:
            # Perfectly regular intervals
            return {
                'type': 'time_based_automation',
                'ip': ip,
                'description': f'Regular time intervals detected ({intervals[0]} seconds)',
                'evidence': {
                    'interval_seconds': intervals[0],
                    'request_count': len(requests),
                    'regularity': 'perfect',
                    'automation_confidence': 0.95
                },
                'severity': 'medium',
                'confidence': 0.95
            }
        
        # Check for mostly regular intervals (allowing some variation)
        interval_counts = Counter(intervals)
        most_common_interval = interval_counts.most_common(1)[0]
        
        if most_common_interval[1] >= len(intervals) * 0.7:  # 70% of intervals are the same
            return {
                'type': 'time_based_automation',
                'ip': ip,
                'description': f'Semi-regular time intervals detected',
                'evidence': {
                    'primary_interval': most_common_interval[0],
                    'interval_frequency': most_common_interval[1],
                    'total_intervals': len(intervals),
                    'regularity': 'semi-regular',
                    'automation_confidence': 0.7
                },
                'severity': 'low',
                'confidence': 0.7
            }
        
        return None
    
    def _detect_unusual_progression(self, ip: str, requests: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Detect unusual request progression patterns."""
        if len(requests) < 3:
            return None
        
        # Analyze URL progression
        urls = [req.get('url', '') for req in requests]
        methods = [req.get('method', '') for req in requests]
        
        # Check for unusual method usage
        unusual_methods = ['TRACE', 'TRACK', 'CONNECT', 'DEBUG']
        unusual_method_count = sum(1 for method in methods if method in unusual_methods)
        
        if unusual_method_count > 0:
            return {
                'type': 'unusual_method_usage',
                'ip': ip,
                'description': f'Unusual HTTP methods detected',
                'evidence': {
                    'unusual_methods': [m for m in methods if m in unusual_methods],
                    'total_requests': len(requests),
                    'unusual_ratio': unusual_method_count / len(requests),
                    'sample_requests': [(methods[i], urls[i]) for i in range(min(3, len(requests)))]
                },
                'severity': 'medium',
                'confidence': 0.8
            }
        
        return None
    
    def _analyze_cross_ip_patterns(self, log_entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyze patterns across different IPs."""
        anomalies = []
        
        # Group by URL patterns
        url_patterns = defaultdict(list)
        for entry in log_entries:
            url = entry.get('url', '')
            # Normalize URL for pattern matching
            normalized = self._normalize_url_pattern(url)
            url_patterns[normalized].append(entry)
        
        # Look for coordinated attacks (same pattern from multiple IPs)
        for pattern, entries in url_patterns.items():
            if len(entries) >= 3:  # At least 3 requests
                ips = set(entry.get('ip', '') for entry in entries)
                if len(ips) > 1:  # Multiple IPs
                    # Check if it's a coordinated attack pattern
                    coordinated = self._detect_coordinated_attack(pattern, entries)
                    if coordinated:
                        anomalies.append(coordinated)
        
        return anomalies
    
    def _calculate_url_similarity(self, urls: List[str]) -> float:
        """Calculate similarity between URLs."""
        if len(urls) < 2:
            return 0.0
        
        # Simple similarity based on common structure
        base_structures = []
        for url in urls:
            # Extract structure (replace variable parts)
            structure = re.sub(r'[?&][^=]+=([^&]*)', r'?param=VAR', url)
            structure = re.sub(r'/\d+', r'/NUM', structure)
            base_structures.append(structure)
        
        # Calculate how many have the same structure
        structure_counts = Counter(base_structures)
        most_common = structure_counts.most_common(1)[0][1]
        
        return most_common / len(urls)
    
    def _is_parameter_enumeration(self, param_patterns: List[str]) -> bool:
        """Check if parameter patterns indicate enumeration."""
        if len(param_patterns) < 3:
            return False
        
        # Check for single character enumeration (a, b, c)
        single_char_values = []
        for pattern in param_patterns:
            if '=' in pattern:
                value = pattern.split('=')[-1]
                if len(value) == 1 and value.isalpha():
                    single_char_values.append(value)
        
        if len(single_char_values) >= 3:
            # Check if they're sequential
            sorted_chars = sorted(single_char_values)
            sequential = all(ord(sorted_chars[i+1]) == ord(sorted_chars[i]) + 1 
                           for i in range(len(sorted_chars)-1))
            if sequential:
                return True
        
        # Check for numeric enumeration
        numeric_values = []
        for pattern in param_patterns:
            if '=' in pattern:
                value = pattern.split('=')[-1]
                if value.isdigit():
                    numeric_values.append(int(value))
        
        if len(numeric_values) >= 3:
            sorted_nums = sorted(numeric_values)
            sequential = all(sorted_nums[i+1] == sorted_nums[i] + 1 
                           for i in range(len(sorted_nums)-1))
            if sequential:
                return True
        
        return False
    
    def _classify_enumeration_type(self, param_patterns: List[str]) -> str:
        """Classify the type of parameter enumeration."""
        # Check for alphabetical enumeration
        if any(len(p.split('=')[-1]) == 1 and p.split('=')[-1].isalpha() 
               for p in param_patterns if '=' in p):
            return 'alphabetical'
        
        # Check for numeric enumeration
        if any(p.split('=')[-1].isdigit() for p in param_patterns if '=' in p):
            return 'numeric'
        
        # Check for parameter pollution
        param_names = [p.split('=')[0] for p in param_patterns if '=' in p]
        if len(set(param_names)) < len(param_names):
            return 'parameter_pollution'
        
        return 'unknown'
    
    def _normalize_url_pattern(self, url: str) -> str:
        """Normalize URL for pattern matching."""
        # Replace variable parts with placeholders
        normalized = re.sub(r'\d+', 'NUM', url)
        normalized = re.sub(r'[a-f0-9]{32}', 'HASH', normalized)
        normalized = re.sub(r'[?&][^=]+=([^&]*)', r'?param=VAR', normalized)
        return normalized
    
    def _detect_coordinated_attack(self, pattern: str, entries: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Detect coordinated attacks across multiple IPs."""
        ips = list(set(entry.get('ip', '') for entry in entries))
        
        if len(ips) < 2:
            return None
        
        # Check timing - coordinated attacks often happen in short time windows
        timestamps = [entry.get('timestamp', '') for entry in entries]
        unique_timestamps = set(timestamps)
        
        # If multiple IPs hit the same pattern in a short time window
        if len(unique_timestamps) <= 3 and len(ips) >= 2:
            return {
                'type': 'coordinated_attack',
                'description': f'Coordinated attack pattern detected',
                'evidence': {
                    'pattern': pattern,
                    'participating_ips': ips,
                    'request_count': len(entries),
                    'time_window': len(unique_timestamps),
                    'coordination_score': len(ips) / len(unique_timestamps)
                },
                'severity': 'high',
                'confidence': 0.8
            }
        
        return None
    
    def _detect_unusual_method(self, ip: str, request: Dict[str, Any]) -> Dict[str, Any]:
        """Detect unusual HTTP methods like TRACE."""
        method = request.get('method', '')
        url = request.get('url', '')
        
        unusual_methods = ['TRACE', 'TRACK', 'CONNECT', 'DEBUG']
        
        if method in unusual_methods:
            return {
                'type': 'unusual_http_method',
                'ip': ip,
                'description': f'Unusual HTTP method {method} detected',
                'evidence': {
                    'method': method,
                    'url': url,
                    'risk_level': 'high' if method in ['TRACE', 'TRACK'] else 'medium',
                    'common_attack_vector': method == 'TRACE'
                },
                'severity': 'high' if method in ['TRACE', 'TRACK'] else 'medium',
                'confidence': 0.9
            }
        
        return None
    
    def _detect_buffer_overflow_attempt(self, ip: str, request: Dict[str, Any]) -> Dict[str, Any]:
        """Detect buffer overflow attempts (long repeated characters)."""
        url = request.get('url', '')
        
        # Look for long sequences of repeated characters
        repeated_sequences = []
        i = 0
        while i < len(url):
            if i + 10 <= len(url):  # Look for sequences of at least 10 characters
                char = url[i]
                sequence_length = 1
                
                # Count consecutive identical characters
                j = i + 1
                while j < len(url) and url[j] == char:
                    sequence_length += 1
                    j += 1
                
                if sequence_length >= 10:  # Found a long sequence
                    repeated_sequences.append({
                        'character': char,
                        'length': sequence_length,
                        'position': i
                    })
                    i = j
                else:
                    i += 1
            else:
                break
        
        if repeated_sequences:
            # Check if it's likely a buffer overflow attempt
            total_repeated = sum(seq['length'] for seq in repeated_sequences)
            if total_repeated >= 20:  # Significant amount of repeated characters
                return {
                    'type': 'buffer_overflow_attempt',
                    'ip': ip,
                    'description': f'Potential buffer overflow attempt detected',
                    'evidence': {
                        'url': url,
                        'repeated_sequences': repeated_sequences,
                        'total_repeated_chars': total_repeated,
                        'url_length': len(url),
                        'repetition_ratio': total_repeated / len(url)
                    },
                    'severity': 'high',
                    'confidence': 0.8
                }
        
        return None
    
    def _detect_internal_api_access(self, ip: str, request: Dict[str, Any]) -> Dict[str, Any]:
        """Detect access to internal/admin API endpoints."""
        url = request.get('url', '').lower()
        method = request.get('method', '')
        
        # Internal API patterns
        internal_patterns = [
            ('internal', r'/api/.*internal'),
            ('admin_api', r'/api/.*admin'),
            ('private_api', r'/api/.*private'),
            ('internal_path', r'/internal/'),
            ('admin_path', r'/admin/api'),
            ('management', r'/management/'),
            ('debug_api', r'/_api/'),
            ('debug_path', r'/debug/'),
            ('test_path', r'/test/'),
            ('v2_internal', r'/api/v\d+/internal')
        ]
        
        for pattern_name, pattern in internal_patterns:
            if re.search(pattern, url):
                return {
                    'type': 'internal_api_access',
                    'ip': ip,
                    'description': f'Access to internal API endpoint detected',
                    'evidence': {
                        'url': request.get('url', ''),
                        'method': method,
                        'pattern_matched': pattern_name,
                        'pattern_regex': pattern,
                        'risk_assessment': 'high' if 'internal' in pattern_name or 'admin' in pattern_name else 'medium'
                    },
                    'severity': 'high',
                    'confidence': 0.85
                }
        
        return None
    
    def _detect_parameter_pollution(self, ip: str, request: Dict[str, Any]) -> Dict[str, Any]:
        """Detect parameter pollution attacks."""
        url = request.get('url', '')
        
        if '?' not in url:
            return None
        
        query_part = url.split('?', 1)[1]
        params = query_part.split('&')
        
        # Count parameter names
        param_names = []
        param_values = []
        
        for param in params:
            if '=' in param:
                name, value = param.split('=', 1)
                param_names.append(name)
                param_values.append(value)
        
        # Check for parameter pollution (same parameter multiple times)
        param_counts = Counter(param_names)
        polluted_params = {name: count for name, count in param_counts.items() if count > 1}
        
        if polluted_params:
            max_pollution = max(polluted_params.values())
            return {
                'type': 'parameter_pollution',
                'ip': ip,
                'description': f'Parameter pollution attack detected',
                'evidence': {
                    'url': url,
                    'polluted_parameters': polluted_params,
                    'max_repetitions': max_pollution,
                    'total_params': len(params),
                    'unique_params': len(set(param_names)),
                    'pollution_ratio': len(polluted_params) / len(set(param_names)) if param_names else 0
                },
                'severity': 'medium',
                'confidence': 0.8
            }
        
        return None