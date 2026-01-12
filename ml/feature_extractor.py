#!/usr/bin/env python3
"""
Feature Extractor for Web Server Access Logs
Extracts numerical and categorical features for ML-based anomaly detection
"""

import re
import math
import hashlib
from urllib.parse import urlparse, parse_qs, unquote
from collections import Counter
import numpy as np
from typing import Dict, List, Any, Tuple

class LogFeatureExtractor:
    """Extract features from web server access logs for ML analysis."""
    
    def __init__(self):
        self.suspicious_keywords = [
            'script', 'alert', 'eval', 'document', 'window', 'onload', 'onerror',
            'union', 'select', 'insert', 'delete', 'drop', 'exec', 'xp_',
            '../', '..\\', '/etc/', '/proc/', '/sys/', 'passwd', 'shadow',
            'cmd', 'powershell', 'bash', 'sh', 'wget', 'curl', 'nc',
            'base64', 'decode', 'encode', 'chr', 'ord', 'hex'
        ]
        
        self.common_extensions = ['.html', '.php', '.asp', '.jsp', '.js', '.css', '.png', '.jpg', '.gif']
        self.common_methods = ['GET', 'POST', 'HEAD', 'PUT', 'DELETE', 'OPTIONS']
        
    def extract_features(self, log_entry: Dict[str, Any]) -> Dict[str, float]:
        """Extract comprehensive features from a single log entry."""
        features = {}
        
        # Basic request features
        features.update(self._extract_url_features(log_entry.get('url', '')))
        features.update(self._extract_method_features(log_entry.get('method', '')))
        features.update(self._extract_status_features(log_entry.get('status', 200)))
        features.update(self._extract_size_features(log_entry.get('size', 0)))
        features.update(self._extract_user_agent_features(log_entry.get('user_agent', '')))
        features.update(self._extract_referer_features(log_entry.get('referer', '')))
        features.update(self._extract_temporal_features(log_entry.get('timestamp', '')))
        
        # Advanced content analysis
        features.update(self._extract_payload_features(log_entry.get('url', '')))
        features.update(self._extract_encoding_features(log_entry.get('url', '')))
        features.update(self._extract_pattern_features(log_entry.get('url', '')))
        
        return features
    
    def _extract_url_features(self, url: str) -> Dict[str, float]:
        """Extract URL-based features."""
        features = {}
        
        # Basic URL metrics
        features['url_length'] = len(url)
        features['url_depth'] = url.count('/')
        features['query_params_count'] = url.count('&') + (1 if '?' in url else 0)
        
        # URL complexity
        features['url_entropy'] = self._calculate_entropy(url)
        features['url_digit_ratio'] = sum(c.isdigit() for c in url) / max(len(url), 1)
        features['url_special_char_ratio'] = sum(not c.isalnum() and c not in '/?&=.-_' for c in url) / max(len(url), 1)
        
        # Path analysis
        parsed = urlparse(url)
        path = parsed.path
        features['path_length'] = len(path)
        features['path_segments'] = path.count('/')
        
        # File extension
        extension = self._get_file_extension(path)
        features['has_common_extension'] = 1.0 if extension in self.common_extensions else 0.0
        features['has_executable_extension'] = 1.0 if extension in ['.exe', '.bat', '.sh', '.php', '.asp', '.jsp'] else 0.0
        
        # Query string analysis
        query = parsed.query
        features['query_length'] = len(query)
        features['query_entropy'] = self._calculate_entropy(query) if query else 0.0
        
        return features
    
    def _extract_method_features(self, method: str) -> Dict[str, float]:
        """Extract HTTP method features."""
        features = {}
        
        # Method type
        features['is_get'] = 1.0 if method == 'GET' else 0.0
        features['is_post'] = 1.0 if method == 'POST' else 0.0
        features['is_common_method'] = 1.0 if method in self.common_methods else 0.0
        features['is_dangerous_method'] = 1.0 if method in ['PUT', 'DELETE', 'PATCH'] else 0.0
        
        # NEW: Enhanced method analysis
        features.update(self._extract_advanced_method_features(method))
        
        return features
    
    def _extract_advanced_method_features(self, method: str) -> Dict[str, float]:
        """Extract advanced HTTP method features for attack detection."""
        features = {}
        
        # Unusual/suspicious methods
        unusual_methods = ['TRACE', 'TRACK', 'CONNECT', 'DEBUG']
        features['is_unusual_method'] = 1.0 if method in unusual_methods else 0.0
        
        # Specific method detection
        features['is_trace_method'] = 1.0 if method == 'TRACE' else 0.0
        features['is_options_method'] = 1.0 if method == 'OPTIONS' else 0.0
        features['is_head_method'] = 1.0 if method == 'HEAD' else 0.0
        
        # Method security risk level
        high_risk_methods = ['TRACE', 'TRACK', 'CONNECT', 'DEBUG', 'PUT', 'DELETE']
        medium_risk_methods = ['PATCH', 'OPTIONS']
        
        if method in high_risk_methods:
            features['method_risk_level'] = 3.0
        elif method in medium_risk_methods:
            features['method_risk_level'] = 2.0
        elif method in ['GET', 'POST', 'HEAD']:
            features['method_risk_level'] = 1.0
        else:
            features['method_risk_level'] = 2.5  # Unknown methods are medium-high risk
        
        return features
    
    def _extract_status_features(self, status: int) -> Dict[str, float]:
        """Extract HTTP status code features."""
        features = {}
        
        features['status_code'] = float(status)
        features['is_success'] = 1.0 if 200 <= status < 300 else 0.0
        features['is_redirect'] = 1.0 if 300 <= status < 400 else 0.0
        features['is_client_error'] = 1.0 if 400 <= status < 500 else 0.0
        features['is_server_error'] = 1.0 if 500 <= status < 600 else 0.0
        
        return features
    
    def _extract_size_features(self, size: int) -> Dict[str, float]:
        """Extract response size features."""
        features = {}
        
        features['response_size'] = float(size)
        features['response_size_log'] = math.log(max(size, 1))
        features['is_large_response'] = 1.0 if size > 10000 else 0.0
        features['is_empty_response'] = 1.0 if size == 0 else 0.0
        
        return features
    
    def _extract_user_agent_features(self, user_agent: str) -> Dict[str, float]:
        """Extract User-Agent features."""
        features = {}
        
        features['ua_length'] = len(user_agent)
        features['ua_entropy'] = self._calculate_entropy(user_agent)
        
        # Common browsers/tools
        ua_lower = user_agent.lower()
        features['is_browser'] = 1.0 if any(browser in ua_lower for browser in ['mozilla', 'chrome', 'safari', 'firefox']) else 0.0
        features['is_bot'] = 1.0 if any(bot in ua_lower for bot in ['bot', 'crawler', 'spider', 'scraper']) else 0.0
        features['is_tool'] = 1.0 if any(tool in ua_lower for tool in ['curl', 'wget', 'python', 'java', 'perl']) else 0.0
        features['is_scanner'] = 1.0 if any(scanner in ua_lower for scanner in ['nmap', 'sqlmap', 'nikto', 'burp', 'zap']) else 0.0
        
        # Suspicious patterns
        features['ua_has_version'] = 1.0 if re.search(r'\d+\.\d+', user_agent) else 0.0
        features['ua_is_empty'] = 1.0 if not user_agent or user_agent == '-' else 0.0
        
        return features
    
    def _extract_referer_features(self, referer: str) -> Dict[str, float]:
        """Extract Referer header features."""
        features = {}
        
        features['has_referer'] = 1.0 if referer and referer != '-' else 0.0
        features['referer_length'] = len(referer) if referer and referer != '-' else 0
        features['referer_entropy'] = self._calculate_entropy(referer) if referer and referer != '-' else 0.0
        
        return features
    
    def _extract_temporal_features(self, timestamp: str) -> Dict[str, float]:
        """Extract time-based features."""
        features = {}
        
        # For now, return basic features - could be enhanced with actual time parsing
        features['timestamp_length'] = len(timestamp)
        
        # NEW: Enhanced temporal analysis
        features.update(self._extract_advanced_temporal_features(timestamp))
        
        return features
    
    def _extract_advanced_temporal_features(self, timestamp: str) -> Dict[str, float]:
        """Extract advanced temporal features for attack detection."""
        features = {}
        
        # Parse timestamp if possible
        try:
            # Try to parse Apache log format: [19/Nov/2025:13:00:01 +0000]
            if '[' in timestamp and ']' in timestamp:
                time_part = timestamp.strip('[]')
                # Extract components
                if ':' in time_part:
                    date_part, time_part = time_part.split(':', 1)
                    time_components = time_part.split(':')
                    
                    if len(time_components) >= 3:
                        hour = int(time_components[0])
                        minute = int(time_components[1])
                        second = int(time_components[2].split()[0])  # Remove timezone
                        
                        # Time-based features
                        features['hour_of_day'] = float(hour)
                        features['minute_of_hour'] = float(minute)
                        features['second_of_minute'] = float(second)
                        
                        # Suspicious timing patterns
                        features['is_exact_minute'] = 1.0 if second == 0 else 0.0
                        features['is_exact_hour'] = 1.0 if minute == 0 and second == 0 else 0.0
                        features['is_off_hours'] = 1.0 if hour < 6 or hour > 22 else 0.0
                        
                        # Regular interval indicators (every minute, every 30 seconds, etc.)
                        features['regular_interval_indicator'] = self._calculate_interval_regularity(second, minute)
                    else:
                        # Fallback values
                        features.update(self._get_default_temporal_features())
                else:
                    features.update(self._get_default_temporal_features())
            else:
                features.update(self._get_default_temporal_features())
                
        except (ValueError, IndexError):
            # If parsing fails, use default values
            features.update(self._get_default_temporal_features())
        
        return features
    
    def _get_default_temporal_features(self) -> Dict[str, float]:
        """Get default temporal features when parsing fails."""
        return {
            'hour_of_day': 12.0,  # Default to noon
            'minute_of_hour': 30.0,
            'second_of_minute': 30.0,
            'is_exact_minute': 0.0,
            'is_exact_hour': 0.0,
            'is_off_hours': 0.0,
            'regular_interval_indicator': 0.0
        }
    
    def _calculate_interval_regularity(self, second: int, minute: int) -> float:
        """Calculate how regular the timing interval appears."""
        # Check for common automation intervals
        regular_patterns = [
            second == 0,  # Every minute
            second == 30,  # Every 30 seconds
            second in [0, 15, 30, 45],  # Every 15 seconds
            second in [0, 10, 20, 30, 40, 50],  # Every 10 seconds
            minute in [0, 15, 30, 45] and second == 0,  # Every 15 minutes
            minute == 0 and second == 0,  # Every hour
        ]
        
        return float(sum(regular_patterns)) / len(regular_patterns)
    
    def _extract_payload_features(self, url: str) -> Dict[str, float]:
        """Extract payload and content analysis features."""
        features = {}
        
        # Suspicious keyword detection
        url_decoded = unquote(url).lower()
        features['suspicious_keywords_count'] = sum(1 for keyword in self.suspicious_keywords if keyword in url_decoded)
        features['has_suspicious_keywords'] = 1.0 if features['suspicious_keywords_count'] > 0 else 0.0
        
        # SQL injection patterns
        sql_patterns = [
            r"union\s+select", r"or\s+1\s*=\s*1", r"and\s+1\s*=\s*1",
            r"'.*or.*'", r"'.*and.*'", r"--", r"/\*.*\*/"
        ]
        features['sql_pattern_count'] = sum(1 for pattern in sql_patterns if re.search(pattern, url_decoded))
        
        # XSS patterns
        xss_patterns = [
            r"<script", r"javascript:", r"onload\s*=", r"onerror\s*=",
            r"alert\s*\(", r"eval\s*\(", r"document\."
        ]
        features['xss_pattern_count'] = sum(1 for pattern in xss_patterns if re.search(pattern, url_decoded))
        
        # Path traversal patterns
        features['path_traversal_count'] = url_decoded.count('../') + url_decoded.count('..\\')
        
        # Command injection patterns
        cmd_patterns = [r";.*\w+", r"\|.*\w+", r"&&.*\w+", r"`.*`"]
        features['cmd_pattern_count'] = sum(1 for pattern in cmd_patterns if re.search(pattern, url_decoded))
        
        return features
    
    def _extract_encoding_features(self, url: str) -> Dict[str, float]:
        """Extract encoding and obfuscation features."""
        features = {}
        
        # URL encoding
        features['url_encoded_chars'] = url.count('%')
        features['double_encoded'] = 1.0 if '%25' in url else 0.0
        
        # Base64 patterns
        features['has_base64'] = 1.0 if re.search(r'[A-Za-z0-9+/]{20,}={0,2}', url) else 0.0
        
        # Hex encoding
        features['hex_encoded_chars'] = len(re.findall(r'%[0-9a-fA-F]{2}', url))
        
        # Unicode encoding
        features['unicode_chars'] = len(re.findall(r'\\u[0-9a-fA-F]{4}', url))
        
        return features
    
    def _extract_pattern_features(self, url: str) -> Dict[str, float]:
        """Extract pattern-based features for anomaly detection."""
        features = {}
        
        # Character distribution
        char_counts = Counter(url.lower())
        total_chars = len(url)
        
        if total_chars > 0:
            # Most common character frequency
            features['max_char_frequency'] = max(char_counts.values()) / total_chars
            
            # Character diversity (number of unique characters)
            features['char_diversity'] = len(char_counts) / max(total_chars, 1)
            
            # Repeated patterns
            features['repeated_patterns'] = self._count_repeated_patterns(url)
        else:
            features['max_char_frequency'] = 0.0
            features['char_diversity'] = 0.0
            features['repeated_patterns'] = 0.0
        
        # Randomness indicators
        features['has_random_string'] = 1.0 if self._has_random_string(url) else 0.0
        
        # NEW: Advanced attack pattern detection
        features.update(self._extract_advanced_attack_patterns(url))
        
        return features
    
    def _extract_advanced_attack_patterns(self, url: str) -> Dict[str, float]:
        """Extract advanced attack pattern features."""
        features = {}
        
        # Parameter pollution detection
        if '?' in url:
            query_part = url.split('?', 1)[1]
            params = query_part.split('&')
            param_names = [p.split('=')[0] for p in params if '=' in p]
            param_counts = Counter(param_names)
            
            # Detect parameter pollution (same parameter multiple times)
            features['param_pollution_count'] = sum(1 for count in param_counts.values() if count > 1)
            features['max_param_repetition'] = max(param_counts.values()) if param_counts else 0
            features['has_param_pollution'] = 1.0 if features['param_pollution_count'] > 0 else 0.0
        else:
            features['param_pollution_count'] = 0.0
            features['max_param_repetition'] = 0.0
            features['has_param_pollution'] = 0.0
        
        # Buffer overflow patterns
        features['has_long_param_value'] = 1.0 if self._has_long_param_value(url) else 0.0
        features['max_param_length'] = self._get_max_param_length(url)
        features['repeated_char_sequences'] = self._count_repeated_char_sequences(url)
        
        # API endpoint patterns
        features['is_internal_api'] = 1.0 if self._is_internal_api_pattern(url) else 0.0
        features['api_version_pattern'] = 1.0 if re.search(r'/v\d+/', url) else 0.0
        features['has_admin_path'] = 1.0 if any(admin in url.lower() for admin in ['admin', 'internal', 'private', 'management']) else 0.0
        
        # Automation indicators
        features['single_char_param'] = 1.0 if self._has_single_char_params(url) else 0.0
        features['sequential_pattern'] = self._detect_sequential_patterns(url)
        
        return features
    
    def _has_long_param_value(self, url: str, threshold: int = 30) -> bool:
        """Detect unusually long parameter values."""
        if '?' not in url:
            return False
        
        query_part = url.split('?', 1)[1]
        params = query_part.split('&')
        
        for param in params:
            if '=' in param:
                value = param.split('=', 1)[1]
                if len(value) > threshold:
                    return True
        
        return False
    
    def _get_max_param_length(self, url: str) -> float:
        """Get the maximum parameter value length."""
        if '?' not in url:
            return 0.0
        
        query_part = url.split('?', 1)[1]
        params = query_part.split('&')
        
        max_length = 0
        for param in params:
            if '=' in param:
                value = param.split('=', 1)[1]
                max_length = max(max_length, len(value))
        
        return float(max_length)
    
    def _count_repeated_char_sequences(self, url: str, min_length: int = 5) -> float:
        """Count repeated character sequences (like AAAAAAA)."""
        count = 0
        i = 0
        
        while i < len(url):
            if i + min_length <= len(url):
                char = url[i]
                sequence_length = 1
                
                # Count consecutive identical characters
                j = i + 1
                while j < len(url) and url[j] == char:
                    sequence_length += 1
                    j += 1
                
                if sequence_length >= min_length:
                    count += 1
                    i = j
                else:
                    i += 1
            else:
                break
        
        return float(count)
    
    def _is_internal_api_pattern(self, url: str) -> bool:
        """Detect internal API access patterns."""
        internal_patterns = [
            r'/api/.*internal',
            r'/api/.*admin',
            r'/api/.*private',
            r'/internal/',
            r'/admin/api',
            r'/management/',
            r'/_api/',
            r'/debug/',
            r'/test/'
        ]
        
        url_lower = url.lower()
        return any(re.search(pattern, url_lower) for pattern in internal_patterns)
    
    def _has_single_char_params(self, url: str) -> bool:
        """Detect single character parameter names/values (automation indicator)."""
        if '?' not in url:
            return False
        
        query_part = url.split('?', 1)[1]
        params = query_part.split('&')
        
        single_char_count = 0
        for param in params:
            if '=' in param:
                name, value = param.split('=', 1)
                if len(name) == 1 or len(value) == 1:
                    single_char_count += 1
        
        # If more than half the parameters are single character, it's suspicious
        return single_char_count > len(params) / 2 if params else False
    
    def _detect_sequential_patterns(self, url: str) -> float:
        """Detect sequential patterns in parameters (like a,b,c or 1,2,3)."""
        if '?' not in url:
            return 0.0
        
        query_part = url.split('?', 1)[1]
        params = query_part.split('&')
        
        values = []
        for param in params:
            if '=' in param:
                value = param.split('=', 1)[1]
                values.append(value)
        
        if len(values) < 2:
            return 0.0
        
        # Check for alphabetical sequence
        alpha_sequential = 0
        for i in range(len(values) - 1):
            if (len(values[i]) == 1 and len(values[i+1]) == 1 and 
                values[i].isalpha() and values[i+1].isalpha() and
                ord(values[i+1]) == ord(values[i]) + 1):
                alpha_sequential += 1
        
        # Check for numerical sequence
        num_sequential = 0
        for i in range(len(values) - 1):
            if (values[i].isdigit() and values[i+1].isdigit() and
                int(values[i+1]) == int(values[i]) + 1):
                num_sequential += 1
        
        # Return ratio of sequential patterns
        total_pairs = len(values) - 1
        return (alpha_sequential + num_sequential) / max(total_pairs, 1)
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text."""
        if not text:
            return 0.0
        
        char_counts = Counter(text)
        total_chars = len(text)
        
        entropy = 0.0
        for count in char_counts.values():
            probability = count / total_chars
            entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _get_file_extension(self, path: str) -> str:
        """Extract file extension from path."""
        if '.' in path:
            return '.' + path.split('.')[-1].lower()
        return ''
    
    def _count_repeated_patterns(self, text: str) -> float:
        """Count repeated patterns in text."""
        if len(text) < 4:
            return 0.0
        
        patterns = {}
        for i in range(len(text) - 3):
            pattern = text[i:i+4]
            patterns[pattern] = patterns.get(pattern, 0) + 1
        
        repeated = sum(1 for count in patterns.values() if count > 1)
        return repeated / max(len(patterns), 1)
    
    def _has_random_string(self, text: str) -> bool:
        """Detect if text contains random-looking strings."""
        # Look for strings with high entropy and mixed case/numbers
        words = re.findall(r'[a-zA-Z0-9]{8,}', text)
        
        for word in words:
            if (self._calculate_entropy(word) > 3.5 and 
                any(c.isupper() for c in word) and 
                any(c.islower() for c in word) and 
                any(c.isdigit() for c in word)):
                return True
        
        return False
    
    def extract_batch_features(self, log_entries: List[Dict[str, Any]]) -> np.ndarray:
        """Extract features for a batch of log entries."""
        feature_list = []
        
        for entry in log_entries:
            features = self.extract_features(entry)
            feature_list.append(list(features.values()))
        
        return np.array(feature_list)
    
    def get_feature_names(self) -> List[str]:
        """Get list of feature names in order."""
        # Extract features from a dummy entry to get feature names
        dummy_entry = {
            'url': '/test.php?id=1',
            'method': 'GET',
            'status': 200,
            'size': 1024,
            'user_agent': 'Mozilla/5.0',
            'referer': '-',
            'timestamp': '2024-01-01 12:00:00'
        }
        
        features = self.extract_features(dummy_entry)
        return list(features.keys())