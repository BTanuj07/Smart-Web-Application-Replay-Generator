#!/usr/bin/env python3
"""
AI-Powered Threat Analyzer using External AI APIs
Progressive learning system for unknown attack pattern classification
"""

import json
import hashlib
import requests
from typing import Dict, List, Any, Optional
from datetime import datetime
import logging
import os

class AIThreatAnalyzer:
    """AI-powered threat analysis using external APIs for progressive learning."""
    
    def __init__(self, db_manager=None):
        self.db_manager = db_manager
        self.api_configs = {
            'groq': {
                'url': 'https://api.groq.com/openai/v1/chat/completions',
                'headers': {
                    'Authorization': f'groq api-key here',
                    'Content-Type': 'application/json'
                }
            },
            'openai': {
                'url': 'https://api.openai.com/v1/chat/completions',
                'headers': {
                    'Authorization': f'Bearer {os.getenv("OPENAI_API_KEY", "")}',
                    'Content-Type': 'application/json'
                }
            },
            'huggingface': {
                'url': 'https://api-inference.huggingface.co/models/microsoft/DialoGPT-medium',
                'headers': {
                    'Authorization': f'Bearer {os.getenv("HUGGINGFACE_API_KEY", "")}',
                    'Content-Type': 'application/json'
                }
            },
            'local_llm': {
                'url': 'http://localhost:11434/api/generate',  # Ollama local LLM
                'headers': {'Content-Type': 'application/json'}
            }
        }
        
        # Threat classification prompts (sanitized for AI content policies)
        self.classification_prompt = """
Analyze this web server access pattern for security anomalies:

Request Path: {sanitized_url}
HTTP Method: {method}
Client Type: {client_type}
Response Code: {status}

Evaluate for:
- Unusual parameter patterns
- Suspicious character sequences
- Automated tool signatures
- Path traversal indicators
- Injection attempt patterns

Respond with JSON:
{{
    "threat_level": "normal|suspicious|high_risk",
    "confidence": 0.0-1.0,
    "pattern_type": "description or 'standard'",
    "analysis": "brief technical assessment",
    "indicators": ["technical", "indicators"],
    "risk_level": "low|medium|high|critical"
}}
"""
    
    def analyze_unknown_pattern(self, log_entry: Dict[str, Any], 
                               occurrence_count: int = 1) -> Dict[str, Any]:
        """
        Analyze unknown pattern using Groq AI with simplified learning.
        
        Args:
            log_entry: The log entry to analyze
            occurrence_count: How many times this pattern has been seen (for compatibility)
            
        Returns:
            AI analysis results with threat classification
        """
        
        # Create pattern signature for tracking
        pattern_signature = self._create_pattern_signature(log_entry)
        
        # Check if we've seen this pattern before and it was malicious or suspicious
        previous_analysis = self._get_previous_analysis(pattern_signature)
        
        if previous_analysis and previous_analysis.get('threat_level') in ['malicious', 'suspicious']:
            # Pattern already identified as threat - return immediately
            previous_analysis['from_database'] = True
            previous_analysis['analysis_timestamp'] = datetime.now().isoformat()
            return previous_analysis
        
        # Analyze with Groq AI
        ai_analysis = self._analyze_with_ai(log_entry)
        
        # Store analysis in database if malicious or suspicious
        if self.db_manager and ai_analysis and ai_analysis.get('threat_level') in ['malicious', 'suspicious']:
            self._store_ai_analysis(pattern_signature, log_entry, ai_analysis, 1)
        
        return ai_analysis
    
    def _sanitize_for_ai(self, log_entry: Dict[str, Any]) -> Dict[str, str]:
        """Sanitize log entry for AI analysis to avoid content policy issues."""
        
        url = log_entry.get('url', '')
        user_agent = log_entry.get('user_agent', '')
        
        # Sanitize URL by replacing potentially problematic content
        sanitized_url = url
        
        # Replace common attack patterns with neutral descriptions
        replacements = {
            'union': 'UNION_KEYWORD',
            'select': 'SELECT_KEYWORD', 
            'drop': 'DROP_KEYWORD',
            'insert': 'INSERT_KEYWORD',
            'script': 'SCRIPT_TAG',
            'alert': 'ALERT_FUNCTION',
            'eval': 'EVAL_FUNCTION',
            'javascript:': 'JS_PROTOCOL',
            '../': 'PARENT_DIR',
            '%2e%2e': 'ENCODED_PARENT',
            'passwd': 'SYSTEM_FILE',
            'shadow': 'SYSTEM_FILE',
            'cmd=': 'COMMAND_PARAM',
            'exec=': 'EXEC_PARAM',
            'system=': 'SYSTEM_PARAM',
            '\'': 'QUOTE_CHAR',
            '"': 'QUOTE_CHAR',
            '<': 'LT_BRACKET',
            '>': 'GT_BRACKET',
            '--': 'SQL_COMMENT'
        }
        
        for pattern, replacement in replacements.items():
            sanitized_url = sanitized_url.replace(pattern, replacement)
        
        # Categorize user agent
        client_type = self._categorize_user_agent(user_agent)
        
        return {
            'sanitized_url': sanitized_url[:200],  # Limit length
            'client_type': client_type,
            'method': log_entry.get('method', 'GET'),
            'status': log_entry.get('status', '200')
        }
    def _analyze_with_ai(self, log_entry: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze log entry using AI API with sanitized content."""
        
        # Sanitize the log entry for AI analysis
        sanitized_data = self._sanitize_for_ai(log_entry)
        
        # Prepare the sanitized prompt
        prompt = self.classification_prompt.format(
            sanitized_url=sanitized_data['sanitized_url'],
            method=sanitized_data['method'],
            client_type=sanitized_data['client_type'],
            status=sanitized_data['status']
        )
        
        # Try Groq AI first (primary provider)
        ai_providers = ['groq']
        
        for provider in ai_providers:
            try:
                result = self._call_ai_api(provider, prompt)
                if result:
                    # Convert sanitized response back to standard format
                    ai_analysis = self._convert_sanitized_response(result, log_entry)
                    ai_analysis['ai_provider'] = provider
                    ai_analysis['analysis_timestamp'] = datetime.now().isoformat()
                    return ai_analysis
            except Exception as e:
                logging.warning(f"AI provider {provider} failed: {e}")
                continue
        
        # Fallback to rule-based analysis if Groq AI fails
        return self._fallback_analysis(log_entry)
    
    def _call_ai_api(self, provider: str, prompt: str) -> Optional[Dict[str, Any]]:
        """Call specific AI API provider."""
        
        config = self.api_configs.get(provider)
        if not config:
            return None
        
        try:
            if provider == 'groq':
                payload = {
                    "model": "llama-3.1-8b-instant",  # Current Groq model
                    "messages": [
                        {"role": "system", "content": "You are a web security analyst. Analyze sanitized web request patterns for anomalies. Respond with JSON only."},
                        {"role": "user", "content": prompt}
                    ],
                    "max_tokens": 300,
                    "temperature": 0.1,
                    "top_p": 1,
                    "stream": False
                }
            elif provider == 'openai':
                payload = {
                    "model": "gpt-3.5-turbo",
                    "messages": [
                        {"role": "system", "content": "You are a cybersecurity expert."},
                        {"role": "user", "content": prompt}
                    ],
                    "max_tokens": 500,
                    "temperature": 0.1
                }
                
            elif provider == 'local_llm':
                payload = {
                    "model": "llama2",  # or whatever model you have
                    "prompt": prompt,
                    "stream": False
                }
                
            elif provider == 'huggingface':
                payload = {
                    "inputs": prompt,
                    "parameters": {
                        "max_length": 500,
                        "temperature": 0.1
                    }
                }
            
            response = requests.post(
                config['url'],
                headers=config['headers'],
                json=payload,
                timeout=30
            )
            
            if response.status_code == 200:
                return self._parse_ai_response(provider, response.json())
            else:
                logging.error(f"AI API {provider} returned status {response.status_code}: {response.text}")
                return None
                
        except Exception as e:
            logging.error(f"Error calling AI API {provider}: {e}")
            return None
    
    def _parse_ai_response(self, provider: str, response: Dict[str, Any]) -> Dict[str, Any]:
        """Parse AI API response to extract threat analysis."""
        
        try:
            if provider == 'groq' or provider == 'openai':
                content = response['choices'][0]['message']['content']
            elif provider == 'local_llm':
                content = response['response']
            elif provider == 'huggingface':
                content = response[0]['generated_text'] if isinstance(response, list) else response['generated_text']
            else:
                return None
            
            # Try to extract JSON from the response
            import re
            json_match = re.search(r'\{.*\}', content, re.DOTALL)
            if json_match:
                json_str = json_match.group(0)
                return json.loads(json_str)
            else:
                # Fallback parsing if JSON not found
                return self._parse_text_response(content)
                
        except Exception as e:
            logging.error(f"Error parsing AI response from {provider}: {e}")
            return None
    
    def _convert_sanitized_response(self, ai_response: Dict[str, Any], 
                                   original_log: Dict[str, Any]) -> Dict[str, Any]:
        """Convert sanitized AI response back to standard format."""
        
        # Map sanitized terms back to standard security terminology
        threat_level_map = {
            'normal': 'benign',
            'suspicious': 'suspicious', 
            'high_risk': 'malicious'
        }
        
        # Convert response
        converted = {
            'threat_level': threat_level_map.get(ai_response.get('threat_level', 'normal'), 'benign'),
            'confidence': ai_response.get('confidence', 0.5),
            'attack_type': ai_response.get('pattern_type', 'unknown'),
            'reasoning': ai_response.get('analysis', 'AI analysis completed'),
            'indicators': ai_response.get('indicators', []),
            'severity': ai_response.get('risk_level', 'low'),
            'ai_provider': 'groq'
        }
        
        # Enhance attack type based on original URL patterns
        original_url = original_log.get('url', '').lower()
        if 'union' in original_url or 'select' in original_url:
            converted['attack_type'] = 'SQL Injection Attempt'
        elif 'script' in original_url or 'alert' in original_url:
            converted['attack_type'] = 'XSS Attempt'
        elif '../' in original_url or '%2e%2e' in original_url:
            converted['attack_type'] = 'Directory Traversal'
        elif 'cmd=' in original_url or 'exec=' in original_url:
            converted['attack_type'] = 'Command Injection Attempt'
        
        return converted
        """Parse non-JSON AI response."""
        
        # Simple text parsing fallback
        content_lower = content.lower()
        
        if 'malicious' in content_lower:
            threat_level = 'malicious'
            severity = 'high'
        elif 'suspicious' in content_lower:
            threat_level = 'suspicious'
            severity = 'medium'
        else:
            threat_level = 'benign'
            severity = 'low'
        
        return {
            'threat_level': threat_level,
            'confidence': 0.7,
            'attack_type': 'unknown',
            'reasoning': content[:200],
            'indicators': [],
            'severity': severity
        }
    
    def _fallback_analysis(self, log_entry: Dict[str, Any]) -> Dict[str, Any]:
        """Fallback rule-based analysis when AI is unavailable."""
        
        url = log_entry.get('url', '').lower()
        user_agent = log_entry.get('user_agent', '').lower()
        
        suspicious_indicators = []
        threat_level = 'benign'
        severity = 'low'
        
        # Check for suspicious patterns
        if len(url) > 200:
            suspicious_indicators.append('very_long_url')
        
        if any(char in url for char in ['<', '>', '"', "'"]):
            suspicious_indicators.append('html_characters')
        
        if 'script' in url or 'alert' in url:
            suspicious_indicators.append('xss_keywords')
        
        if any(word in url for word in ['union', 'select', 'drop', 'insert']):
            suspicious_indicators.append('sql_keywords')
        
        if any(tool in user_agent for tool in ['curl', 'wget', 'python', 'scanner', 'nikto']):
            suspicious_indicators.append('automated_tool')
        
        if '../' in url or '%2e%2e' in url:
            suspicious_indicators.append('directory_traversal')
        
        # Additional patterns for better detection
        if any(param in url for param in ['cmd=', 'exec=', 'system=', 'shell=']):
            suspicious_indicators.append('command_injection')
        
        if any(path in url for path in ['/etc/', '/passwd', '/shadow', '/admin', '/config']):
            suspicious_indicators.append('sensitive_path')
        
        if len(url) > 100:  # Lower threshold for long URLs
            suspicious_indicators.append('long_url')
        
        if url.count('=') > 3:  # Multiple parameters
            suspicious_indicators.append('parameter_pollution')
        
        # Determine threat level based on indicators (more sensitive)
        if len(suspicious_indicators) >= 2:  # Lower threshold
            threat_level = 'suspicious'
            severity = 'medium'
        if len(suspicious_indicators) >= 4:
            threat_level = 'malicious'
            severity = 'high'
        
        return {
            'threat_level': threat_level,
            'confidence': 0.6,
            'attack_type': 'rule_based_analysis',
            'reasoning': f'Rule-based analysis found {len(suspicious_indicators)} suspicious indicators',
            'indicators': suspicious_indicators,
            'severity': severity,
            'ai_provider': 'fallback_rules'
        }
    
    def _create_pattern_signature(self, log_entry: Dict[str, Any]) -> str:
        """Create a unique signature for pattern tracking."""
        
        # Normalize URL for pattern matching
        url = log_entry.get('url', '')
        method = log_entry.get('method', '')
        user_agent = log_entry.get('user_agent', '')
        
        # Create normalized pattern
        import re
        normalized_url = re.sub(r'\d+', 'NUM', url)
        normalized_url = re.sub(r'[a-f0-9]{32}', 'HASH32', normalized_url)
        normalized_url = re.sub(r'[a-f0-9]{40}', 'HASH40', normalized_url)
        
        # Create signature
        signature_data = f"{method}:{normalized_url}:{self._categorize_user_agent(user_agent)}"
        
        # Hash for consistent storage
        return hashlib.md5(signature_data.encode()).hexdigest()
    
    def _categorize_user_agent(self, user_agent: str) -> str:
        """Categorize user agent for pattern matching."""
        ua_lower = user_agent.lower()
        
        if any(browser in ua_lower for browser in ['mozilla', 'chrome', 'safari', 'firefox']):
            return 'BROWSER'
        elif any(bot in ua_lower for bot in ['bot', 'crawler', 'spider']):
            return 'BOT'
        elif any(tool in ua_lower for tool in ['curl', 'wget', 'python', 'java']):
            return 'TOOL'
        elif any(scanner in ua_lower for scanner in ['nmap', 'sqlmap', 'nikto', 'burp']):
            return 'SCANNER'
        else:
            return 'OTHER'
    
    def _get_previous_analysis(self, pattern_signature: str) -> Optional[Dict[str, Any]]:
        """Get previous AI analysis for this pattern."""
        
        if not self.db_manager:
            return None
        
        try:
            return self.db_manager.get_ai_analysis(pattern_signature)
        except Exception as e:
            logging.error(f"Error getting previous AI analysis: {e}")
            return None
    
    def _store_ai_analysis(self, pattern_signature: str, log_entry: Dict[str, Any], 
                          analysis: Dict[str, Any], occurrence_count: int):
        """Store AI analysis in database (simplified)."""
        
        try:
            self.db_manager.save_ai_analysis(
                pattern_signature=pattern_signature,
                log_entry=log_entry,
                analysis=analysis,
                occurrence_count=1  # Always 1 for simplified approach
            )
        except Exception as e:
            logging.error(f"Error storing AI analysis: {e}")
    
    def get_threat_statistics(self) -> Dict[str, Any]:
        """Get statistics about AI threat analysis."""
        
        if not self.db_manager:
            return {}
        
        try:
            return self.db_manager.get_ai_threat_statistics()
        except Exception as e:
            logging.error(f"Error getting threat statistics: {e}")
            return {}
    
    def get_escalated_threats(self, days: int = 7) -> List[Dict[str, Any]]:
        """Get threats that have been escalated in the last N days."""
        
        if not self.db_manager:
            return []
        
        try:
            return self.db_manager.get_escalated_threats(days)
        except Exception as e:
            logging.error(f"Error getting escalated threats: {e}")
            return []