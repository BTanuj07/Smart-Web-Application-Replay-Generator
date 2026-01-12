import re
from datetime import datetime
from typing import List, Dict, Optional
from urllib.parse import urlparse, parse_qs, unquote

class LogParser:
    def __init__(self):
        # More flexible Apache/Nginx patterns
        self.apache_pattern = re.compile(
            r'(?P<ip>[\d\.]+)\s+-\s+-\s+\[(?P<timestamp>[^\]]+)\]\s+'
            r'"(?P<method>\w+)\s+(?P<url>[^\s]+)\s+HTTP/[\d\.]+"\s+'
            r'(?P<status>\d+)\s+(?P<size>\d+|-)\s*'
            r'"(?P<referrer>[^"]*)"\s+"(?P<user_agent>[^"]*)"',
            re.IGNORECASE
        )
        
        # Alternative pattern for different formats
        self.flexible_pattern = re.compile(
            r'(?P<ip>[\d\.]+).*?\[(?P<timestamp>[^\]]+)\].*?'
            r'"(?P<method>\w+)\s+(?P<url>[^\s"]+).*?"\s+'
            r'(?P<status>\d+)\s+(?P<size>\d+|-)',
            re.IGNORECASE
        )

    def parse_log_file(self, log_content: str) -> List[Dict[str, str]]:
        parsed_logs = []
        
        # Handle different line endings and clean content
        log_content = log_content.replace('\r\n', '\n').replace('\r', '\n')
        lines = [line.strip() for line in log_content.strip().split('\n') if line.strip()]
        
        for line_num, line in enumerate(lines, 1):
            if not line or line.startswith('#'):  # Skip empty lines and comments
                continue
            
            parsed_entry = self._parse_line(line)
            if parsed_entry:
                parsed_entry['line_number'] = line_num
                parsed_logs.append(parsed_entry)
            else:
                # Debug: print failed lines
                print(f"Failed to parse line {line_num}: {line[:100]}...")
        
        return parsed_logs

    def _parse_line(self, line: str) -> Optional[Dict[str, str]]:
        # Try main pattern first
        match = self.apache_pattern.match(line)
        
        # Try flexible pattern if main fails
        if not match:
            match = self.flexible_pattern.search(line)
        
        if not match:
            return None
        
        data = match.groupdict()
        
        # Clean and decode URL
        url = data.get('url', '')
        try:
            url = unquote(url)
        except:
            pass  # Keep original if decode fails
        
        # Parse URL components safely
        try:
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)
        except:
            parsed_url = type('obj', (object,), {'path': url, 'query': ''})()
            query_params = {}
        
        return {
            'ip': data.get('ip', ''),
            'timestamp': data.get('timestamp', ''),
            'method': data.get('method', 'GET'),
            'url': url,
            'path': getattr(parsed_url, 'path', url),
            'query_string': getattr(parsed_url, 'query', ''),
            'query_params': query_params,
            'status': data.get('status', '200'),
            'size': data.get('size', '0'),
            'referrer': data.get('referrer', '-'),
            'user_agent': data.get('user_agent', ''),
            'raw_line': line
        }

    def get_payload_from_entry(self, entry: Dict[str, str]) -> str:
        url = entry.get('url', '')
        query_string = entry.get('query_string', '')
        
        if query_string:
            return f"{entry.get('path', '')}?{query_string}"
        return entry.get('path', '')
