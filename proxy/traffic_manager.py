#!/usr/bin/env python3
"""
Traffic Manager - Storage and Streaming Layer
Handles traffic storage, filtering, and real-time streaming
"""

import json
import threading
import time
from datetime import datetime
from typing import Dict, List, Optional, Callable
from collections import deque
import re

class TrafficFilter:
    """Filter traffic based on various criteria."""
    
    def __init__(self):
        self.method_filter = None
        self.status_filter = None
        self.host_filter = None
        self.url_filter = None
        
    def set_method_filter(self, methods: List[str]):
        """Filter by HTTP methods."""
        self.method_filter = [m.upper() for m in methods] if methods else None
        
    def set_status_filter(self, status_codes: List[int]):
        """Filter by status codes."""
        self.status_filter = status_codes if status_codes else None
        
    def set_host_filter(self, hosts: List[str]):
        """Filter by hosts."""
        self.host_filter = hosts if hosts else None
        
    def set_url_filter(self, pattern: str):
        """Filter by URL pattern (regex)."""
        self.url_filter = re.compile(pattern) if pattern else None
        
    def matches(self, transaction_dict: Dict) -> bool:
        """Check if transaction matches all filters."""
        # Method filter
        if self.method_filter and transaction_dict['method'] not in self.method_filter:
            return False
            
        # Status filter
        if self.status_filter and transaction_dict['response_status'] not in self.status_filter:
            return False
            
        # Host filter
        if self.host_filter and transaction_dict['host'] not in self.host_filter:
            return False
            
        # URL filter
        if self.url_filter and not self.url_filter.search(transaction_dict['url']):
            return False
            
        return True

class TrafficStorage:
    """In-memory traffic storage with filtering and search."""
    
    def __init__(self, max_size: int = 10000):
        self.max_size = max_size
        self.transactions = deque(maxlen=max_size)
        self.lock = threading.RLock()
        
    def add_transaction(self, transaction_dict: Dict):
        """Add a transaction to storage."""
        with self.lock:
            self.transactions.append(transaction_dict)
    
    def get_all_transactions(self) -> List[Dict]:
        """Get all transactions."""
        with self.lock:
            return list(self.transactions)
    
    def get_filtered_transactions(self, traffic_filter: TrafficFilter) -> List[Dict]:
        """Get transactions matching filter."""
        with self.lock:
            return [t for t in self.transactions if traffic_filter.matches(t)]
    
    def get_transaction_by_id(self, transaction_id: str) -> Optional[Dict]:
        """Get specific transaction by ID."""
        with self.lock:
            for transaction in self.transactions:
                if transaction['id'] == transaction_id:
                    return transaction
            return None
    
    def clear_transactions(self):
        """Clear all transactions."""
        with self.lock:
            self.transactions.clear()
    
    def get_stats(self) -> Dict:
        """Get traffic statistics."""
        with self.lock:
            if not self.transactions:
                return {
                    'total_requests': 0,
                    'methods': {},
                    'status_codes': {},
                    'hosts': {},
                    'avg_response_time': 0
                }
            
            methods = {}
            status_codes = {}
            hosts = {}
            response_times = []
            
            for t in self.transactions:
                # Count methods
                method = t['method']
                methods[method] = methods.get(method, 0) + 1
                
                # Count status codes
                status = t['response_status']
                status_codes[status] = status_codes.get(status, 0) + 1
                
                # Count hosts
                host = t['host']
                hosts[host] = hosts.get(host, 0) + 1
                
                # Collect response times
                response_times.append(t['response_time_ms'])
            
            avg_response_time = sum(response_times) / len(response_times) if response_times else 0
            
            return {
                'total_requests': len(self.transactions),
                'methods': methods,
                'status_codes': status_codes,
                'hosts': hosts,
                'avg_response_time': round(avg_response_time, 2)
            }

class TrafficStreamer:
    """Real-time traffic streaming via WebSocket."""
    
    def __init__(self, socketio):
        self.socketio = socketio
        self.subscribers = set()
        self.lock = threading.Lock()
        
    def subscribe(self, session_id: str):
        """Subscribe to traffic stream."""
        with self.lock:
            self.subscribers.add(session_id)
            
    def unsubscribe(self, session_id: str):
        """Unsubscribe from traffic stream."""
        with self.lock:
            self.subscribers.discard(session_id)
    
    def emit_transaction(self, transaction_dict: Dict):
        """Emit transaction to all subscribers."""
        with self.lock:
            if self.subscribers:
                self.socketio.emit('traffic_update', {
                    'type': 'new_transaction',
                    'data': transaction_dict
                }, room=None)  # Broadcast to all connected clients

class TrafficManager:
    """Main traffic management class."""
    
    def __init__(self, socketio, max_storage: int = 10000):
        self.storage = TrafficStorage(max_storage)
        self.streamer = TrafficStreamer(socketio)
        self.filter = TrafficFilter()
        self.running = False
        
    def handle_transaction(self, transaction):
        """Handle new transaction from proxy."""
        transaction_dict = transaction.to_dict()
        
        # Store transaction
        self.storage.add_transaction(transaction_dict)
        
        # Stream to subscribers
        self.streamer.emit_transaction(transaction_dict)
        
        print(f"📊 Captured: {transaction_dict['method']} {transaction_dict['url']} -> {transaction_dict['response_status']}")
    
    def get_transactions(self, filter_params: Dict = None) -> List[Dict]:
        """Get transactions with optional filtering."""
        if not filter_params:
            return self.storage.get_all_transactions()
        
        # Apply filters
        traffic_filter = TrafficFilter()
        
        if 'methods' in filter_params:
            traffic_filter.set_method_filter(filter_params['methods'])
            
        if 'status_codes' in filter_params:
            traffic_filter.set_status_filter(filter_params['status_codes'])
            
        if 'hosts' in filter_params:
            traffic_filter.set_host_filter(filter_params['hosts'])
            
        if 'url_pattern' in filter_params:
            traffic_filter.set_url_filter(filter_params['url_pattern'])
        
        return self.storage.get_filtered_transactions(traffic_filter)
    
    def get_transaction_details(self, transaction_id: str) -> Optional[Dict]:
        """Get detailed transaction information."""
        return self.storage.get_transaction_by_id(transaction_id)
    
    def clear_traffic(self):
        """Clear all traffic data."""
        self.storage.clear_transactions()
        
        # Notify subscribers
        self.streamer.socketio.emit('traffic_update', {
            'type': 'traffic_cleared'
        })
    
    def get_statistics(self) -> Dict:
        """Get traffic statistics."""
        return self.storage.get_stats()
    
    def export_traffic(self, format_type: str = 'json') -> str:
        """Export traffic data."""
        transactions = self.storage.get_all_transactions()
        
        if format_type == 'json':
            return json.dumps(transactions, indent=2)
        elif format_type == 'txt':
            return self._export_as_apache_log(transactions)
        else:
            raise ValueError(f"Unsupported export format: {format_type}")
    
    def _export_as_apache_log(self, transactions: List[Dict]) -> str:
        """Export as Apache/Nginx log format."""
        log_lines = []
        
        for t in transactions:
            # Parse timestamp to Apache log format
            try:
                # Convert ISO timestamp to Apache format
                dt = datetime.fromisoformat(t['timestamp'].replace('Z', '+00:00'))
                timestamp = dt.strftime('[%d/%b/%Y:%H:%M:%S %z]')
            except:
                # Fallback timestamp
                timestamp = '[19/Nov/2025:10:30:00 +0000]'
            
            # Get client IP
            client_ip = t.get('client_ip', '127.0.0.1')
            
            # Build request line
            method = t.get('method', 'GET')
            url = t.get('url', '/')
            
            # Extract path from full URL if needed
            if url.startswith('http'):
                try:
                    from urllib.parse import urlparse
                    parsed = urlparse(url)
                    path = parsed.path
                    if parsed.query:
                        path += '?' + parsed.query
                except:
                    path = url
            else:
                path = url
            
            request_line = f'"{method} {path} HTTP/1.1"'
            
            # Get response status
            status = t.get('response_status', 200)
            
            # Get response size (use body size or estimate)
            size = t.get('response_body_size', 0)
            if size == 0:
                # Estimate size based on status
                size = 1234 if status == 200 else 123
            
            # Get user agent
            headers = t.get('request_headers', {})
            user_agent = headers.get('User-Agent', headers.get('user-agent', 'Mozilla/5.0'))
            
            # Get referer
            referer = headers.get('Referer', headers.get('referer', '-'))
            
            # Build Apache log line
            # Format: IP - - [timestamp] "request" status size "referer" "user-agent"
            log_line = f'{client_ip} - - {timestamp} {request_line} {status} {size} "{referer}" "{user_agent}"'
            log_lines.append(log_line)
        
        return '\n'.join(log_lines)