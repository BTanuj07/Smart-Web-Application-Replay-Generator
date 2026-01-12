#!/usr/bin/env python3
"""
Proxy Controller - Integration Layer
Manages proxy lifecycle and integrates with Flask application
"""

import threading
import time
from typing import Optional
from .http_proxy import HTTPProxy
from .traffic_manager import TrafficManager

class ProxyController:
    """Controls HTTP proxy server and traffic management."""
    
    def __init__(self, socketio, host='127.0.0.1', port=8080, enable_https=False):
        self.host = host
        self.port = port
        self.socketio = socketio
        self.enable_https = enable_https
        
        # Initialize components
        self.traffic_manager = TrafficManager(socketio)
        self.proxy = None
        self.proxy_thread = None
        self.running = False
        
    def start_proxy(self, enable_https_interception=False) -> bool:
        """Start the HTTP proxy server."""
        if self.running:
            return False
        
        try:
            # Create proxy with callback to traffic manager
            self.proxy = HTTPProxy(
                host=self.host,
                port=self.port,
                callback=self.traffic_manager.handle_transaction,
                enable_https_interception=enable_https_interception
            )
            
            # Start proxy in separate thread
            self.proxy_thread = threading.Thread(target=self.proxy.start)
            self.proxy_thread.daemon = True
            self.proxy_thread.start()
            
            # Wait a moment to ensure proxy started
            time.sleep(0.5)
            
            self.running = True
            self.enable_https = enable_https_interception
            
            if enable_https_interception:
                print(f"✅ Proxy controller started on {self.host}:{self.port} with HTTPS interception")
            else:
                print(f"✅ Proxy controller started on {self.host}:{self.port} (HTTP only)")
            
            return True
            
        except Exception as e:
            print(f"❌ Failed to start proxy: {e}")
            return False
    
    def stop_proxy(self) -> bool:
        """Stop the HTTP proxy server."""
        if not self.running:
            return False
        
        try:
            self.running = False
            
            if self.proxy:
                self.proxy.stop()
            
            print("✅ Proxy controller stopped")
            return True
            
        except Exception as e:
            print(f"❌ Failed to stop proxy: {e}")
            return False
    
    def is_running(self) -> bool:
        """Check if proxy is running."""
        return self.running
    
    def get_proxy_info(self) -> dict:
        """Get proxy information."""
        return {
            'host': self.host,
            'port': self.port,
            'running': self.running,
            'https_enabled': self.enable_https,
            'url': f"http://{self.host}:{self.port}",
            'ca_cert_path': self.proxy.get_ca_certificate_path() if self.proxy else None
        }
    
    def get_traffic_history(self, filter_params: dict = None) -> list:
        """Get traffic history with optional filtering."""
        return self.traffic_manager.get_transactions(filter_params)
    
    def get_transaction_details(self, transaction_id: str) -> Optional[dict]:
        """Get detailed transaction information."""
        return self.traffic_manager.get_transaction_details(transaction_id)
    
    def clear_traffic_history(self):
        """Clear all traffic history."""
        self.traffic_manager.clear_traffic()
    
    def get_traffic_statistics(self) -> dict:
        """Get traffic statistics."""
        stats = self.traffic_manager.get_statistics()
        stats['proxy_info'] = self.get_proxy_info()
        return stats
    
    def export_traffic(self, format_type: str = 'json') -> str:
        """Export traffic data."""
        return self.traffic_manager.export_traffic(format_type)
    
    def subscribe_to_stream(self, session_id: str):
        """Subscribe to real-time traffic stream."""
        self.traffic_manager.streamer.subscribe(session_id)
    
    def unsubscribe_from_stream(self, session_id: str):
        """Unsubscribe from real-time traffic stream."""
        self.traffic_manager.streamer.unsubscribe(session_id)