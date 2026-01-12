"""
HTTP Proxy Module for Real-time Traffic Capture
Similar to Burp Suite's HTTP History feature
"""

from .http_proxy import HTTPProxy, HTTPTransaction, HTTPRequest, HTTPResponse
from .traffic_manager import TrafficManager, TrafficFilter, TrafficStorage, TrafficStreamer
from .proxy_controller import ProxyController

__all__ = [
    'HTTPProxy',
    'HTTPTransaction', 
    'HTTPRequest',
    'HTTPResponse',
    'TrafficManager',
    'TrafficFilter',
    'TrafficStorage', 
    'TrafficStreamer',
    'ProxyController'
]