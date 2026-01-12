#!/usr/bin/env python3
"""
HTTP Forward Proxy Server
Similar to Burp Suite's HTTP History - captures HTTP traffic only
Now with optional HTTPS interception support
"""

import socket
import threading
import time
import json
import re
from datetime import datetime
from typing import Dict, List, Optional, Callable
from urllib.parse import urlparse
import struct

class HTTPRequest:
    """HTTP Request data structure."""
    def __init__(self):
        self.timestamp = datetime.now().isoformat()
        self.client_ip = ""
        self.method = ""
        self.url = ""
        self.host = ""
        self.path = ""
        self.headers = {}
        self.body = ""
        self.body_size = 0

class HTTPResponse:
    """HTTP Response data structure."""
    def __init__(self):
        self.timestamp = datetime.now().isoformat()
        self.status_code = 0
        self.status_message = ""
        self.headers = {}
        self.body = ""
        self.body_size = 0
        self.response_time_ms = 0

class HTTPTransaction:
    """Complete HTTP request/response transaction."""
    def __init__(self):
        self.id = ""
        self.request = HTTPRequest()
        self.response = HTTPResponse()
        self.start_time = time.time()
        self.end_time = 0
        
    def to_dict(self):
        """Convert to dictionary for JSON serialization."""
        return {
            'id': self.id,
            'timestamp': self.request.timestamp,
            'client_ip': self.request.client_ip,
            'method': self.request.method,
            'url': self.request.url,
            'host': self.request.host,
            'path': self.request.path,
            'request_headers': self.request.headers,
            'request_body': self.request.body,
            'request_body_size': self.request.body_size,
            'response_status': self.response.status_code,
            'response_message': self.response.status_message,
            'response_headers': self.response.headers,
            'response_body_size': self.response.body_size,
            'response_time_ms': self.response.response_time_ms,
            'tags': []
        }

class HTTPParser:
    """Parse HTTP requests and responses."""
    
    @staticmethod
    def parse_request(raw_data: bytes, client_ip: str) -> Optional[HTTPRequest]:
        """Parse raw HTTP request."""
        try:
            data = raw_data.decode('utf-8', errors='ignore')
            lines = data.split('\r\n')
            
            if not lines or not lines[0]:
                return None
            
            # Parse request line
            request_line = lines[0]
            parts = request_line.split(' ')
            if len(parts) < 3:
                return None
            
            request = HTTPRequest()
            request.client_ip = client_ip
            request.method = parts[0]
            request.url = parts[1]
            
            # Parse URL components
            if request.url.startswith('http://'):
                parsed = urlparse(request.url)
                request.host = parsed.netloc
                request.path = parsed.path + ('?' + parsed.query if parsed.query else '')
            else:
                request.path = request.url
            
            # Parse headers
            header_end = 1
            for i, line in enumerate(lines[1:], 1):
                if line == '':
                    header_end = i + 1
                    break
                if ':' in line:
                    key, value = line.split(':', 1)
                    request.headers[key.strip()] = value.strip()
                    
                    # Extract host from headers if not in URL
                    if key.strip().lower() == 'host' and not request.host:
                        request.host = value.strip()
            
            # Parse body
            if header_end < len(lines):
                request.body = '\r\n'.join(lines[header_end:])
                request.body_size = len(request.body.encode('utf-8'))
            
            return request
            
        except Exception as e:
            print(f"Error parsing request: {e}")
            return None
    
    @staticmethod
    def parse_response(raw_data: bytes) -> Optional[HTTPResponse]:
        """Parse raw HTTP response."""
        try:
            data = raw_data.decode('utf-8', errors='ignore')
            lines = data.split('\r\n')
            
            if not lines or not lines[0]:
                return None
            
            # Parse status line
            status_line = lines[0]
            parts = status_line.split(' ', 2)
            if len(parts) < 2:
                return None
            
            response = HTTPResponse()
            response.status_code = int(parts[1])
            response.status_message = parts[2] if len(parts) > 2 else ''
            
            # Parse headers
            header_end = 1
            for i, line in enumerate(lines[1:], 1):
                if line == '':
                    header_end = i + 1
                    break
                if ':' in line:
                    key, value = line.split(':', 1)
                    response.headers[key.strip()] = value.strip()
            
            # Parse body
            if header_end < len(lines):
                response.body = '\r\n'.join(lines[header_end:])
                response.body_size = len(response.body.encode('utf-8'))
            else:
                response.body_size = len(raw_data) - len('\r\n'.join(lines[:header_end]).encode('utf-8'))
            
            return response
            
        except Exception as e:
            print(f"Error parsing response: {e}")
            return None

class HTTPProxy:
    """HTTP Forward Proxy Server with optional HTTPS interception."""
    
    def __init__(self, host='127.0.0.1', port=8080, callback: Optional[Callable] = None, enable_https_interception=False):
        self.host = host
        self.port = port
        self.callback = callback
        self.running = False
        self.server_socket = None
        self.transaction_counter = 0
        self.enable_https_interception = enable_https_interception
        self.https_interceptor = None
        
        # Initialize HTTPS interceptor if enabled
        if self.enable_https_interception:
            try:
                from .https_interceptor_fixed import HTTPSInterceptor
                self.https_interceptor = HTTPSInterceptor(callback=self.callback)
                if not self.https_interceptor.initialize():
                    print("HTTPS interception disabled - certificate generation failed")
                    self.enable_https_interception = False
                else:
                    print("HTTPS interception enabled")
            except ImportError:
                print("HTTPS interception disabled - cryptography library not installed")
                print("   Install with: pip install cryptography")
                self.enable_https_interception = False
        
    def start(self):
        """Start the proxy server."""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(100)
            
            self.running = True
            print(f"🌐 HTTP Proxy started on {self.host}:{self.port}")
            print(f"📋 Configure your browser proxy to {self.host}:{self.port}")
            
            while self.running:
                try:
                    client_socket, client_address = self.server_socket.accept()
                    client_thread = threading.Thread(
                        target=self._handle_client,
                        args=(client_socket, client_address)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                except Exception as e:
                    if self.running:
                        print(f"Error accepting connection: {e}")
                        
        except Exception as e:
            print(f"Error starting proxy server: {e}")
        finally:
            self.stop()
    
    def stop(self):
        """Stop the proxy server."""
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        print("🛑 HTTP Proxy stopped")
    
    def _handle_client(self, client_socket, client_address):
        """Handle client connection."""
        transaction = HTTPTransaction()
        transaction.id = f"req_{int(time.time() * 1000)}_{self.transaction_counter}"
        self.transaction_counter += 1
        
        try:
            # Set socket timeout
            client_socket.settimeout(30)
            
            # Receive request from client
            request_data = b''
            while True:
                try:
                    chunk = client_socket.recv(4096)
                    if not chunk:
                        break
                    request_data += chunk
                    
                    # Check if we have complete HTTP request
                    if b'\r\n\r\n' in request_data:
                        # Check if there's a body
                        header_part = request_data.split(b'\r\n\r\n')[0]
                        headers_str = header_part.decode('utf-8', errors='ignore')
                        
                        # Check Content-Length
                        content_length = 0
                        for line in headers_str.split('\r\n'):
                            if line.lower().startswith('content-length:'):
                                try:
                                    content_length = int(line.split(':', 1)[1].strip())
                                except:
                                    content_length = 0
                                break
                        
                        # If we have all the data, break
                        body_start = request_data.find(b'\r\n\r\n') + 4
                        if len(request_data) - body_start >= content_length:
                            break
                            
                except socket.timeout:
                    break
            
            if not request_data:
                return
            
            # Parse HTTP request
            request = HTTPParser.parse_request(request_data, client_address[0])
            if not request:
                client_socket.close()
                return
            
            transaction.request = request
            
            # Skip HTTPS CONNECT requests - handle them properly
            if request.method == 'CONNECT':
                if self.enable_https_interception and self.https_interceptor:
                    # HTTPS interception mode
                    target_host, target_port = request.url.split(':')
                    target_port = int(target_port)
                    
                    # Handle HTTPS interception in separate thread
                    https_thread = threading.Thread(
                        target=self.https_interceptor.handle_https_connect,
                        args=(client_socket, client_address, target_host, target_port)
                    )
                    https_thread.daemon = True
                    https_thread.start()
                    return
                else:
                    # Normal HTTPS tunneling (no interception)
                    response = b"HTTP/1.1 200 Connection established\r\n\r\n"
                    try:
                        client_socket.send(response)
                        # For CONNECT, we don't capture the tunneled data
                        # Just relay the connection
                        target_host, target_port = request.url.split(':')
                        target_port = int(target_port)
                        
                        target_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        target_socket.settimeout(30)
                        target_socket.connect((target_host, target_port))
                        
                        # Relay data between client and target
                        def relay_data(source, destination):
                            try:
                                while True:
                                    data = source.recv(4096)
                                    if not data:
                                        break
                                    destination.send(data)
                            except:
                                pass
                            finally:
                                try:
                                    source.close()
                                    destination.close()
                                except:
                                    pass
                        
                        # Start relay threads
                        t1 = threading.Thread(target=relay_data, args=(client_socket, target_socket))
                        t2 = threading.Thread(target=relay_data, args=(target_socket, client_socket))
                        t1.daemon = True
                        t2.daemon = True
                        t1.start()
                        t2.start()
                        
                        # Wait for threads to finish
                        t1.join(timeout=300)  # 5 minute timeout
                        t2.join(timeout=300)
                        
                    except Exception as e:
                        print(f"Error handling CONNECT: {e}")
                    finally:
                        try:
                            client_socket.close()
                        except:
                            pass
                    return
            
            # Extract target host and port
            target_host, target_port = self._extract_target(request)
            
            if not target_host:
                # Send error response
                error_response = b"HTTP/1.1 400 Bad Request\r\n\r\nBad Request: Could not determine target host"
                try:
                    client_socket.send(error_response)
                except:
                    pass
                client_socket.close()
                return
            
            # Connect to target server
            start_time = time.time()
            target_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            target_socket.settimeout(30)
            
            try:
                target_socket.connect((target_host, target_port))
                
                # Forward request to target
                target_socket.send(request_data)
                
                # Receive response from target
                response_data = b''
                content_length = None
                is_chunked = False
                headers_complete = False
                
                while True:
                    try:
                        chunk = target_socket.recv(4096)
                        if not chunk:
                            break
                        response_data += chunk
                        
                        # Parse headers if not done yet
                        if not headers_complete and b'\r\n\r\n' in response_data:
                            headers_complete = True
                            header_part = response_data.split(b'\r\n\r\n')[0]
                            headers_str = header_part.decode('utf-8', errors='ignore')
                            
                            # Check transfer encoding and content length
                            for line in headers_str.split('\r\n'):
                                line_lower = line.lower()
                                if line_lower.startswith('transfer-encoding:') and 'chunked' in line_lower:
                                    is_chunked = True
                                elif line_lower.startswith('content-length:'):
                                    try:
                                        content_length = int(line.split(':', 1)[1].strip())
                                    except:
                                        pass
                        
                        # Check if response is complete
                        if headers_complete:
                            if is_chunked:
                                # For chunked encoding, look for end marker
                                if response_data.endswith(b'0\r\n\r\n'):
                                    break
                            elif content_length is not None:
                                # For content-length, check if we have all data
                                body_start = response_data.find(b'\r\n\r\n') + 4
                                if len(response_data) - body_start >= content_length:
                                    break
                            else:
                                # No content-length or chunked encoding
                                # For HTTP/1.0 or connection close, read until connection closes
                                continue
                        
                    except socket.timeout:
                        break
                
                end_time = time.time()
                response_time_ms = int((end_time - start_time) * 1000)
                
                # Parse HTTP response
                if response_data:
                    response = HTTPParser.parse_response(response_data)
                    if response:
                        response.response_time_ms = response_time_ms
                        transaction.response = response
                        transaction.end_time = end_time
                
                # Forward response to client
                if response_data:
                    client_socket.send(response_data)
                
                # Emit transaction via callback
                if self.callback and transaction.response.status_code > 0:
                    self.callback(transaction)
                
            except Exception as e:
                print(f"Error connecting to target {target_host}:{target_port}: {e}")
                # Send error response to client
                error_response = b"HTTP/1.1 502 Bad Gateway\r\n\r\nProxy Error: Could not connect to target server"
                try:
                    client_socket.send(error_response)
                except:
                    pass
            
            finally:
                try:
                    target_socket.close()
                except:
                    pass
                
        except Exception as e:
            print(f"Error handling client {client_address}: {e}")
        finally:
            try:
                client_socket.close()
            except:
                pass
    
    def _extract_target(self, request: HTTPRequest) -> tuple:
        """Extract target host and port from HTTP request."""
        try:
            # For absolute URLs
            if request.url.startswith('http://'):
                parsed = urlparse(request.url)
                host = parsed.hostname
                port = parsed.port or 80
                return host, port
            
            # For relative URLs, use Host header
            if request.host:
                if ':' in request.host:
                    host, port = request.host.split(':')
                    return host, int(port)
                return request.host, 80
            
            return None, None
            
        except Exception as e:
            print(f"Error extracting target: {e}")
            return None, None

    def get_ca_certificate_path(self):
        """Get CA certificate path for browser installation."""
        if self.enable_https_interception and self.https_interceptor:
            return self.https_interceptor.get_ca_certificate_path()
        return None

if __name__ == "__main__":
    # Test the proxy
    def transaction_callback(transaction):
        print(f"📡 {transaction.request.method} {transaction.request.url} -> {transaction.response.status_code} ({transaction.response.response_time_ms}ms)")
    
    proxy = HTTPProxy(callback=transaction_callback)
    try:
        proxy.start()
    except KeyboardInterrupt:
        proxy.stop()