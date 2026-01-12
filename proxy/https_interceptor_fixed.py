#!/usr/bin/env python3
"""
Fixed HTTPS Traffic Interceptor
Implements SSL/TLS interception with proper socket handling
"""

import ssl
import socket
import threading
import time
import os
from datetime import datetime
from typing import Optional, Callable
from .http_proxy import HTTPParser, HTTPTransaction, HTTPRequest, HTTPResponse
import tempfile

class CertificateManager:
    """Manages SSL certificates for HTTPS interception."""
    
    def __init__(self):
        self.ca_cert_path = None
        self.ca_key_path = None
        self.cert_cache = {}
        self.cert_dir = os.path.join(tempfile.gettempdir(), 'proxy_certs')
        os.makedirs(self.cert_dir, exist_ok=True)
        
    def generate_ca_certificate(self):
        """Generate Certificate Authority (CA) certificate."""
        try:
            from cryptography import x509
            from cryptography.x509.oid import NameOID
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import rsa
            import datetime
            
            # Generate CA private key
            ca_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
            
            # Generate CA certificate
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Smart Web Attack Replay Generator"),
                x509.NameAttribute(NameOID.COMMON_NAME, "Proxy CA"),
            ])
            
            ca_cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                ca_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.datetime.utcnow()
            ).not_valid_after(
                datetime.datetime.utcnow() + datetime.timedelta(days=365)
            ).add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True,
            ).add_extension(
                x509.KeyUsage(
                    key_cert_sign=True,
                    crl_sign=True,
                    digital_signature=False,
                    key_encipherment=False,
                    key_agreement=False,
                    content_commitment=False,
                    data_encipherment=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            ).sign(ca_key, hashes.SHA256())
            
            # Save CA certificate and key
            self.ca_cert_path = os.path.join(self.cert_dir, 'ca.crt')
            self.ca_key_path = os.path.join(self.cert_dir, 'ca.key')
            
            with open(self.ca_cert_path, 'wb') as f:
                f.write(ca_cert.public_bytes(serialization.Encoding.PEM))
            
            with open(self.ca_key_path, 'wb') as f:
                f.write(ca_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            
            print(f"CA Certificate generated: {self.ca_cert_path}")
            return True
            
        except ImportError:
            print("cryptography library required for HTTPS interception")
            print("   Install with: pip install cryptography")
            return False
        except Exception as e:
            print(f"Error generating CA certificate: {e}")
            return False
    
    def generate_server_certificate(self, hostname: str):
        """Generate server certificate for specific hostname."""
        if hostname in self.cert_cache:
            return self.cert_cache[hostname]
        
        try:
            from cryptography import x509
            from cryptography.x509.oid import NameOID
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import rsa
            import datetime
            
            # Load CA certificate and key
            with open(self.ca_cert_path, 'rb') as f:
                ca_cert = x509.load_pem_x509_certificate(f.read())
            
            with open(self.ca_key_path, 'rb') as f:
                ca_key = serialization.load_pem_private_key(f.read(), password=None)
            
            # Generate server private key
            server_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
            
            # Generate server certificate
            subject = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Proxy Server"),
                x509.NameAttribute(NameOID.COMMON_NAME, hostname),
            ])
            
            server_cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                ca_cert.subject
            ).public_key(
                server_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.datetime.utcnow()
            ).not_valid_after(
                datetime.datetime.utcnow() + datetime.timedelta(days=30)
            ).add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName(hostname),
                ]),
                critical=False,
            ).sign(ca_key, hashes.SHA256())
            
            # Save server certificate and key
            cert_path = os.path.join(self.cert_dir, f'{hostname}.crt')
            key_path = os.path.join(self.cert_dir, f'{hostname}.key')
            
            with open(cert_path, 'wb') as f:
                f.write(server_cert.public_bytes(serialization.Encoding.PEM))
            
            with open(key_path, 'wb') as f:
                f.write(server_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            
            self.cert_cache[hostname] = (cert_path, key_path)
            return cert_path, key_path
            
        except Exception as e:
            print(f"Error generating server certificate for {hostname}: {e}")
            return None, None

class HTTPSInterceptor:
    """HTTPS traffic interceptor with SSL/TLS termination."""
    
    def __init__(self, callback: Optional[Callable] = None):
        self.callback = callback
        self.cert_manager = CertificateManager()
        self.running = False
        
    def initialize(self):
        """Initialize HTTPS interceptor."""
        return self.cert_manager.generate_ca_certificate()
    
    def handle_https_connect(self, client_socket, client_address, target_host, target_port):
        """Handle HTTPS CONNECT request with SSL interception."""
        client_ssl_socket = None
        target_ssl_socket = None
        target_socket = None
        
        try:
            # Validate socket before proceeding
            if not self._is_socket_valid(client_socket):
                print(f"Invalid client socket for {target_host}")
                return
            
            # Send 200 Connection established
            try:
                response = b"HTTP/1.1 200 Connection established\r\n\r\n"
                client_socket.send(response)
            except Exception as e:
                print(f"Failed to send CONNECT response to {target_host}: {e}")
                return
            
            # Generate certificate for target host
            cert_path, key_path = self.cert_manager.generate_server_certificate(target_host)
            if not cert_path or not key_path:
                print(f"Could not generate certificate for {target_host}")
                return
            
            # Create SSL context for client connection with better error handling
            try:
                client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                client_context.load_cert_chain(cert_path, key_path)
                client_context.set_ciphers('HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!SRP:!CAMELLIA')
                
                # Set socket options before SSL wrap
                client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                client_socket.settimeout(10)  # Shorter timeout for handshake
                
                # Wrap client socket with SSL
                client_ssl_socket = client_context.wrap_socket(
                    client_socket, 
                    server_side=True,
                    suppress_ragged_eofs=True,
                    do_handshake_on_connect=True
                )
                
            except ssl.SSLError as e:
                print(f"SSL handshake failed with client for {target_host}: {e}")
                return
            except Exception as e:
                print(f"Unexpected SSL error with client for {target_host}: {e}")
                return
            
            # Connect to target server with better error handling
            try:
                target_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                target_socket.settimeout(10)
                target_socket.connect((target_host, target_port))
                
                target_context = ssl.create_default_context()
                target_context.check_hostname = False
                target_context.verify_mode = ssl.CERT_NONE
                
                target_ssl_socket = target_context.wrap_socket(
                    target_socket,
                    server_hostname=target_host,
                    do_handshake_on_connect=True
                )
                
            except Exception as e:
                print(f"Failed to connect to target {target_host}:{target_port}: {e}")
                return
            
            # Handle HTTPS traffic with improved error handling
            self._handle_https_traffic(client_ssl_socket, target_ssl_socket, client_address, target_host)
            
        except Exception as e:
            print(f"Error handling HTTPS connection to {target_host}: {e}")
        finally:
            # Clean up all sockets properly
            self._cleanup_sockets([
                ('client_ssl', client_ssl_socket),
                ('target_ssl', target_ssl_socket),
                ('target', target_socket),
                ('client', client_socket)
            ])
    
    def _is_socket_valid(self, sock):
        """Check if socket is still valid and connected."""
        try:
            # Try to get socket info
            sock.getpeername()
            return True
        except (OSError, socket.error):
            return False
    
    def _cleanup_sockets(self, sockets):
        """Safely cleanup multiple sockets."""
        for name, sock in sockets:
            if sock:
                try:
                    if hasattr(sock, 'shutdown') and self._is_socket_valid(sock):
                        sock.shutdown(socket.SHUT_RDWR)
                except:
                    pass
                try:
                    sock.close()
                except:
                    pass
    
    def _handle_https_traffic(self, client_ssl_socket, target_ssl_socket, client_address, target_host):
        """Handle decrypted HTTPS traffic with improved error handling."""
        try:
            # Set longer timeouts for data transfer
            client_ssl_socket.settimeout(30)
            target_ssl_socket.settimeout(30)
            
            while True:
                # Read request from client with better buffering
                request_data = self._read_http_message(client_ssl_socket, is_request=True)
                if not request_data:
                    break
                
                # Parse HTTPS request
                transaction = HTTPTransaction()
                transaction.id = f"https_{int(time.time() * 1000)}"
                
                request = HTTPParser.parse_request(request_data, client_address[0])
                if request:
                    # Fix URL for HTTPS
                    if not request.url.startswith('http'):
                        request.url = f"https://{target_host}{request.url}"
                    request.host = target_host
                    transaction.request = request
                
                # Forward request to target
                start_time = time.time()
                try:
                    target_ssl_socket.send(request_data)
                except Exception as e:
                    print(f"Error sending to target: {e}")
                    break
                
                # Read response from target
                response_data = self._read_http_message(target_ssl_socket, is_request=False)
                if not response_data:
                    break
                
                end_time = time.time()
                response_time_ms = int((end_time - start_time) * 1000)
                
                # Parse HTTPS response
                response = HTTPParser.parse_response(response_data)
                if response:
                    response.response_time_ms = response_time_ms
                    transaction.response = response
                    transaction.end_time = end_time
                
                # Send response back to client
                try:
                    client_ssl_socket.send(response_data)
                except Exception as e:
                    print(f"Error sending response to client: {e}")
                    break
                
                # Emit transaction via callback
                if self.callback and hasattr(transaction, 'response') and transaction.response.status_code > 0:
                    try:
                        self.callback(transaction)
                    except Exception as e:
                        print(f"Error in callback: {e}")
                
        except Exception as e:
            print(f"Error in HTTPS traffic handling: {e}")
    
    def _read_http_message(self, ssl_socket, is_request=True, max_size=1024*1024):
        """Read complete HTTP message (request or response) with proper buffering."""
        try:
            data = b''
            headers_complete = False
            content_length = None
            is_chunked = False
            
            while len(data) < max_size:
                try:
                    chunk = ssl_socket.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                    
                    # Check if headers are complete
                    if not headers_complete and b'\r\n\r\n' in data:
                        headers_complete = True
                        header_part = data.split(b'\r\n\r\n')[0]
                        headers_str = header_part.decode('utf-8', errors='ignore')
                        
                        # Parse headers for content-length and transfer-encoding
                        for line in headers_str.split('\r\n'):
                            line_lower = line.lower()
                            if line_lower.startswith('content-length:'):
                                try:
                                    content_length = int(line.split(':', 1)[1].strip())
                                except:
                                    pass
                            elif line_lower.startswith('transfer-encoding:') and 'chunked' in line_lower:
                                is_chunked = True
                    
                    # Check if message is complete
                    if headers_complete:
                        if is_chunked:
                            # For chunked encoding, look for end marker
                            if data.endswith(b'0\r\n\r\n'):
                                break
                        elif content_length is not None:
                            # For content-length, check if we have all data
                            body_start = data.find(b'\r\n\r\n') + 4
                            if len(data) - body_start >= content_length:
                                break
                        else:
                            # For requests without body or responses with connection close
                            if is_request and content_length is None:
                                break
                            # For responses, continue reading until connection closes
                            continue
                
                except ssl.SSLWantReadError:
                    continue
                except (ssl.SSLError, OSError, ConnectionResetError) as e:
                    if data:  # Return partial data if we have some
                        break
                    return b''
                except Exception as e:
                    print(f"Unexpected error reading SSL data: {e}")
                    break
            
            return data
            
        except Exception as e:
            print(f"Error reading HTTP message: {e}")
            return b''
    
    def get_ca_certificate_path(self):
        """Get path to CA certificate for browser installation."""
        return self.cert_manager.ca_cert_path