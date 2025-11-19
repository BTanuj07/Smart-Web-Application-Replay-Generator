import os
import json
from typing import Dict, List
from urllib.parse import urlparse, quote

class ReplayGenerator:
    def __init__(self, output_dir: str = "generated_attacks"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def generate_python_script(self, attack: Dict[str, any], attack_id: int) -> str:
        raw_url = attack.get('full_url', '')
        method = attack.get('method', 'GET')
        user_agent = attack.get('user_agent', 'Mozilla/5.0')
        attack_type = attack.get('attack_type', 'Unknown')
        
        parsed_url = urlparse(raw_url)
        if parsed_url.scheme:
            full_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
            if parsed_url.query:
                full_url += f"?{parsed_url.query}"
        else:
            full_url = f"http://example.com{raw_url}"
        
        script = f'''#!/usr/bin/env python3
import requests
from datetime import datetime

attack_info = {{
    "attack_type": "{attack_type}",
    "original_ip": "{attack.get('ip', '')}",
    "timestamp": "{attack.get('timestamp', '')}",
    "method": "{method}",
    "status_code": "{attack.get('status', '')}"
}}

print(f"[*] Replaying {attack_type} attack")
print(f"[*] Original IP: {{attack_info['original_ip']}}")
print(f"[*] Original Timestamp: {{attack_info['timestamp']}}")
print(f"[*] Method: {{attack_info['method']}}")
print("-" * 60)

url = "{full_url}"
headers = {{
    "User-Agent": "{user_agent}"
}}

try:
    print(f"[*] Sending {method} request to: {{url}}")
    '''
        
        if method.upper() == 'GET':
            script += f'''
    response = requests.get(url, headers=headers, timeout=10, allow_redirects=False)
    '''
        elif method.upper() == 'POST':
            script += f'''
    response = requests.post(url, headers=headers, timeout=10, allow_redirects=False)
    '''
        else:
            script += f'''
    response = requests.request("{method}", url, headers=headers, timeout=10, allow_redirects=False)
    '''
        
        script += f'''
    print(f"[+] Response Status Code: {{response.status_code}}")
    print(f"[+] Response Length: {{len(response.content)}} bytes")
    print(f"[*] Response Headers:")
    for key, value in response.headers.items():
        print(f"    {{key}}: {{value}}")
    
    print("\\n[*] Response Preview (first 500 chars):")
    print(response.text[:500])
    
except requests.exceptions.RequestException as e:
    print(f"[-] Error occurred: {{e}}")
except Exception as e:
    print(f"[-] Unexpected error: {{e}}")
'''
        
        return script

    def generate_curl_command(self, attack: Dict[str, any]) -> str:
        raw_url = attack.get('full_url', '')
        method = attack.get('method', 'GET')
        user_agent = attack.get('user_agent', 'Mozilla/5.0')
        
        parsed_url = urlparse(raw_url)
        if parsed_url.scheme:
            full_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
            if parsed_url.query:
                full_url += f"?{parsed_url.query}"
        else:
            full_url = f"http://example.com{raw_url}"
        
        curl_cmd = f'curl -X {method} \\\n'
        curl_cmd += f'  -H "User-Agent: {user_agent}" \\\n'
        curl_cmd += f'  -i \\\n'
        curl_cmd += f'  "{full_url}"'
        
        return curl_cmd

    def save_replay_scripts(self, attacks: List[Dict[str, any]]) -> Dict[str, List[str]]:
        generated_files = {
            'python_scripts': [],
            'curl_commands': []
        }
        
        for idx, attack in enumerate(attacks, 1):
            attack_type = attack.get('attack_type', 'Unknown').replace(' ', '_')
            
            python_script = self.generate_python_script(attack, idx)
            python_filename = f"{self.output_dir}/attack_{idx}_{attack_type}.py"
            with open(python_filename, 'w') as f:
                f.write(python_script)
            os.chmod(python_filename, 0o755)
            generated_files['python_scripts'].append(python_filename)
            
            curl_command = self.generate_curl_command(attack)
            curl_filename = f"{self.output_dir}/attack_{idx}_{attack_type}.sh"
            with open(curl_filename, 'w') as f:
                f.write("#!/bin/bash\n\n")
                f.write(f"# Attack Type: {attack.get('attack_type', 'Unknown')}\n")
                f.write(f"# Original IP: {attack.get('ip', '')}\n")
                f.write(f"# Timestamp: {attack.get('timestamp', '')}\n\n")
                f.write(curl_command)
                f.write("\n")
            os.chmod(curl_filename, 0o755)
            generated_files['curl_commands'].append(curl_filename)
        
        return generated_files

    def generate_summary_report(self, analysis_results: Dict[str, any], generated_files: Dict[str, List[str]]) -> str:
        report = {
            "analysis_timestamp": str(os.path.getmtime(__file__)) if os.path.exists(__file__) else "N/A",
            "total_attacks_detected": analysis_results.get('total_attacks', 0),
            "unique_ips": analysis_results.get('unique_ips', 0),
            "attack_breakdown": analysis_results.get('attack_type_counts', {}),
            "generated_files": generated_files,
            "attacks": analysis_results.get('attacks', [])
        }
        
        report_filename = f"{self.output_dir}/attack_summary.json"
        with open(report_filename, 'w') as f:
            json.dump(report, f, indent=2)
        
        return report_filename

    def clean_output_directory(self):
        if os.path.exists(self.output_dir):
            for file in os.listdir(self.output_dir):
                file_path = os.path.join(self.output_dir, file)
                if os.path.isfile(file_path):
                    os.remove(file_path)
