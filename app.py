import streamlit as st
import json
import os
import zipfile
from io import BytesIO
import pandas as pd
from parser.log_parser import LogParser
from detector.attack_detector import AttackDetector
from generator.replay_generator import ReplayGenerator

st.set_page_config(
    page_title="Smart Web Attack Replay Generator",
    page_icon="🔐",
    layout="wide"
)

st.title("🔐 Smart Web Application Attack Replay Generator")
st.markdown("**Analyze web server logs, detect attack patterns, and generate replay scripts for security testing**")

st.markdown("---")

with st.sidebar:
    st.header("📋 About")
    st.markdown("""
    This tool helps security researchers and ethical hackers:
    - Parse Apache/Nginx/WAF logs
    - Detect common web attacks
    - Generate replay scripts (Python & cURL)
    - Export analysis reports
    
    **Supported Attack Types:**
    - SQL Injection
    - Cross-Site Scripting (XSS)
    - Directory Traversal
    - Command Injection
    - File Inclusion (LFI/RFI)
    """)
    
    st.markdown("---")
    
    if st.button("📄 Load Sample Log"):
        st.session_state['use_sample'] = True
        st.rerun()
    
    if st.button("🔄 Reset Analysis"):
        st.session_state.clear()
        st.rerun()

tab1, tab2, tab3, tab4 = st.tabs(["📤 Upload & Analyze", "📊 Attack Dashboard", "💾 Generate Scripts", "📈 Statistics"])

with tab1:
    st.header("Step 1: Upload Log File")
    
    log_content = None
    
    if 'use_sample' in st.session_state and st.session_state['use_sample']:
        st.info("📂 Using sample.log for demonstration")
        try:
            with open('sample.log', 'r') as f:
                log_content = f.read()
            st.session_state['use_sample'] = False
        except Exception as e:
            st.error(f"Error loading sample log: {e}")
    else:
        uploaded_file = st.file_uploader(
            "Choose a log file (Apache/Nginx format)",
            type=['log', 'txt'],
            help="Upload your web server access log file"
        )
        
        if uploaded_file is not None:
            log_content = uploaded_file.read().decode('utf-8')
    
    if log_content:
        st.success(f"✅ Log file loaded: {len(log_content.split(chr(10)))} lines")
        
        with st.expander("👁️ Preview Log Content (first 10 lines)"):
            preview_lines = log_content.split('\n')[:10]
            st.code('\n'.join(preview_lines), language='log')
        
        if st.button("🔍 Analyze Log File", type="primary"):
            with st.spinner("Parsing log file..."):
                parser = LogParser()
                parsed_logs = parser.parse_log_file(log_content)
                st.session_state['parsed_logs'] = parsed_logs
                st.session_state['total_lines'] = len(log_content.split('\n'))
            
            with st.spinner("Detecting attacks..."):
                detector = AttackDetector()
                analysis = detector.analyze_logs(parsed_logs)
                st.session_state['analysis'] = analysis
            
            st.success(f"✅ Analysis complete! Found {analysis['total_attacks']} potential attacks")
            st.rerun()

with tab2:
    st.header("📊 Attack Detection Dashboard")
    
    if 'analysis' in st.session_state:
        analysis = st.session_state['analysis']
        
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Total Attacks Detected", analysis['total_attacks'])
        with col2:
            st.metric("Unique IP Addresses", analysis['unique_ips'])
        with col3:
            st.metric("Total Log Lines", st.session_state.get('total_lines', 0))
        
        st.markdown("---")
        
        if analysis['total_attacks'] > 0:
            attack_filter = st.multiselect(
                "Filter by Attack Type",
                options=list(analysis['attack_type_counts'].keys()),
                default=list(analysis['attack_type_counts'].keys())
            )
            
            filtered_attacks = [
                attack for attack in analysis['attacks']
                if attack['attack_type'] in attack_filter
            ]
            
            st.subheader(f"🎯 Detected Attacks ({len(filtered_attacks)})")
            
            for idx, attack in enumerate(filtered_attacks, 1):
                with st.expander(
                    f"Attack #{idx}: {attack['attack_type']} - IP: {attack['ip']} - Line {attack['line_number']}"
                ):
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        st.markdown("**Attack Details:**")
                        st.write(f"**Type:** {attack['attack_type']}")
                        st.write(f"**IP Address:** {attack['ip']}")
                        st.write(f"**Timestamp:** {attack['timestamp']}")
                        st.write(f"**Method:** {attack['method']}")
                        st.write(f"**Status Code:** {attack['status']}")
                    
                    with col2:
                        st.markdown("**Payload Information:**")
                        st.write(f"**Pattern Matched:** `{attack['matched_pattern']}`")
                        st.code(attack['matched_payload'], language='text')
                    
                    st.markdown("**Full URL:**")
                    st.code(attack['full_url'], language='text')
                    
                    st.markdown("**User Agent:**")
                    st.text(attack['user_agent'])
        else:
            st.info("No attacks detected in the log file.")
    else:
        st.info("👆 Upload and analyze a log file first to see the dashboard.")

with tab3:
    st.header("💾 Generate Replay Scripts")
    
    if 'analysis' in st.session_state and st.session_state['analysis']['total_attacks'] > 0:
        analysis = st.session_state['analysis']
        
        st.markdown(f"""
        Generate executable replay scripts for **{analysis['total_attacks']} detected attacks**.
        
        **What you'll get:**
        - Python scripts using `requests` library
        - cURL commands for manual testing
        - JSON summary report
        """)
        
        if st.button("🚀 Generate All Replay Scripts", type="primary"):
            with st.spinner("Generating replay scripts..."):
                generator = ReplayGenerator()
                generator.clean_output_directory()
                
                generated_files = generator.save_replay_scripts(analysis['attacks'])
                report_file = generator.generate_summary_report(analysis, generated_files)
                
                st.session_state['generated_files'] = generated_files
                st.session_state['report_file'] = report_file
            
            st.success("✅ Replay scripts generated successfully!")
            st.rerun()
        
        if 'generated_files' in st.session_state:
            st.markdown("---")
            st.subheader("📦 Download Generated Files")
            
            generated = st.session_state['generated_files']
            
            col1, col2, col3 = st.columns(3)
            
            with col1:
                st.metric("Python Scripts", len(generated['python_scripts']))
            with col2:
                st.metric("cURL Scripts", len(generated['curl_commands']))
            with col3:
                st.metric("JSON Report", 1)
            
            zip_buffer = BytesIO()
            with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
                for file_path in generated['python_scripts']:
                    if os.path.exists(file_path):
                        zip_file.write(file_path, os.path.basename(file_path))
                
                for file_path in generated['curl_commands']:
                    if os.path.exists(file_path):
                        zip_file.write(file_path, os.path.basename(file_path))
                
                if 'report_file' in st.session_state and os.path.exists(st.session_state['report_file']):
                    zip_file.write(st.session_state['report_file'], os.path.basename(st.session_state['report_file']))
            
            zip_buffer.seek(0)
            
            st.download_button(
                label="📥 Download All Scripts (ZIP)",
                data=zip_buffer,
                file_name="attack_replay_scripts.zip",
                mime="application/zip",
                type="primary"
            )
            
            st.markdown("---")
            st.subheader("👁️ Preview Generated Scripts")
            
            if generated['python_scripts']:
                sample_script = generated['python_scripts'][0]
                if os.path.exists(sample_script):
                    with open(sample_script, 'r') as f:
                        script_content = f.read()
                    
                    with st.expander(f"Preview: {os.path.basename(sample_script)}"):
                        st.code(script_content, language='python')
            
            if 'report_file' in st.session_state and os.path.exists(st.session_state['report_file']):
                with open(st.session_state['report_file'], 'r') as f:
                    report_data = json.load(f)
                
                with st.expander("Preview: attack_summary.json"):
                    st.json(report_data)
    else:
        st.info("👆 Analyze a log file first to generate replay scripts.")

with tab4:
    st.header("📈 Attack Statistics")
    
    if 'analysis' in st.session_state and st.session_state['analysis']['total_attacks'] > 0:
        analysis = st.session_state['analysis']
        
        st.subheader("Attack Type Distribution")
        
        attack_counts = analysis['attack_type_counts']
        df_attacks = pd.DataFrame(
            list(attack_counts.items()),
            columns=['Attack Type', 'Count']
        ).sort_values('Count', ascending=False)
        
        st.bar_chart(df_attacks.set_index('Attack Type'))
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("📊 Attack Type Breakdown")
            st.dataframe(df_attacks, use_container_width=True)
        
        with col2:
            st.subheader("🌐 Top Attacking IPs")
            ip_attack_counts = {
                ip: len(attacks) for ip, attacks in analysis['ip_attacks'].items()
            }
            df_ips = pd.DataFrame(
                list(ip_attack_counts.items()),
                columns=['IP Address', 'Attack Count']
            ).sort_values('Attack Count', ascending=False).head(10)
            
            st.dataframe(df_ips, use_container_width=True)
        
        st.markdown("---")
        st.subheader("📋 Export Analysis Report")
        
        if st.button("📄 Generate JSON Report"):
            report = {
                "total_attacks": analysis['total_attacks'],
                "unique_ips": analysis['unique_ips'],
                "attack_type_counts": analysis['attack_type_counts'],
                "ip_attacks": {k: list(set(v)) for k, v in analysis['ip_attacks'].items()},
                "attacks": analysis['attacks']
            }
            
            st.download_button(
                label="💾 Download JSON Report",
                data=json.dumps(report, indent=2),
                file_name="attack_analysis_report.json",
                mime="application/json"
            )
    else:
        st.info("👆 Analyze a log file first to see statistics.")

st.markdown("---")
st.markdown(
    "<div style='text-align: center; color: gray;'>"
    "Smart Web Application Attack Replay Generator | "
    "For Ethical Hacking & Security Research Only"
    "</div>",
    unsafe_allow_html=True
)
