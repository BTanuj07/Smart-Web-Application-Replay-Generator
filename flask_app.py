#!/usr/bin/env python3
"""
Flask Web Application for Smart Web Application Attack Replay Generator
Modern web interface for log analysis and attack replay generation
"""

import os
import json
import zipfile
from io import BytesIO
import re
from datetime import datetime
from flask import Flask, render_template, request, jsonify, send_file, flash, redirect, url_for, session
from flask_socketio import SocketIO, emit
from werkzeug.utils import secure_filename

from parser.log_parser import LogParser
from detector.attack_detector import AttackDetector
from generator.replay_generator import ReplayGenerator
from database.db_manager import DatabaseManager
from batch.batch_processor import BatchProcessor
from proxy.proxy_controller import ProxyController

app = Flask(__name__, static_folder='static', static_url_path='/static')
app.secret_key = 'your-secret-key-change-this-in-production'

# Initialize SocketIO for real-time features
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')

# Initialize proxy controller
proxy_controller = ProxyController(socketio)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['UPLOAD_FOLDER'] = 'uploads'

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize database
try:
    db_manager = DatabaseManager()
    db_available = db_manager.db_available
    
    # Initialize database components
    if db_available:
        # Database components initialized
        pass
        
except Exception as e:
    print(f"Database initialization failed: {e}")
    db_manager = None
    db_available = False

@app.route('/favicon.ico')
def favicon():
    """Serve favicon."""
    return send_file('static/favicon.svg', mimetype='image/svg+xml')

@app.route('/debug_upload')
def debug_upload():
    """Debug upload page for testing."""
    return send_file('debug_upload.html')

@app.route('/simple_test')
def simple_test():
    """Simple upload test page."""
    return send_file('simple_upload_test.html')

@app.route('/')
def index():
    """Main dashboard page."""
    return render_template('index.html', db_available=db_available)

@app.route('/upload', methods=['GET', 'POST'])
def upload_analyze():
    """Upload and analyze log files."""
    if request.method == 'GET':
        return render_template('upload.html', db_available=db_available)
    
    analysis_results = None
    error_message = None
    
    try:
        # Check if using sample log
        if 'use_sample' in request.form:
            with open('sample.log', 'r') as f:
                log_content = f.read()
            filename = 'sample.log'
        else:
            # Handle file upload
            if 'log_file' not in request.files:
                flash('No file part in the request', 'error')
                return render_template('upload.html', db_available=db_available)
            
            file = request.files['log_file']
            if file.filename == '' or file.filename is None:
                flash('No file selected', 'error')
                return render_template('upload.html', db_available=db_available)
            
            # Check if file has content
            if file and file.filename:
                filename = secure_filename(file.filename)
                try:
                    log_content = file.read().decode('utf-8')
                    if not log_content.strip():
                        flash('The uploaded file is empty', 'error')
                        return render_template('upload.html', db_available=db_available)
                except UnicodeDecodeError:
                    flash('Unable to read file. Please ensure it\'s a text file with UTF-8 encoding.', 'error')
                    return render_template('upload.html', db_available=db_available)
            else:
                flash('Invalid file', 'error')
                return render_template('upload.html', db_available=db_available)
        
        # Parse log file
        parser = LogParser()
        parsed_logs = parser.parse_log_file(log_content)
        total_lines = len(log_content.split('\n'))
        non_empty_lines = len([l for l in log_content.split('\n') if l.strip()])
        
        if not parsed_logs:
            flash(f'No valid log entries found. Checked {non_empty_lines} non-empty lines out of {total_lines} total lines.', 'warning')
            
            # Show sample of first few lines for debugging
            sample_lines = [l.strip() for l in log_content.split('\n')[:3] if l.strip()]
            if sample_lines:
                flash(f'Sample line: {sample_lines[0][:100]}...', 'info')
                flash('Please ensure your log file follows Apache/Nginx format: IP - - [timestamp] "METHOD /path HTTP/1.1" status size "referer" "user-agent"', 'info')
            
            return render_template('upload.html', db_available=db_available)
        
        flash(f'Successfully parsed {len(parsed_logs)} of {non_empty_lines} log entries', 'success')
        
        # Get processing options - single checkbox enables all ML features
        enable_learning = request.form.get('enable_learning') == 'on' and db_available
        enable_ml = enable_learning  # Enable ML when learning is enabled
        enable_ai_analysis = enable_learning  # Enable AI when learning is enabled
        
        detector = AttackDetector(
            db_manager=db_manager if db_available else None,
            enable_learning=enable_learning,
            enable_ml=enable_ml
        )
        analysis = detector.analyze_logs(parsed_logs)
        
        # Save to database if available
        if db_available and db_manager:
            try:
                analysis_id = db_manager.save_analysis(
                    filename=filename,
                    total_lines=total_lines,
                    total_attacks=analysis['total_attacks'],
                    unique_ips=analysis['unique_ips'],
                    attack_breakdown=analysis['attack_type_counts'],
                    attacks_data=analysis['attacks']
                )
                analysis['analysis_id'] = analysis_id
            except Exception as e:
                flash(f'Could not save to database: {str(e)}', 'warning')
        
        # Store in session for other pages
        session['analysis'] = analysis
        session['filename'] = filename
        session['total_lines'] = total_lines
        
        analysis_results = analysis
        
        if enable_learning and analysis.get('unknown_tracked', 0) > 0:
            flash(f'Tracked {analysis["unknown_tracked"]} unknown suspicious requests', 'info')
        
        flash(f'Analysis complete! Found {analysis["total_attacks"]} potential attacks', 'success')
        
    except Exception as e:
        error_message = str(e)
        flash(f'Error analyzing log file: {error_message}', 'error')
    
    return render_template('upload.html', 
                         analysis=analysis_results, 
                         error=error_message,
                         db_available=db_available)

@app.route('/dashboard')
def dashboard():
    """Attack detection dashboard."""
    # Try to get analysis from session first (current upload)
    analysis = session.get('analysis')
    
    # If no session data and database is available, get latest analysis
    if not analysis and db_available and db_manager:
        try:
            history = db_manager.get_analysis_history(limit=1)
            if history:
                latest = history[0]
                # Get full analysis data including attacks
                full_analysis = db_manager.get_analysis_by_id(latest['id'])
                if full_analysis:
                    # Reconstruct analysis data from database
                    analysis = {
                        'total_attacks': full_analysis['total_attacks'],
                        'unique_ips': full_analysis['unique_ips'],
                        'attack_type_counts': full_analysis['attack_breakdown'],
                        'attacks': full_analysis['attacks_data'],  # Now includes individual attacks
                        'ip_attacks': {}  # Empty dict to prevent template errors
                    }
                    session['analysis'] = analysis  # Store in session for this request
                    session['filename'] = full_analysis['filename']
                    flash(f'Showing latest analysis: {full_analysis["filename"]}', 'info')
        except Exception as e:
            print(f"Error loading latest analysis: {e}")
    
    if not analysis:
        flash('No analysis data available. Please upload and analyze a log file first.', 'warning')
        return redirect(url_for('upload_analyze'))
    
    return render_template('dashboard.html', analysis=analysis, db_available=db_available)

@app.route('/generate')
def generate_scripts():
    """Generate replay scripts."""
    analysis = session.get('analysis')
    if not analysis or analysis['total_attacks'] == 0:
        flash('No attacks detected. Please analyze a log file with attacks first.', 'warning')
        return redirect(url_for('upload_analyze'))
    
    return render_template('generate.html', analysis=analysis, db_available=db_available)

@app.route('/generate_scripts', methods=['POST'])
def do_generate_scripts():
    """Actually generate the replay scripts."""
    analysis = session.get('analysis')
    if not analysis:
        return jsonify({'error': 'No analysis data available'}), 400
    
    try:
        generator = ReplayGenerator()
        generator.clean_output_directory()
        
        generated_files = generator.save_replay_scripts(analysis['attacks'])
        report_file = generator.generate_summary_report(analysis, generated_files)
        
        session['generated_files'] = generated_files
        session['report_file'] = report_file
        
        return jsonify({
            'success': True,
            'python_scripts': len(generated_files['python_scripts']),
            'curl_scripts': len(generated_files['curl_commands']),
            'batch_script': bool(generated_files.get('batch_script')),
            'readme_included': bool(generated_files.get('readme')),
            'total_files': (len(generated_files['python_scripts']) + 
                          len(generated_files['curl_commands']) + 
                          (1 if generated_files.get('batch_script') else 0) +
                          (1 if generated_files.get('readme') else 0)),
            'report_file': report_file
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/download_scripts')
def download_scripts():
    """Download generated scripts as ZIP."""
    generated_files = session.get('generated_files')
    report_file = session.get('report_file')
    
    if not generated_files:
        flash('No generated files available. Generate scripts first.', 'error')
        return redirect(url_for('generate_scripts'))
    
    # Create ZIP file in memory
    zip_buffer = BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
        # Add Python scripts
        for file_path in generated_files['python_scripts']:
            if os.path.exists(file_path):
                zip_file.write(file_path, os.path.basename(file_path))
        
        # Add cURL scripts
        for file_path in generated_files['curl_commands']:
            if os.path.exists(file_path):
                zip_file.write(file_path, os.path.basename(file_path))
        
        # Add batch script
        if generated_files.get('batch_script') and os.path.exists(generated_files['batch_script']):
            zip_file.write(generated_files['batch_script'], os.path.basename(generated_files['batch_script']))
        
        # Add README
        if generated_files.get('readme') and os.path.exists(generated_files['readme']):
            zip_file.write(generated_files['readme'], os.path.basename(generated_files['readme']))
        
        # Add report file
        if report_file and os.path.exists(report_file):
            zip_file.write(report_file, os.path.basename(report_file))
    
    zip_buffer.seek(0)
    
    return send_file(
        zip_buffer,
        as_attachment=True,
        download_name='attack_replay_scripts.zip',
        mimetype='application/zip'
    )

@app.route('/statistics')
def statistics():
    """Attack statistics page."""
    # Try to get analysis from session first (current upload)
    analysis = session.get('analysis')
    
    # If no session data and database is available, get latest analysis
    if not analysis and db_available and db_manager:
        try:
            history = db_manager.get_analysis_history(limit=1)
            if history:
                latest = history[0]
                # Get full analysis data including attacks
                full_analysis = db_manager.get_analysis_by_id(latest['id'])
                if full_analysis:
                    # Reconstruct analysis data from database
                    analysis = {
                        'total_attacks': full_analysis['total_attacks'],
                        'unique_ips': full_analysis['unique_ips'],
                        'attack_type_counts': full_analysis['attack_breakdown'],
                        'attacks': full_analysis['attacks_data'],  # Now includes individual attacks
                        'ip_attacks': {}  # Empty dict to prevent template errors
                    }
                    session['analysis'] = analysis  # Store in session for this request
                    session['filename'] = full_analysis['filename']
                    flash(f'Showing statistics for: {full_analysis["filename"]}', 'info')
        except Exception as e:
            print(f"Error loading latest analysis: {e}")
    
    if not analysis:
        flash('No analysis data available. Please upload and analyze a log file first.', 'warning')
        return redirect(url_for('upload_analyze'))
    
    return render_template('statistics.html', analysis=analysis, db_available=db_available)

@app.route('/batch')
def batch_processing():
    """Batch processing page."""
    return render_template('batch.html', db_available=db_available)

@app.route('/batch_process', methods=['POST'])
def do_batch_process():
    """Process multiple files with AI/ML capabilities."""
    if 'files[]' not in request.files:
        return jsonify({'error': 'No files uploaded'}), 400
    
    files = request.files.getlist('files[]')
    if not files or all(f.filename == '' for f in files):
        return jsonify({'error': 'No files selected'}), 400
    
    try:
        files_data = []
        for file in files:
            if file.filename != '':
                filename = secure_filename(file.filename)
                content = file.read().decode('utf-8')
                files_data.append((filename, content))
        
        # Get processing options - single checkbox enables all ML features
        enable_learning = request.form.get('enable_learning') == 'on' and db_available
        enable_ml = enable_learning  # Enable ML when learning is enabled
        enable_ai_analysis = enable_learning  # Enable AI when learning is enabled
        
        # Initialize batch processor
        processor = BatchProcessor(db_manager=db_manager if db_available else None)
        
        # Process files with enhanced capabilities
        results = processor.process_multiple_files(
            files_data, 
            enable_learning=enable_learning,
            enable_ml=enable_ml,
            enable_ai_analysis=enable_ai_analysis
        )
        
        # Get enhanced summary
        summary = processor.get_batch_summary(results)
        
        # Get AI threat summary if AI analysis was enabled
        ai_summary = {}
        if enable_ai_analysis and db_available:
            ai_summary = processor.get_ai_threat_summary(results)
        
        # Store results in session
        session['batch_results'] = results
        session['batch_summary'] = summary
        session['batch_ai_summary'] = ai_summary
        
        return jsonify({
            'success': True,
            'summary': summary,
            'results': results,
            'ai_summary': ai_summary,
            'processing_options': {
                'learning_enabled': enable_learning,
                'ml_enabled': enable_ml,
                'ai_enabled': enable_ai_analysis
            }
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/timeline')
def timeline():
    """Timeline visualization page."""
    if not db_available:
        flash('Timeline visualization requires database. Database is currently unavailable.', 'warning')
        return render_template('timeline.html', db_available=False, timeline_data=None, history=None)
    
    try:
        timeline_data = db_manager.get_timeline_data(days=30)
        history = db_manager.get_analysis_history(limit=20)
        
        # Add summary statistics
        total_analyses = len(history)
        total_attacks = sum(h['total_attacks'] for h in history)
        total_ips = sum(h['unique_ips'] for h in history)
        
        summary = {
            'total_analyses': total_analyses,
            'total_attacks': total_attacks,
            'total_unique_ips': total_ips,
            'avg_attacks_per_analysis': round(total_attacks / total_analyses, 2) if total_analyses > 0 else 0
        }
        
        return render_template('timeline.html', 
                             db_available=True, 
                             timeline_data=timeline_data, 
                             history=history,
                             summary=summary)
    except Exception as e:
        flash(f'Unable to load timeline data: {str(e)}', 'error')
        return render_template('timeline.html', db_available=False, timeline_data=None, history=None)

@app.route('/unknown_attacks')
def unknown_attacks():
    """Unknown attacks pattern learning page."""
    if not db_available:
        flash('Pattern learning requires database. Database is currently unavailable.', 'warning')
        return render_template('unknown_attacks.html', db_available=False, unknown_attacks=None)
    
    try:
        unknown = db_manager.get_unknown_attacks(limit=100)
        return render_template('unknown_attacks.html', 
                             db_available=True, 
                             unknown_attacks=unknown)
    except Exception as e:
        flash(f'Error loading unknown attacks: {str(e)}', 'error')
        return render_template('unknown_attacks.html', db_available=False, unknown_attacks=None)

@app.route('/clear_unknown', methods=['POST'])
def clear_unknown():
    """Clear all unknown attacks."""
    if not db_available:
        return jsonify({'error': 'Database not available'}), 400
    
    try:
        db_manager.clear_unknown_attacks()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/custom_patterns')
def custom_patterns():
    """Custom pattern management page."""
    if not db_available:
        flash('Custom pattern management requires database. Database is currently unavailable.', 'warning')
        return render_template('custom_patterns.html', db_available=False, patterns=None)
    
    try:
        patterns = db_manager.get_custom_patterns(active_only=False)
        return render_template('custom_patterns.html', 
                             db_available=True, 
                             patterns=patterns)
    except Exception as e:
        flash(f'Error loading custom patterns: {str(e)}', 'error')
        return render_template('custom_patterns.html', db_available=False, patterns=None)

@app.route('/add_pattern', methods=['POST'])
def add_pattern():
    """Add a new custom pattern."""
    if not db_available:
        return jsonify({'error': 'Database not available'}), 400
    
    attack_type = request.form.get('attack_type')
    pattern_regex = request.form.get('pattern_regex')
    description = request.form.get('description', '')
    
    if not attack_type or not pattern_regex:
        return jsonify({'error': 'Attack type and pattern are required'}), 400
    
    try:
        # Validate regex
        re.compile(pattern_regex)
        
        pattern_id = db_manager.add_custom_pattern(attack_type, pattern_regex, description)
        return jsonify({'success': True, 'pattern_id': pattern_id})
    except re.error:
        return jsonify({'error': 'Invalid regex pattern'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/update_pattern/<int:pattern_id>', methods=['POST'])
def update_pattern(pattern_id):
    """Update a custom pattern."""
    if not db_available:
        return jsonify({'error': 'Database not available'}), 400
    
    try:
        action = request.form.get('action')
        if action == 'toggle':
            is_active = request.form.get('is_active') == 'true'
            db_manager.update_custom_pattern(pattern_id, is_active=is_active)
        elif action == 'delete':
            db_manager.delete_custom_pattern(pattern_id)
        
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/load_analysis/<int:analysis_id>')
def load_analysis(analysis_id):
    """Load a specific analysis by ID."""
    if not db_available:
        flash('Database not available', 'error')
        return redirect(url_for('upload_analyze'))
    
    try:
        # Get specific analysis (you'll need to add this method to db_manager)
        history = db_manager.get_analysis_history(limit=100)  # Get more records
        analysis_record = None
        
        for record in history:
            if record['id'] == analysis_id:
                analysis_record = record
                break
        
        if not analysis_record:
            flash(f'Analysis with ID {analysis_id} not found', 'error')
            return redirect(url_for('timeline'))
        
        # Reconstruct analysis data
        analysis = {
            'total_attacks': analysis_record['total_attacks'],
            'unique_ips': analysis_record['unique_ips'],
            'attack_type_counts': analysis_record['attack_breakdown'],
            'attacks': []  # Could load detailed attacks if stored
        }
        
        # Store in session
        session['analysis'] = analysis
        session['filename'] = analysis_record['filename']
        session['analysis_id'] = analysis_id
        
        flash(f'Loaded analysis: {analysis_record["filename"]} (ID: {analysis_id})', 'success')
        return redirect(url_for('dashboard'))
        
    except Exception as e:
        flash(f'Error loading analysis: {str(e)}', 'error')
        return redirect(url_for('timeline'))

@app.route('/api/analysis_data')
def api_analysis_data():
    """API endpoint to get current analysis data."""
    # Try to get analysis from session first (current upload)
    analysis = session.get('analysis')
    
    # If no session data and database is available, get latest analysis
    if not analysis and db_available and db_manager:
        try:
            history = db_manager.get_analysis_history(limit=1)
            if history:
                latest = history[0]
                # Get full analysis data including attacks
                full_analysis = db_manager.get_analysis_by_id(latest['id'])
                if full_analysis:
                    # Reconstruct analysis data from database
                    analysis = {
                        'total_attacks': full_analysis['total_attacks'],
                        'unique_ips': full_analysis['unique_ips'],
                        'attack_type_counts': full_analysis['attack_breakdown'],
                        'attacks': full_analysis['attacks_data'],  # Now includes individual attacks
                        'ip_attacks': {}  # Empty dict to prevent template errors
                    }
        except Exception as e:
            print(f"Error loading latest analysis: {e}")
    
    if not analysis:
        return jsonify({'error': 'No analysis data available'}), 404
    
    return jsonify(analysis)

@app.route('/api/timeline_data')
def api_timeline_data():
    """API endpoint to get timeline data for charts."""
    if not db_available:
        return jsonify({'error': 'Database not available'}), 400
    
    try:
        days = request.args.get('days', 30, type=int)
        timeline_data = db_manager.get_timeline_data(days=days)
        return jsonify(timeline_data)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/http_history')
def http_history():
    """HTTP History dashboard (Burp Suite style)."""
    return render_template('http_history.html')

# Proxy API endpoints
@app.route('/api/proxy/start', methods=['POST'])
def start_proxy():
    """Start the HTTP proxy server."""
    try:
        data = request.get_json() or {}
        enable_https = data.get('enable_https', False)
        
        # Check if cryptography is available for HTTPS
        if enable_https:
            try:
                import cryptography
            except ImportError:
                return jsonify({
                    'success': False, 
                    'error': 'HTTPS interception requires cryptography library. Install with: pip install cryptography>=3.0.0'
                }), 400
        
        success = proxy_controller.start_proxy(enable_https_interception=enable_https)
        if success:
            proxy_info = proxy_controller.get_proxy_info()
            response_data = {
                'success': True, 
                'message': 'Proxy started successfully',
                'https_enabled': enable_https
            }
            
            # Add CA certificate path if HTTPS is enabled
            if enable_https:
                ca_cert_path = proxy_info.get('ca_cert_path')
                if ca_cert_path:
                    response_data['ca_cert_path'] = ca_cert_path
                    response_data['ca_cert_available'] = os.path.exists(ca_cert_path)
                else:
                    response_data['warning'] = 'HTTPS enabled but CA certificate not available'
            
            return jsonify(response_data)
        else:
            return jsonify({'success': False, 'error': 'Failed to start proxy. Check console for details.'}), 500
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/proxy/stop', methods=['POST'])
def stop_proxy():
    """Stop the HTTP proxy server."""
    try:
        success = proxy_controller.stop_proxy()
        if success:
            return jsonify({'success': True, 'message': 'Proxy stopped successfully'})
        else:
            return jsonify({'success': False, 'error': 'Failed to stop proxy'}), 500
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/proxy/status')
def proxy_status():
    """Get proxy status."""
    try:
        return jsonify(proxy_controller.get_proxy_info())
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/proxy/history', methods=['GET', 'POST'])
def proxy_history():
    """Get traffic history with optional filtering."""
    try:
        if request.method == 'POST':
            # Apply filters
            filter_params = request.get_json() or {}
            traffic = proxy_controller.get_traffic_history(filter_params)
        else:
            # Get all traffic
            traffic = proxy_controller.get_traffic_history()
        
        return jsonify(traffic)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/proxy/transaction/<transaction_id>')
def proxy_transaction_details(transaction_id):
    """Get detailed transaction information."""
    try:
        transaction = proxy_controller.get_transaction_details(transaction_id)
        if transaction:
            return jsonify(transaction)
        else:
            return jsonify({'error': 'Transaction not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/proxy/clear', methods=['POST'])
def clear_proxy_history():
    """Clear all traffic history."""
    try:
        proxy_controller.clear_traffic_history()
        return jsonify({'success': True, 'message': 'Traffic history cleared'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/proxy/stats')
def proxy_statistics():
    """Get traffic statistics."""
    try:
        stats = proxy_controller.get_traffic_statistics()
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/proxy/export')
def export_proxy_traffic():
    """Export traffic data."""
    try:
        format_type = request.args.get('format', 'json')
        data = proxy_controller.export_traffic(format_type)
        
        if format_type == 'json':
            return app.response_class(
                data,
                mimetype='application/json',
                headers={'Content-Disposition': 'attachment; filename=traffic_export.json'}
            )
        elif format_type == 'txt':
            return app.response_class(
                data,
                mimetype='text/plain',
                headers={'Content-Disposition': 'attachment; filename=traffic_export.log'}
            )
        else:
            return jsonify({'error': 'Unsupported format'}), 400
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/proxy/ca-certificate')
def download_ca_certificate():
    """Download CA certificate for browser installation."""
    try:
        # Check if proxy is running with HTTPS
        if not proxy_controller.is_running():
            return jsonify({'error': 'Proxy is not running. Please start the proxy with HTTPS interception enabled.'}), 400
        
        proxy_info = proxy_controller.get_proxy_info()
        
        if not proxy_info.get('https_enabled', False):
            return jsonify({'error': 'HTTPS interception is not enabled. Please restart the proxy with HTTPS interception.'}), 400
        
        ca_cert_path = proxy_info.get('ca_cert_path')
        
        if not ca_cert_path:
            return jsonify({'error': 'CA certificate path not available. HTTPS interception may not be properly initialized.'}), 404
        
        if not os.path.exists(ca_cert_path):
            return jsonify({'error': f'CA certificate file not found at {ca_cert_path}. Please restart the proxy with HTTPS interception.'}), 404
        
        return send_file(
            ca_cert_path,
            as_attachment=True,
            download_name='proxy_ca_certificate.crt',
            mimetype='application/x-x509-ca-cert'
        )
        
    except Exception as e:
        return jsonify({'error': f'Error downloading CA certificate: {str(e)}'}), 500

# WebSocket endpoint for real-time traffic streaming
@socketio.on('connect')
def handle_connect():
    """Handle WebSocket connection."""
    print(f"Client connected: {request.sid}")
    proxy_controller.subscribe_to_stream(request.sid)

@socketio.on('disconnect')
def handle_disconnect():
    """Handle WebSocket disconnection."""
    print(f"Client disconnected: {request.sid}")
    proxy_controller.unsubscribe_from_stream(request.sid)

if __name__ == '__main__':
    # Run with SocketIO support using eventlet
    socketio.run(app, debug=False, host='0.0.0.0', port=5000, async_mode='eventlet')