#!/usr/bin/env python3
"""
Main entry point for Smart Web Application Attack Replay Generator
Flask-based web application for log analysis and attack replay generation
"""

from flask_app import app

def main():
    """Launch the Flask web application."""
    print("🚀 Starting Smart Web Application Attack Replay Generator")
    print("📊 Flask Web Interface")
    print("🌐 Access at: http://localhost:5000")
    print("📝 Database: SQLite (auto-configured)")
    print()
    
    app.run(debug=True, host='0.0.0.0', port=5000)

if __name__ == "__main__":
    main()
