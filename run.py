#!/usr/bin/env python3
"""
Simple startup script for Smart Web Application Attack Replay Generator
"""

import sys
import os

def check_dependencies():
    """Check if required dependencies are available."""
    required = ['flask', 'pandas', 'numpy']
    missing = []
    
    for package in required:
        try:
            __import__(package)
        except ImportError:
            missing.append(package)
    
    if missing:
        print("❌ Missing dependencies:")
        for pkg in missing:
            print(f"   - {pkg}")
        print(f"\n📦 Install with: pip install {' '.join(missing)}")
        return False
    
    return True

def main():
    """Main startup function."""
    print("🛡️ Smart Web Application Attack Replay Generator")
    print("=" * 60)
    
    # Check dependencies
    if not check_dependencies():
        sys.exit(1)
    
    print("✅ Dependencies OK")
    
    # Create uploads directory if it doesn't exist
    os.makedirs('uploads', exist_ok=True)
    
    # Import and run the Flask app
    try:
        from flask_app import app, socketio
        
        print("\n🚀 Starting web server...")
        print("🌐 Open your browser and go to: http://localhost:5000")
        print("⏹️  Press Ctrl+C to stop\n")
        
        # Run the application
        socketio.run(app, debug=False, host='0.0.0.0', port=5000)
        
    except KeyboardInterrupt:
        print("\n👋 Goodbye!")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        print("💡 Try: python main.py")

if __name__ == "__main__":
    main()