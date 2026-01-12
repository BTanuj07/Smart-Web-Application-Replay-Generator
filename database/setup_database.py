#!/usr/bin/env python3
"""
Database Setup Script for Smart Web Application Attack Replay Generator

This script creates the required database tables for the application.
Run this script before using the timeline view and unknown attacks features.

Usage:
    python database/setup_database.py

Environment Variables Required:
    PGDATABASE - Database name
    PGUSER - Database username  
    PGPASSWORD - Database password
    PGHOST - Database host (default: localhost)
    PGPORT - Database port (default: 5432)
"""

import os
import sys
from pathlib import Path

try:
    import psycopg2
    from psycopg2 import sql
except ImportError:
    print("❌ Error: psycopg2-binary is required but not installed.")
    print("Install it with: pip install psycopg2-binary")
    sys.exit(1)

def get_db_config():
    """Get database configuration from environment variables."""
    config = {
        'dbname': os.getenv('PGDATABASE'),
        'user': os.getenv('PGUSER'),
        'password': os.getenv('PGPASSWORD'),
        'host': os.getenv('PGHOST', 'localhost'),
        'port': os.getenv('PGPORT', '5432')
    }
    
    missing = [key for key, value in config.items() if not value and key != 'host' and key != 'port']
    if missing:
        print(f"❌ Missing required environment variables: {', '.join(missing.upper())}")
        print("\nSet them like this:")
        print("export PGDATABASE=your_database_name")
        print("export PGUSER=your_username")
        print("export PGPASSWORD=your_password")
        print("export PGHOST=localhost  # optional")
        print("export PGPORT=5432       # optional")
        sys.exit(1)
    
    return config

def read_schema_file():
    """Read the SQL schema file."""
    schema_path = Path(__file__).parent / 'schema.sql'
    if not schema_path.exists():
        print(f"❌ Schema file not found: {schema_path}")
        sys.exit(1)
    
    with open(schema_path, 'r') as f:
        return f.read()

def setup_database():
    """Create database tables and indexes."""
    print("🔧 Setting up Smart Web Attack Replay Generator Database...")
    
    # Get configuration
    config = get_db_config()
    print(f"📡 Connecting to database: {config['dbname']} at {config['host']}:{config['port']}")
    
    try:
        # Connect to database
        conn = psycopg2.connect(**config)
        conn.autocommit = True
        
        print("✅ Database connection successful!")
        
        # Read and execute schema
        schema_sql = read_schema_file()
        
        with conn.cursor() as cursor:
            print("📋 Creating tables and indexes...")
            cursor.execute(schema_sql)
            
            # Check if tables were created
            cursor.execute("""
                SELECT table_name 
                FROM information_schema.tables 
                WHERE table_schema = 'public' 
                AND table_name IN ('analysis_history', 'custom_patterns', 'unknown_attacks')
                ORDER BY table_name;
            """)
            
            tables = cursor.fetchall()
            print(f"✅ Created {len(tables)} tables:")
            for table in tables:
                print(f"   - {table[0]}")
            
            # Check custom patterns
            cursor.execute("SELECT COUNT(*) FROM custom_patterns;")
            pattern_count = cursor.fetchone()[0]
            print(f"📝 Custom patterns available: {pattern_count}")
        
        conn.close()
        print("\n🎉 Database setup completed successfully!")
        print("\n📖 Next steps:")
        print("1. Run the Flask app: python flask_app.py")
        print("2. Enable 'Pattern Learning' during log analysis")
        print("3. Upload log files to see timeline and unknown attacks")
        
    except psycopg2.Error as e:
        print(f"❌ Database error: {e}")
        print("\n🔍 Troubleshooting:")
        print("1. Make sure PostgreSQL is running")
        print("2. Verify database credentials")
        print("3. Check if database exists")
        print("4. Ensure user has CREATE TABLE permissions")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        sys.exit(1)

def check_database_status():
    """Check if database is properly configured."""
    print("🔍 Checking database status...")
    
    config = get_db_config()
    
    try:
        conn = psycopg2.connect(**config)
        
        with conn.cursor() as cursor:
            # Check if tables exist
            cursor.execute("""
                SELECT table_name 
                FROM information_schema.tables 
                WHERE table_schema = 'public' 
                AND table_name IN ('analysis_history', 'custom_patterns', 'unknown_attacks');
            """)
            
            existing_tables = [row[0] for row in cursor.fetchall()]
            required_tables = ['analysis_history', 'custom_patterns', 'unknown_attacks']
            
            print(f"📊 Database: {config['dbname']}")
            print(f"🏠 Host: {config['host']}:{config['port']}")
            print(f"👤 User: {config['user']}")
            
            if len(existing_tables) == len(required_tables):
                print("✅ All required tables exist")
                
                # Check data counts
                for table in required_tables:
                    cursor.execute(f"SELECT COUNT(*) FROM {table};")
                    count = cursor.fetchone()[0]
                    print(f"   - {table}: {count} records")
                
                print("\n🎉 Database is ready for use!")
            else:
                missing = set(required_tables) - set(existing_tables)
                print(f"❌ Missing tables: {', '.join(missing)}")
                print("Run setup to create missing tables.")
        
        conn.close()
        
    except Exception as e:
        print(f"❌ Cannot connect to database: {e}")
        return False
    
    return True

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "check":
        check_database_status()
    else:
        setup_database()