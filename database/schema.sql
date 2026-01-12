-- Smart Web Application Attack Replay Generator Database Schema
-- PostgreSQL Database Setup

-- Create database (run this manually if needed)
-- CREATE DATABASE attack_replay_db;

-- Analysis History Table
-- Stores results from each log file analysis
CREATE TABLE IF NOT EXISTS analysis_history (
    id SERIAL PRIMARY KEY,
    filename VARCHAR(255) NOT NULL,
    total_lines INTEGER NOT NULL DEFAULT 0,
    total_attacks INTEGER NOT NULL DEFAULT 0,
    unique_ips INTEGER NOT NULL DEFAULT 0,
    attack_breakdown JSONB,
    attacks_data JSONB,
    analyzed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Custom Attack Patterns Table
-- Allows users to define their own attack detection patterns
CREATE TABLE IF NOT EXISTS custom_patterns (
    id SERIAL PRIMARY KEY,
    attack_type VARCHAR(100) NOT NULL,
    pattern_regex TEXT NOT NULL,
    description TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Unknown Attacks Table
-- Tracks suspicious requests that don't match known patterns
CREATE TABLE IF NOT EXISTS unknown_attacks (
    id SERIAL PRIMARY KEY,
    url TEXT NOT NULL,
    ip INET NOT NULL,
    timestamp VARCHAR(100),
    method VARCHAR(10),
    user_agent TEXT,
    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    frequency INTEGER DEFAULT 1,
    UNIQUE(url, ip)
);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_analysis_history_analyzed_at ON analysis_history(analyzed_at);
CREATE INDEX IF NOT EXISTS idx_analysis_history_filename ON analysis_history(filename);
CREATE INDEX IF NOT EXISTS idx_custom_patterns_active ON custom_patterns(is_active);
CREATE INDEX IF NOT EXISTS idx_custom_patterns_attack_type ON custom_patterns(attack_type);
CREATE INDEX IF NOT EXISTS idx_unknown_attacks_frequency ON unknown_attacks(frequency DESC);
CREATE INDEX IF NOT EXISTS idx_unknown_attacks_detected_at ON unknown_attacks(detected_at);
CREATE INDEX IF NOT EXISTS idx_unknown_attacks_ip ON unknown_attacks(ip);

-- Insert some sample custom patterns (optional)
INSERT INTO custom_patterns (attack_type, pattern_regex, description) VALUES
('Custom SQL Injection', '(sleep\s*\(\s*\d+\s*\)|benchmark\s*\()', 'Time-based SQL injection patterns'),
('Custom XSS', '(fromCharCode|unescape|decodeURI)', 'Encoded XSS patterns'),
('Custom Command Injection', '(whoami|id\s|pwd\s)', 'System information gathering commands')
ON CONFLICT DO NOTHING;

-- Sample data for testing (optional)
-- Uncomment the following lines if you want sample data

/*
INSERT INTO analysis_history (filename, total_lines, total_attacks, unique_ips, attack_breakdown, attacks_data) VALUES
('sample_test.log', 100, 15, 8, 
 '{"SQL Injection": 5, "XSS": 4, "Directory Traversal": 3, "Command Injection": 2, "File Inclusion": 1}',
 '[]'
),
('another_test.log', 250, 32, 12,
 '{"SQL Injection": 12, "XSS": 8, "Directory Traversal": 7, "Command Injection": 3, "File Inclusion": 2}',
 '[]'
);

INSERT INTO unknown_attacks (url, ip, timestamp, method, user_agent, frequency) VALUES
('/suspicious.php?param=malicious_value', '192.168.1.100', '19/Nov/2025:10:15:23 +0000', 'GET', 'Unknown Scanner', 5),
('/test.php?input=suspicious_input', '203.0.113.45', '19/Nov/2025:10:16:45 +0000', 'POST', 'Custom Bot', 3);
*/