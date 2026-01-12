# AttackReplay Pro

Advanced Web Application Security Testing Platform with AI-powered attack detection and replay generation.

## 🚀 Features

- **Smart Attack Detection**: Detects SQL injection, XSS, command injection, and more
- **AI-Powered Analysis**: Uses Groq AI for unknown attack pattern detection
- **ML-Based Learning**: Machine learning for behavioral analysis and anomaly detection
- **HTTP Traffic Monitoring**: Built-in proxy for real-time traffic capture
- **Custom Pattern Management**: Create and manage custom attack detection patterns
- **Replay Script Generation**: Automatically generate Python and cURL attack scripts
- **Comprehensive Dashboard**: Visual analysis with filtering and statistics
- **Batch Processing**: Analyze multiple log files simultaneously

## 📦 Installation

### Prerequisites
- Python 3.8 or higher
- pip package manager

### Install Dependencies
```bash
pip install -r requirements.txt
```

### Optional: ML Features
For machine learning capabilities:
```bash
pip install -r requirements_ml.txt
```

## 🎯 Quick Start

### 1. Start the Application
```bash
python flask_app.py
```
Or use the simple runner:
```bash
python run.py
```

### 2. Access Web Interface
Open your browser and go to: `http://localhost:5000`

### 3. Upload Log Files
- Go to "Upload & Analyze" page
- Upload Apache/Nginx format log files
- Enable "ML Based Learning" for advanced detection
- View results in the Dashboard

## 🧪 HTTP Traffic Testing

Generate test attack traffic for analysis:

### Quick Testing
```bash
python simple_http_tester.py
```

### Comprehensive Testing
```bash
python http_attack_tester.py
```

### Using Menu Scripts
**Windows:**
```cmd
run_http_tests.bat
```

**Linux/Mac:**
```bash
./run_http_tests.sh
```

See [HTTP_TESTING_README.md](HTTP_TESTING_README.md) for detailed testing instructions.

## 📊 Usage Workflow

1. **Generate Traffic**: Use HTTP testing tools or capture real traffic
2. **Start Proxy** (optional): Use built-in HTTP proxy for traffic capture
3. **Export Logs**: Export captured traffic in Apache/Nginx log format
4. **Upload & Analyze**: Upload logs with ML-based learning enabled
5. **Review Dashboard**: View detected attacks with filtering options
6. **Manage Patterns**: Add custom attack detection patterns
7. **Generate Scripts**: Create executable attack replay scripts

## 🔧 Configuration

### Database
- **SQLite**: Default database (no setup required)
- **PostgreSQL**: Set environment variables for production use

### AI Integration
- **Groq API**: Set API key for AI-based threat detection
- **Content Filtering**: Automatic sanitization for AI analysis

### Proxy Settings
- **HTTP Proxy**: Built-in proxy on port 8080
- **HTTPS Support**: SSL interception with certificate generation

## 📁 Project Structure

```
AttackReplay Pro/
├── flask_app.py              # Main Flask application
├── run.py                    # Simple startup script
├── sample.log                # Sample log file for testing
├── attack_replay.db          # SQLite database
├── requirements.txt          # Python dependencies
├── requirements_ml.txt       # ML dependencies
├── http_attack_tester.py     # Comprehensive HTTP tester
├── simple_http_tester.py     # Quick HTTP tester
├── HTTP_TESTING_README.md    # HTTP testing documentation
├── batch/                    # Batch processing modules
├── database/                 # Database management
├── detector/                 # Attack detection engines
├── generator/                # Script generation
├── ml/                       # Machine learning modules
├── parser/                   # Log parsing utilities
├── proxy/                    # HTTP/HTTPS proxy
├── reporting/                # Report generation
├── static/                   # Web assets
├── templates/                # HTML templates
└── uploads/                  # File upload directory
```

## 🎨 Web Interface

### Main Pages
- **Dashboard**: Attack analysis with filtering
- **Upload & Analyze**: Log file upload and processing
- **Statistics**: Visual attack statistics and charts
- **HTTP History**: Real-time traffic monitoring
- **Custom Patterns**: Manage attack detection patterns
- **Generate Scripts**: Create attack replay scripts
- **Batch Processing**: Multi-file analysis

### Key Features
- **Real-time Updates**: WebSocket-based live updates
- **Responsive Design**: Works on desktop and mobile
- **Dark/Light Theme**: Automatic theme detection
- **Export Options**: Multiple export formats
- **Filter Controls**: Advanced filtering and search

## 🤖 AI & ML Features

### AI-Based Detection
- **Groq Integration**: Advanced threat analysis
- **Content Sanitization**: Safe AI processing
- **Pattern Learning**: Automatic pattern recognition

### Machine Learning
- **Anomaly Detection**: Behavioral analysis
- **Feature Extraction**: 50+ traffic features
- **Ensemble Methods**: Multiple ML algorithms
- **Unknown Pattern Detection**: Identifies new attack types

## 🔒 Security Features

### Attack Detection
- **SQL Injection**: Multiple injection techniques
- **XSS**: Cross-site scripting variants
- **Command Injection**: System command execution
- **Directory Traversal**: File system access
- **File Inclusion**: Local/remote file inclusion
- **NoSQL Injection**: MongoDB and similar
- **LDAP Injection**: Directory service attacks
- **XXE**: XML external entity attacks

### Traffic Analysis
- **Real-time Monitoring**: Live traffic capture
- **SSL Interception**: HTTPS traffic analysis
- **User Agent Analysis**: Suspicious tool detection
- **Rate Limiting**: Rapid request detection

## 📈 Analytics & Reporting

### Dashboard Analytics
- **Attack Statistics**: Counts and breakdowns
- **IP Analysis**: Unique attackers
- **Timeline Views**: Attack patterns over time
- **Success Rates**: Attack effectiveness

### Export Options
- **Apache Log Format**: Standard web server logs
- **JSON Export**: Structured data export
- **Script Generation**: Executable attack scripts
- **PDF Reports**: Comprehensive analysis reports

## 🛠️ Development

### Running in Development
```bash
python flask_app.py
```

### Database Setup
```bash
python database/setup_database.py
```

### Testing
Use the HTTP testing tools to generate test traffic:
```bash
python http_attack_tester.py
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test with HTTP testing tools
5. Submit a pull request

## 📄 License

This project is for educational and authorized security testing purposes only.

## ⚠️ Disclaimer

**Important**: This tool is designed for authorized security testing only. Only use on systems you own or have explicit written permission to test. Unauthorized use is illegal and unethical.

### Responsible Use
- ✅ Test your own applications
- ✅ Use in authorized penetration testing
- ✅ Educational and research purposes
- ❌ Never test systems without permission
- ❌ Don't use for malicious purposes

## 📞 Support

For questions or issues:
1. Check the documentation files
2. Review the HTTP testing guide
3. Test with sample data first
4. Ensure proper configuration

---

**AttackReplay Pro** - Advanced Web Application Security Testing Platform