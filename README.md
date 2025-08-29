# Forensic AI Log Analyzer

A production-ready AI-powered forensic analysis tool for security log investigation using IBM Granite LLM.

## 🚀 Features

- **AI-Powered Analysis**: Uses IBM Granite LLM for intelligent log analysis
- **Multi-Format Support**: Parses Windows Event Logs, Syslog, Firewall logs, and more
- **IOC Detection**: Automatically identifies Indicators of Compromise
- **MITRE ATT&CK Mapping**: Maps findings to MITRE ATT&CK framework
- **VirusTotal Integration**: Enriches IOCs with reputation data
- **RAG Pipeline**: Advanced retrieval-augmented generation for context
- **Web Dashboard**: Streamlit-based interactive interface
- **Comprehensive Reporting**: JSON, Word, and CSV report generation
- **Production Ready**: Security, monitoring, and reliability features

## 📋 Prerequisites

- Python 3.11+
- 8GB RAM minimum (16GB recommended)
- 50GB disk space
- Access to LLM provider (IBM Watson or Groq)

## 🛠️ Quick Start

### 1. Installation

```bash
# Clone the repository
git clone <repository-url>
cd LogForge

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or
venv\Scripts\activate     # Windows

# Install dependencies
pip install -r requirements.txt
```

### 2. Configuration

```bash
# Copy environment template
cp env_template.txt .env

# Edit .env with your settings
# Required: LLM_PROVIDER, API keys
# Optional: VirusTotal, AWS S3
```

**IBM Watsonx.ai Setup (Required):**
1. Go to [IBM Watsonx.ai Console](https://watsonx.ai/)
2. Create a new project or use an existing one
3. Get your API key and project ID
4. Configure IBM credentials in your `.env` file

### 3. Validate Configuration

```bash
# Check configuration
python main.py config --validate
```

### 4. Run Analysis

```bash
# CLI analysis
python main.py analyze logs/security.log --case-id INCIDENT_001

# Web dashboard
python main.py dashboard

# Demo with sample data
python main.py demo --scenario malware
```

## 🔧 Production Deployment

### Security Configuration

1. **Environment Variables**
   ```bash
   # Generate secure secret key
   python -c "import secrets; print(secrets.token_hex(32))"
   
   # Configure production settings
   DEBUG_MODE=false
   SECRET_KEY=<your-32-char-secret>
   ALLOWED_HOSTS=<your-domain.com>
   ```

2. **File Permissions**
   ```bash
   chmod 600 .env
   chmod 700 logs/ chroma_db/
   ```

### Deployment Options

#### Option 1: Direct Python
```bash
# Install and run
pip install -r requirements.txt
python main.py dashboard --host 0.0.0.0 --port 8501
```

#### Option 2: Systemd Service (Linux)
```bash
# Create service file
sudo nano /etc/systemd/system/forensic-analyzer.service

# Enable and start
sudo systemctl enable forensic-analyzer
sudo systemctl start forensic-analyzer
```

#### Option 3: Docker
```bash
# Build and run
docker build -t forensic-analyzer .
docker run -d -p 8501:8501 --env-file .env forensic-analyzer
```

### Monitoring

```bash
# Health check
python health_check.py

# Monitor logs
tail -f logs/forensic_analyzer.log
tail -f logs/errors.log

# Configuration validation
python main.py config --validate
```

## 📊 Usage Examples

### CLI Analysis
```bash
# Analyze multiple log files
python main.py analyze \
  logs/firewall.log \
  logs/windows_events.evtx \
  --case-id "MALWARE_INCIDENT_2024" \
  --output reports/

# Check configuration
python main.py config --check
```

### Web Dashboard
```bash
# Start dashboard
python main.py dashboard --host 0.0.0.0 --port 8501

# Access at http://localhost:8501
```

### Demo Scenarios
```bash
# Run malware scenario
python main.py demo --scenario malware

# Run data breach scenario
python main.py demo --scenario breach

# Run insider threat scenario
python main.py demo --scenario insider
```

## 🔍 Configuration

### Required Settings
- `LLM_PROVIDER`: "ibm_granite" (only option)
- `AWS_ACCESS_KEY_ID` / `IBM_API_KEY`: LLM provider credentials
- `SECRET_KEY`: 32-character random string

### LLM Provider Options

#### IBM Granite (Required)
- **Provider ID**: `ibm_granite`
- **Model**: IBM Granite 3 8B Instruct
- **Requirements**: IBM Watsonx.ai account and API credentials
- **Environment Variables**: `IBM_API_KEY`, `IBM_PROJECT_ID`
- **Benefits**: Enterprise-grade AI, excellent reasoning capabilities, optimized for security analysis
- **Setup**: Create project in IBM Watsonx.ai console and get API credentials

### Optional Settings
- `VT_API_KEY`: VirusTotal API for IOC enrichment
- `AWS_*`: S3 integration for file storage
- `DEBUG_MODE`: Enable debug features (false in production)

### Security Settings
- `ALLOWED_HOSTS`: Comma-separated list of allowed hosts
- `CORS_ORIGINS`: Comma-separated list of CORS origins
- `RATE_LIMIT_*`: Rate limiting configuration

## 📈 Monitoring and Maintenance

### Health Checks
```bash
# Run comprehensive health check
python health_check.py

# JSON output for monitoring systems
python health_check.py --json
```

### Backup and Recovery
```bash
# Backup data
tar -czf backup_$(date +%Y%m%d).tar.gz chroma_db/ logs/

# Restore data
tar -xzf backup_YYYYMMDD.tar.gz
```

### Log Management
- Main logs: `logs/forensic_analyzer.log`
- Error logs: `logs/errors.log`
- Automatic rotation: 50MB files, 30-day retention

## 🛡️ Security Features

- **Configuration Validation**: Automatic validation of production settings
- **Error Handling**: Graceful degradation and retry logic
- **Logging**: Comprehensive audit trails
- **Rate Limiting**: Built-in request throttling
- **Secure Defaults**: Production-ready security settings

## 🔧 Troubleshooting

### Common Issues

1. **LLM Connection Failures**
   ```bash
   python main.py config --validate
   ```

2. **Memory Issues**
   ```bash
   # Reduce log entry limit
   MAX_LOG_ENTRIES=5000
   ```

3. **Disk Space**
   ```bash
   # Clean old logs
   find logs/ -name "*.log.*" -mtime +30 -delete
   ```

### Performance Optimization

- Increase `MAX_LOG_ENTRIES` for larger datasets
- Configure ChromaDB persistence for better performance
- Use AWS S3 for large file storage

## 📚 Documentation

- [Production Deployment Guide](PRODUCTION_DEPLOYMENT.md)
- [Configuration Reference](env_template.txt)
- [API Documentation](docs/api.md)

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

For issues and support:
1. Check the logs in `logs/` directory
2. Run configuration validation
3. Review the deployment guide
4. Check system resources
5. Contact support with logs and error details

## 🔄 Updates

```bash
# Update application
git pull origin main
pip install -r requirements.txt
python main.py config --validate
```
