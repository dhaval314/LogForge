# Production Deployment Guide

## Overview
This guide covers deploying the Forensic AI Log Analyzer in a production environment with security, monitoring, and reliability best practices.

## Prerequisites

### System Requirements
- Python 3.11 or higher
- 8GB RAM minimum (16GB recommended)
- 50GB disk space
- Linux/Unix environment (recommended)

### Dependencies
- All Python packages from `requirements.txt`
- Access to LLM provider (IBM Watson or Groq)
- Optional: AWS S3, VirusTotal API

## Security Configuration

### 1. Environment Variables
```bash
# Generate a secure secret key
python -c "import secrets; print(secrets.token_hex(32))"

# Copy and configure environment template
cp env_template.txt .env
# Edit .env with your production values
```

### 2. Required Security Settings
- `DEBUG_MODE=false`
- `SECRET_KEY=<32-character-random-string>`
- `ALLOWED_HOSTS=<your-domain.com>`
- `CORS_ORIGINS=<https://your-domain.com>`

### 3. File Permissions
```bash
# Secure sensitive files
chmod 600 .env
chmod 700 logs/
chmod 700 chroma_db/
```

## Deployment Options

### Option 1: Direct Python Deployment

#### 1. Install Dependencies
```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or
venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt
```

#### 2. Configuration Validation
```bash
# Validate configuration
python main.py config --validate
```

#### 3. Run Application
```bash
# CLI mode
python main.py analyze <log_files> --case-id <case_id>

# Web dashboard
python main.py dashboard --host 0.0.0.0 --port 8501
```

### Option 2: Systemd Service (Linux)

#### 1. Create Service File
```bash
sudo nano /etc/systemd/system/forensic-analyzer.service
```

```ini
[Unit]
Description=Forensic AI Log Analyzer
After=network.target

[Service]
Type=simple
User=forensic
Group=forensic
WorkingDirectory=/opt/forensic-analyzer
Environment=PATH=/opt/forensic-analyzer/venv/bin
ExecStart=/opt/forensic-analyzer/venv/bin/python main.py dashboard --host 0.0.0.0 --port 8501
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

#### 2. Enable and Start Service
```bash
sudo systemctl daemon-reload
sudo systemctl enable forensic-analyzer
sudo systemctl start forensic-analyzer
sudo systemctl status forensic-analyzer
```

### Option 3: Docker Deployment

#### 1. Build Image
```bash
docker build -t forensic-analyzer .
```

#### 2. Run Container
```bash
docker run -d \
  --name forensic-analyzer \
  -p 8501:8501 \
  -v $(pwd)/logs:/app/logs \
  -v $(pwd)/chroma_db:/app/chroma_db \
  --env-file .env \
  forensic-analyzer
```

## Monitoring and Logging

### 1. Application Logs
- Main logs: `logs/forensic_analyzer.log`
- Error logs: `logs/errors.log`
- Log rotation: 50MB files, 30-day retention

### 2. System Monitoring
```bash
# Check application status
python main.py config --check

# Monitor logs
tail -f logs/forensic_analyzer.log
tail -f logs/errors.log

# Check disk usage
du -sh logs/ chroma_db/
```

### 3. Health Checks
```bash
# Application health
curl http://localhost:8501/_stcore/health

# Configuration validation
python main.py config --validate
```

## Backup and Recovery

### 1. Data Backup
```bash
# Backup ChromaDB
tar -czf chroma_db_backup_$(date +%Y%m%d).tar.gz chroma_db/

# Backup logs
tar -czf logs_backup_$(date +%Y%m%d).tar.gz logs/

# Backup configuration
cp .env .env.backup.$(date +%Y%m%d)
```

### 2. Recovery Procedures
```bash
# Restore ChromaDB
tar -xzf chroma_db_backup_YYYYMMDD.tar.gz

# Restore logs
tar -xzf logs_backup_YYYYMMDD.tar.gz

# Restore configuration
cp .env.backup.YYYYMMDD .env
```

## Security Best Practices

### 1. Network Security
- Use HTTPS in production
- Configure firewall rules
- Implement rate limiting
- Use reverse proxy (nginx/Apache)

### 2. Access Control
- Implement authentication if needed
- Use strong passwords
- Regular credential rotation
- Principle of least privilege

### 3. Data Protection
- Encrypt sensitive data at rest
- Secure API keys and secrets
- Regular security updates
- Audit logging

## Troubleshooting

### Common Issues

#### 1. LLM Connection Failures
```bash
# Check API credentials
python main.py config --validate

# Test LLM connection
python -c "from llm_analysis import LLMAnalyzer; a=LLMAnalyzer(); print('LLM OK' if a.ibm_client else 'LLM Failed')"
```

#### 2. Memory Issues
```bash
# Monitor memory usage
free -h
ps aux | grep python

# Reduce MAX_LOG_ENTRIES in .env if needed
```

#### 3. Disk Space Issues
```bash
# Check disk usage
df -h
du -sh logs/ chroma_db/

# Clean old logs
find logs/ -name "*.log.*" -mtime +30 -delete
```

### Performance Optimization

#### 1. ChromaDB Optimization
```bash
# Optimize ChromaDB
python -c "import chromadb; client = chromadb.PersistentClient('./chroma_db'); client.persist()"
```

#### 2. Log Management
```bash
# Implement log rotation
logrotate /etc/logrotate.d/forensic-analyzer
```

## Maintenance

### 1. Regular Tasks
- Weekly: Check disk space and logs
- Monthly: Update dependencies
- Quarterly: Security audit
- Annually: Full backup and recovery test

### 2. Updates
```bash
# Update application
git pull origin main
pip install -r requirements.txt
python main.py config --validate
```

### 3. Monitoring Scripts
Create monitoring scripts for:
- Application health checks
- Disk space monitoring
- Log analysis
- Performance metrics

## Support

For issues and support:
1. Check logs in `logs/` directory
2. Run configuration validation
3. Review this deployment guide
4. Check system resources
5. Contact support team with logs and error details
