# 🔒 CyberToolkit - Professional Cybersecurity Multi-Tool

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://python.org)
[![Node.js](https://img.shields.io/badge/Node.js-16%2B-green.svg)](https://nodejs.org)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue.svg)](https://docker.com)

A production-grade terminal-based cybersecurity multi-tool with an optional local web dashboard. Designed for security professionals, penetration testers, and IT administrators.

## 🌟 Features

### Core Security Tools
- **🔍 Vulnerability Scanning**: Nmap + Nikto integration for comprehensive network and web application scanning
- **🔐 Brute Force Simulation**: Safe testing of SSH, FTP, and HTTP authentication mechanisms
- **📧 Phishing Simulation**: Educational phishing email campaigns for security awareness training
- **🤖 AI Risk Prediction**: Machine learning-powered risk assessment and threat analysis

### Advanced Capabilities
- **📊 PDF Report Generation**: Professional security assessment reports
- **🌐 Real-time Web Dashboard**: Live monitoring with Socket.io integration
- **📱 Multi-Channel Alerts**: Telegram, Slack, and email notifications
- **🗄️ Data Persistence**: MongoDB for scan history, Redis for caching
- **🐳 Container Ready**: Full Docker and docker-compose support

### Enterprise Features
- **📈 Analytics Dashboard**: Grafana integration for advanced monitoring
- **🔍 Log Analysis**: ELK stack integration for security event correlation
- **⚡ Performance Monitoring**: Prometheus metrics collection
- **🔐 Security Hardened**: Rate limiting, authentication, and encryption support

## 📋 Quick Start

### Prerequisites
- Python 3.8+ 
- Node.js 16+
- Docker & Docker Compose (optional)
- Git

### 🚀 Installation

#### Option 1: Standard Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/your-org/cybertoolkit.git
   cd cybertoolkit
   ```

2. **Install dependencies**
   ```bash
   # Install Python dependencies
   pip install -r requirements.txt
   
   # Install Node.js dependencies
   npm install
   ```

3. **Configure environment**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

4. **Run the toolkit**
   ```bash
   # Interactive CLI mode
   python cli.py
   
   # Or start specific components
   python cli.py interactive  # Interactive menu
   node web/server.js         # Web dashboard
   ```

#### Option 2: Docker Installation

1. **Quick start with Docker Compose**
   ```bash
   git clone https://github.com/your-org/cybertoolkit.git
   cd cybertoolkit
   cp .env.example .env
   docker-compose up -d
   ```

2. **Access the dashboard**
   - Web Dashboard: http://localhost:3000
   - Grafana: http://localhost:3001
   - Prometheus: http://localhost:9090

## 🖥️ Usage

### Interactive CLI Menu
```bash
python cli.py
```

The interactive menu provides access to all toolkit features:
```
[1] 🔍 Vulnerability Scan (Nmap + Nikto)
[2] 🔐 Safe Brute Force Simulation  
[3] 📧 Phishing Simulation
[4] 🤖 AI Risk Prediction
[5] 📊 Generate PDF Report
[6] 🌐 Launch Local Web Dashboard
[7] ❌ Exit
```

### Command Line Usage
```bash
# Quick vulnerability scan
python cli.py scan example.com

# Install/update dependencies
python cli.py install

# Generate report for specific target
python cli.py report example.com --output report.pdf
```

### Web Dashboard
Access the real-time dashboard at `http://localhost:3000` to:
- Monitor active scans in real-time
- View scan history and reports
- Start new scans remotely
- Download PDF reports
- Monitor system status

### API Usage
```bash
# Start a new scan via API
curl -X POST http://localhost:3000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com", "scanType": "vulnerability"}'

# Get scan status
curl http://localhost:3000/api/status

# List reports
curl http://localhost:3000/api/reports
```

## 🔧 Configuration

### Environment Variables
Copy `.env.example` to `.env` and configure:

```bash
# Basic configuration
WEB_PORT=3000
CYBER_TOOLKIT_LOG_LEVEL=INFO

# Database
MONGODB_URI=mongodb://localhost:27017/cybertoolkit
REDIS_URI=redis://localhost:6379

# Alerts
TELEGRAM_BOT_TOKEN=your_token
SLACK_WEBHOOK_URL=your_webhook
ALERT_EMAIL=security@company.com
```

### Alert Configuration

#### Telegram Setup
1. Create a bot with [@BotFather](https://t.me/botfather)
2. Get your bot token and chat ID
3. Configure in `.env`:
   ```bash
   TELEGRAM_BOT_TOKEN=123456789:ABC-DEF1234ghIkl-zyx57W2v1u123ew11
   TELEGRAM_CHAT_ID=123456789
   ```

#### Slack Setup
1. Create a Slack webhook URL
2. Configure in `.env`:
   ```bash
   SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK
   ```

#### Email Setup
```bash
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your_email@gmail.com
SMTP_PASS=your_app_password
```

## 📊 Monitoring & Analytics

### Grafana Dashboard
Access Grafana at `http://localhost:3001` (admin/admin) for:
- Scan performance metrics
- Risk trend analysis
- System resource monitoring
- Custom security dashboards

### Log Analysis
- Application logs: `logs/cybertoolkit_YYYYMMDD.log`
- Security events: `logs/security_YYYYMMDD.log`
- Web dashboard: `logs/web_dashboard.log`

## 🔐 Security Considerations

### Safe Usage
- **Educational Purpose**: This tool is designed for authorized security testing only
- **Legal Compliance**: Ensure you have proper authorization before scanning any systems
- **Network Security**: Use appropriate network segmentation and access controls
- **Data Protection**: Secure your configuration files and scan results

### Production Deployment
- Enable HTTPS with proper SSL certificates
- Use strong passwords and rotate secrets regularly
- Implement proper firewall rules
- Enable audit logging and monitoring
- Regular security updates and patches

## 🧪 Testing

### Run Tests
```bash
# Python tests
pytest tests/ -v --cov

# Node.js tests  
npm test

# Integration tests
docker-compose -f docker-compose.test.yml up --abort-on-container-exit
```

### Development Mode
```bash
# Development with hot reload
npm run dev

# Python development
export CYBER_TOOLKIT_LOG_LEVEL=DEBUG
python cli.py
```

## 📁 Project Structure

```
cybertoolkit/
├── cli.py                 # Main CLI entry point
├── scans/                 # Scanning modules
│   ├── nmap_scan.py      # Nmap & Nikto integration
│   ├── brute_force.py    # Safe brute force testing
│   └── phishing.py       # Phishing simulations
├── ml/                    # Machine learning components
│   ├── predict.py        # Risk prediction model
│   └── trained_model.pkl # Pre-trained ML model
├── web/                   # Web dashboard
│   ├── server.js         # Express.js server
│   └── public/           # Frontend assets
├── shared/                # Shared utilities
│   ├── logger.py         # Centralized logging
│   └── utils.py          # Helper functions
├── reports/               # Generated reports
├── logs/                  # Application logs
├── tests/                 # Test suites
├── requirements.txt       # Python dependencies
├── package.json          # Node.js dependencies
├── docker-compose.yml    # Container orchestration
└── README.md             # This file
```

## 🚀 Deployment

### Docker Production Deployment
```bash
# Production deployment
docker-compose -f docker-compose.yml up -d

# With monitoring stack
docker-compose --profile monitoring up -d

# Scale services
docker-compose up -d --scale cybertoolkit=3
```

### Kubernetes Deployment
```bash
# Apply Kubernetes manifests
kubectl apply -f k8s/

# Check deployment status
kubectl get pods -n cybertoolkit
```

### Cloud Deployment
- **AWS**: Use ECS or EKS with Application Load Balancer
- **Azure**: Deploy to Container Instances or AKS
- **GCP**: Use Cloud Run or GKE
- **DigitalOcean**: Deploy to App Platform or Kubernetes

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Guidelines
- Follow PEP 8 for Python code
- Use ESLint configuration for JavaScript
- Write tests for new features
- Update documentation
- Ensure security best practices

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This tool is intended for authorized security testing and educational purposes only. Users are responsible for ensuring compliance with applicable laws and regulations. The authors are not responsible for any misuse or damage caused by this tool.

## 🆘 Support

- **Documentation**: [Wiki](https://github.com/your-org/cybertoolkit/wiki)
- **Issues**: [GitHub Issues](https://github.com/your-org/cybertoolkit/issues)
- **Discussions**: [GitHub Discussions](https://github.com/your-org/cybertoolkit/discussions)
- **Security**: Report security issues to security@yourcompany.com

## 🙏 Acknowledgments

- **Nmap**: Network discovery and security auditing
- **Nikto**: Web server scanner
- **Socket.io**: Real-time web communication
- **Express.js**: Web application framework
- **scikit-learn**: Machine learning library
- **ReportLab**: PDF generation
- **Rich**: Terminal formatting
- **Bootstrap**: Frontend framework

---

**Made with ❤️ by the CyberToolkit Team**

*Securing the digital world, one scan at a time.*