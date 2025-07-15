"""
Shared utilities for the cybersecurity toolkit
Contains PDF generation, alerts, file operations, and environment setup
"""

import os
import sys
import json
import time
import subprocess
import urllib.parse
import smtplib
import requests
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication

# PDF generation
try:
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.lib.colors import black, red, orange, green, blue
    from reportlab.lib import colors
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

# Chart generation
try:
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False

from shared.logger import get_logger

logger = get_logger(__name__)

def save_scan_results(results: Dict[str, Any], scan_type: str) -> str:
    """
    Save scan results to JSON file
    
    Args:
        results: Scan results dictionary
        scan_type: Type of scan (nmap, brute_force, etc.)
    
    Returns:
        Path to saved file
    """
    try:
        reports_dir = Path("reports")
        reports_dir.mkdir(exist_ok=True)
        
        # Create filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        target = results.get('target', 'unknown').replace('/', '_').replace(':', '_')
        filename = f"{scan_type}_{target}_{timestamp}.json"
        
        file_path = reports_dir / filename
        
        # Save results
        with open(file_path, 'w') as f:
            json.dump(results, f, indent=2, default=str)
            
        logger.info(f"Scan results saved to {file_path}")
        return str(file_path)
        
    except Exception as e:
        logger.error(f"Failed to save scan results: {e}")
        return ""

def load_scan_results(file_path: str) -> Optional[Dict[str, Any]]:
    """Load scan results from JSON file"""
    try:
        with open(file_path, 'r') as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Failed to load scan results from {file_path}: {e}")
        return None

def send_alert(message: str, alert_type: str = "telegram", target: str = "unknown"):
    """
    Send alert notification via configured channels
    
    Args:
        message: Alert message
        alert_type: Type of alert (telegram, slack, email)
        target: Target that triggered the alert
    """
    logger.info(f"Sending {alert_type} alert: {message}")
    
    try:
        if alert_type == "telegram":
            send_telegram_alert(message)
        elif alert_type == "slack":
            send_slack_alert(message)
        elif alert_type == "email":
            send_email_alert(message)
        else:
            # Simulate alert for demo
            logger.warning(f"ALERT SIMULATION: {message}")
            
        # Log the alert
        from shared.logger import log_alert_sent
        log_alert_sent(alert_type, target, message)
        
    except Exception as e:
        logger.error(f"Failed to send {alert_type} alert: {e}")

def send_telegram_alert(message: str):
    """Send alert via Telegram bot"""
    telegram_token = os.getenv('TELEGRAM_BOT_TOKEN')
    telegram_chat_id = os.getenv('TELEGRAM_CHAT_ID')
    
    if not telegram_token or not telegram_chat_id:
        logger.info("Telegram credentials not configured - simulating alert")
        return
        
    try:
        url = f"https://api.telegram.org/bot{telegram_token}/sendMessage"
        data = {
            'chat_id': telegram_chat_id,
            'text': f"🔒 CyberToolkit Alert\n\n{message}",
            'parse_mode': 'HTML'
        }
        
        response = requests.post(url, data=data, timeout=10)
        response.raise_for_status()
        
        logger.info("Telegram alert sent successfully")
        
    except Exception as e:
        logger.error(f"Failed to send Telegram alert: {e}")

def send_slack_alert(message: str):
    """Send alert via Slack webhook"""
    slack_webhook = os.getenv('SLACK_WEBHOOK_URL')
    
    if not slack_webhook:
        logger.info("Slack webhook not configured - simulating alert")
        return
        
    try:
        payload = {
            "text": f"🔒 CyberToolkit Alert",
            "attachments": [
                {
                    "color": "danger",
                    "fields": [
                        {
                            "title": "Security Alert",
                            "value": message,
                            "short": False
                        }
                    ],
                    "footer": "CyberToolkit",
                    "ts": int(time.time())
                }
            ]
        }
        
        response = requests.post(slack_webhook, json=payload, timeout=10)
        response.raise_for_status()
        
        logger.info("Slack alert sent successfully")
        
    except Exception as e:
        logger.error(f"Failed to send Slack alert: {e}")

def send_email_alert(message: str):
    """Send alert via email"""
    smtp_server = os.getenv('SMTP_SERVER', 'localhost')
    smtp_port = int(os.getenv('SMTP_PORT', '587'))
    smtp_user = os.getenv('SMTP_USER')
    smtp_pass = os.getenv('SMTP_PASS')
    alert_email = os.getenv('ALERT_EMAIL')
    
    if not alert_email:
        logger.info("Email configuration not complete - simulating alert")
        return
        
    try:
        msg = MIMEMultipart()
        msg['From'] = smtp_user or 'cybertoolkit@localhost'
        msg['To'] = alert_email
        msg['Subject'] = '🔒 CyberToolkit Security Alert'
        
        body = f"""
CyberToolkit Security Alert

Alert Details:
{message}

Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

This is an automated security alert from CyberToolkit.
        """
        
        msg.attach(MIMEText(body, 'plain'))
        
        # Send email
        if smtp_user and smtp_pass:
            server = smtplib.SMTP(smtp_server, smtp_port)
            server.starttls()
            server.login(smtp_user, smtp_pass)
            text = msg.as_string()
            server.sendmail(smtp_user, alert_email, text)
            server.quit()
            
            logger.info("Email alert sent successfully")
        else:
            logger.info("SMTP credentials not configured - alert would be sent")
            
    except Exception as e:
        logger.error(f"Failed to send email alert: {e}")

def generate_pdf_report(report_data: Dict[str, Any]) -> str:
    """
    Generate comprehensive PDF report
    
    Args:
        report_data: Dictionary containing report data
    
    Returns:
        Path to generated PDF file
    """
    if not REPORTLAB_AVAILABLE:
        logger.warning("ReportLab not available - generating simple text report")
        return generate_text_report(report_data)
        
    try:
        reports_dir = Path("reports")
        reports_dir.mkdir(exist_ok=True)
        
        # Create filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        target = report_data.get('target', 'unknown').replace('/', '_').replace(':', '_')
        pdf_file = reports_dir / f"security_report_{target}_{timestamp}.pdf"
        
        # Create PDF document
        doc = SimpleDocTemplate(str(pdf_file), pagesize=letter)
        story = []
        styles = getSampleStyleSheet()
        
        # Add custom styles
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            textColor=colors.darkblue
        )
        
        # Title
        story.append(Paragraph("🔒 CyberToolkit Security Assessment Report", title_style))
        story.append(Spacer(1, 20))
        
        # Executive Summary
        story.append(Paragraph("Executive Summary", styles['Heading2']))
        summary_text = f"""
        <b>Target:</b> {report_data.get('target', 'N/A')}<br/>
        <b>Assessment Date:</b> {report_data.get('timestamp', 'N/A')}<br/>
        <b>Overall Risk Level:</b> {determine_risk_level(report_data)}<br/>
        <b>Total Findings:</b> {count_total_findings(report_data)}
        """
        story.append(Paragraph(summary_text, styles['Normal']))
        story.append(Spacer(1, 20))
        
        # Scan Results
        if 'scan_results' in report_data:
            story.append(Paragraph("Detailed Findings", styles['Heading2']))
            
            for scan_type, results in report_data['scan_results'].items():
                story.append(Paragraph(f"{scan_type.title()} Results", styles['Heading3']))
                
                if isinstance(results, dict):
                    # Create table for scan results
                    table_data = [['Finding', 'Details', 'Severity']]
                    
                    # Add findings to table
                    if 'vulnerabilities' in results:
                        for vuln in results['vulnerabilities'][:10]:  # Limit to 10
                            if isinstance(vuln, dict):
                                table_data.append([
                                    vuln.get('description', 'Unknown')[:50],
                                    vuln.get('details', 'N/A')[:50],
                                    vuln.get('severity', 'Unknown')
                                ])
                    
                    if len(table_data) > 1:
                        table = Table(table_data, colWidths=[2.5*inch, 2.5*inch, 1*inch])
                        table.setStyle(TableStyle([
                            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                            ('FONTSIZE', (0, 0), (-1, 0), 10),
                            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                            ('GRID', (0, 0), (-1, -1), 1, colors.black)
                        ]))
                        story.append(table)
                        
                story.append(Spacer(1, 15))
        
        # Recommendations
        story.append(Paragraph("Security Recommendations", styles['Heading2']))
        recommendations = generate_recommendations(report_data)
        
        for i, rec in enumerate(recommendations[:15], 1):  # Limit to 15
            story.append(Paragraph(f"{i}. {rec}", styles['Normal']))
            
        story.append(Spacer(1, 20))
        
        # Footer
        footer_text = f"""
        <i>This report was generated by CyberToolkit on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}.
        For questions about this assessment, please contact your security team.</i>
        """
        story.append(Paragraph(footer_text, styles['Normal']))
        
        # Build PDF
        doc.build(story)
        
        logger.info(f"PDF report generated: {pdf_file}")
        return str(pdf_file)
        
    except Exception as e:
        logger.error(f"Failed to generate PDF report: {e}")
        return generate_text_report(report_data)

def generate_text_report(report_data: Dict[str, Any]) -> str:
    """Generate simple text report as fallback"""
    try:
        reports_dir = Path("reports")
        reports_dir.mkdir(exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        target = report_data.get('target', 'unknown').replace('/', '_').replace(':', '_')
        txt_file = reports_dir / f"security_report_{target}_{timestamp}.txt"
        
        with open(txt_file, 'w') as f:
            f.write("CYBERTOOLKIT SECURITY ASSESSMENT REPORT\n")
            f.write("=" * 50 + "\n\n")
            f.write(f"Target: {report_data.get('target', 'N/A')}\n")
            f.write(f"Date: {report_data.get('timestamp', 'N/A')}\n")
            f.write(f"Risk Level: {determine_risk_level(report_data)}\n\n")
            
            f.write("FINDINGS:\n")
            f.write("-" * 20 + "\n")
            
            if 'scan_results' in report_data:
                for scan_type, results in report_data['scan_results'].items():
                    f.write(f"\n{scan_type.upper()} RESULTS:\n")
                    if isinstance(results, dict) and 'vulnerabilities' in results:
                        for vuln in results['vulnerabilities'][:10]:
                            if isinstance(vuln, dict):
                                f.write(f"- {vuln.get('description', 'Unknown')}\n")
            
            f.write("\nRECOMMENDATIONS:\n")
            f.write("-" * 20 + "\n")
            recommendations = generate_recommendations(report_data)
            for i, rec in enumerate(recommendations[:15], 1):
                f.write(f"{i}. {rec}\n")
                
        logger.info(f"Text report generated: {txt_file}")
        return str(txt_file)
        
    except Exception as e:
        logger.error(f"Failed to generate text report: {e}")
        return ""

def determine_risk_level(report_data: Dict[str, Any]) -> str:
    """Determine overall risk level from report data"""
    risk_score = report_data.get('risk_score', 5)
    
    if isinstance(risk_score, (int, float)):
        if risk_score >= 8:
            return "HIGH RISK ⚠️"
        elif risk_score >= 6:
            return "MEDIUM RISK ⚠️"
        elif risk_score >= 4:
            return "LOW-MEDIUM RISK 💡"
        else:
            return "LOW RISK ✅"
    
    # Fallback analysis
    critical_findings = 0
    if 'scan_results' in report_data:
        for results in report_data['scan_results'].values():
            if isinstance(results, dict):
                critical_findings += len([v for v in results.get('vulnerabilities', [])
                                        if isinstance(v, dict) and v.get('severity') == 'high'])
    
    if critical_findings >= 5:
        return "HIGH RISK ⚠️"
    elif critical_findings >= 2:
        return "MEDIUM RISK ⚠️"
    else:
        return "LOW RISK ✅"

def count_total_findings(report_data: Dict[str, Any]) -> int:
    """Count total findings across all scans"""
    total = 0
    if 'scan_results' in report_data:
        for results in report_data['scan_results'].values():
            if isinstance(results, dict):
                total += len(results.get('vulnerabilities', []))
    return total

def generate_recommendations(report_data: Dict[str, Any]) -> List[str]:
    """Generate security recommendations based on findings"""
    recommendations = [
        "Implement a comprehensive patch management program",
        "Deploy network segmentation and access controls",
        "Enable multi-factor authentication on all critical systems",
        "Conduct regular security awareness training",
        "Implement continuous security monitoring",
        "Perform regular vulnerability assessments",
        "Maintain incident response procedures",
        "Review and update security policies regularly",
        "Implement endpoint detection and response (EDR)",
        "Ensure proper backup and recovery procedures"
    ]
    
    # Add specific recommendations based on findings
    if 'scan_results' in report_data:
        for scan_type, results in report_data['scan_results'].items():
            if scan_type == 'nmap' and isinstance(results, dict):
                if len(results.get('open_ports', [])) > 10:
                    recommendations.insert(0, "Close unnecessary open ports and services")
                    
            elif scan_type == 'brute_force' and isinstance(results, dict):
                if results.get('successful_logins'):
                    recommendations.insert(0, "Change default/weak passwords immediately")
                    
            elif scan_type == 'nikto' and isinstance(results, dict):
                if results.get('vulnerabilities'):
                    recommendations.insert(0, "Update web server and fix web vulnerabilities")
    
    return recommendations

def setup_environment():
    """Setup environment and install dependencies"""
    logger.info("Setting up CyberToolkit environment...")
    
    try:
        # Check and install Python dependencies
        install_python_dependencies()
        
        # Check and install Node.js dependencies  
        install_node_dependencies()
        
        # Create necessary directories
        create_directories()
        
        # Set up configuration files
        setup_config_files()
        
        logger.info("Environment setup completed successfully")
        
    except Exception as e:
        logger.error(f"Environment setup failed: {e}")

def install_python_dependencies():
    """Install Python dependencies"""
    logger.info("Checking Python dependencies...")
    
    try:
        # Check if requirements.txt exists
        if Path("requirements.txt").exists():
            logger.info("Installing Python packages from requirements.txt...")
            result = subprocess.run([
                sys.executable, "-m", "pip", "install", "-r", "requirements.txt"
            ], capture_output=True, text=True)
            
            if result.returncode == 0:
                logger.info("Python dependencies installed successfully")
            else:
                logger.warning(f"Some dependencies may have failed: {result.stderr}")
        else:
            logger.warning("requirements.txt not found")
            
    except Exception as e:
        logger.error(f"Failed to install Python dependencies: {e}")

def install_node_dependencies():
    """Install Node.js dependencies"""
    logger.info("Checking Node.js dependencies...")
    
    try:
        # Check if Node.js is available
        result = subprocess.run(["node", "--version"], 
                              capture_output=True, text=True)
        
        if result.returncode == 0:
            logger.info(f"Node.js version: {result.stdout.strip()}")
            
            # Install npm packages if package.json exists
            if Path("package.json").exists():
                logger.info("Installing Node.js packages...")
                result = subprocess.run(["npm", "install"], 
                                      capture_output=True, text=True)
                
                if result.returncode == 0:
                    logger.info("Node.js dependencies installed successfully")
                else:
                    logger.warning(f"npm install issues: {result.stderr}")
            else:
                logger.warning("package.json not found")
        else:
            logger.warning("Node.js not found - web dashboard will not be available")
            
    except FileNotFoundError:
        logger.warning("Node.js not found - web dashboard will not be available")
    except Exception as e:
        logger.error(f"Failed to check Node.js dependencies: {e}")

def create_directories():
    """Create necessary directories"""
    directories = ["reports", "logs", "ml", "web/public", "tests"]
    
    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True)
        logger.debug(f"Created directory: {directory}")

def setup_config_files():
    """Setup configuration files"""
    # Create .env.example if it doesn't exist
    env_example_path = Path(".env.example")
    if not env_example_path.exists():
        env_content = """# CyberToolkit Configuration
# Copy this file to .env and configure your settings

# Logging
CYBER_TOOLKIT_LOG_LEVEL=INFO

# Telegram Alerts
TELEGRAM_BOT_TOKEN=your_telegram_bot_token
TELEGRAM_CHAT_ID=your_chat_id

# Slack Alerts  
SLACK_WEBHOOK_URL=your_slack_webhook_url

# Email Alerts
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your_email@gmail.com
SMTP_PASS=your_app_password
ALERT_EMAIL=security@yourcompany.com

# Database (optional)
MONGODB_URI=mongodb://localhost:27017/cybertoolkit
REDIS_URI=redis://localhost:6379

# Web Dashboard
WEB_PORT=3000
WEB_SECRET=your_secret_key
"""
        with open(env_example_path, 'w') as f:
            f.write(env_content)
        logger.info("Created .env.example file")

def check_dependencies() -> Dict[str, bool]:
    """Check if required dependencies are available"""
    dependencies = {
        'python': True,  # Always true since we're running in Python
        'nmap': False,
        'nikto': False,
        'nodejs': False,
        'reportlab': REPORTLAB_AVAILABLE,
        'matplotlib': MATPLOTLIB_AVAILABLE
    }
    
    # Check nmap
    try:
        subprocess.run(["nmap", "--version"], capture_output=True, check=True)
        dependencies['nmap'] = True
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass
    
    # Check nikto
    try:
        subprocess.run(["nikto", "-Version"], capture_output=True, check=True)
        dependencies['nikto'] = True
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass
    
    # Check Node.js
    try:
        subprocess.run(["node", "--version"], capture_output=True, check=True)
        dependencies['nodejs'] = True
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass
    
    return dependencies

def get_system_info() -> Dict[str, Any]:
    """Get system information"""
    import platform
    
    return {
        "platform": platform.platform(),
        "python_version": platform.python_version(),
        "architecture": platform.architecture(),
        "processor": platform.processor(),
        "hostname": platform.node(),
        "dependencies": check_dependencies()
    }

def validate_target(target: str) -> bool:
    """Validate if target is a valid IP or domain"""
    import re
    
    # Simple IP regex
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    
    # Simple domain regex
    domain_pattern = r'^[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]*\.([a-zA-Z]{2,}|[a-zA-Z]{2,}\.[a-zA-Z]{2,})$'
    
    if re.match(ip_pattern, target) or re.match(domain_pattern, target):
        return True
    
    # Allow localhost and local IPs for testing
    if target.lower() in ['localhost', '127.0.0.1', '::1']:
        return True
        
    return False

def format_bytes(bytes_value: int) -> str:
    """Format bytes into human readable format"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_value < 1024.0:
            return f"{bytes_value:.1f} {unit}"
        bytes_value /= 1024.0
    return f"{bytes_value:.1f} PB"

def get_file_hash(file_path: str, algorithm: str = "sha256") -> str:
    """Calculate file hash"""
    import hashlib
    
    hash_algo = getattr(hashlib, algorithm)()
    
    try:
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_algo.update(chunk)
        return hash_algo.hexdigest()
    except Exception as e:
        logger.error(f"Failed to calculate hash for {file_path}: {e}")
        return ""

if __name__ == "__main__":
    # Test utilities
    logger.info("Testing CyberToolkit utilities...")
    
    # Test system info
    info = get_system_info()
    print(f"System: {info['platform']}")
    print(f"Python: {info['python_version']}")
    
    # Test dependencies
    deps = check_dependencies()
    print(f"Dependencies: {deps}")
    
    # Test target validation
    test_targets = ["example.com", "192.168.1.1", "invalid..domain", "localhost"]
    for target in test_targets:
        valid = validate_target(target)
        print(f"Target '{target}': {'Valid' if valid else 'Invalid'}")
    
    print("Utilities test completed.")