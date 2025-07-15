"""
Centralized logging module for the cybersecurity toolkit
Provides structured logging with file output and console formatting
"""

import logging
import sys
import json
import time
from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime
import os

class SecurityLogger:
    """Enhanced logger for security events and operations"""
    
    def __init__(self, name: str, log_level: str = "INFO"):
        self.name = name
        self.log_level = getattr(logging, log_level.upper(), logging.INFO)
        self.logs_dir = Path("logs")
        self.logs_dir.mkdir(exist_ok=True)
        
        # Create logger
        self.logger = logging.getLogger(name)
        self.logger.setLevel(self.log_level)
        
        # Clear existing handlers to avoid duplicates
        self.logger.handlers.clear()
        
        # Setup handlers
        self._setup_console_handler()
        self._setup_file_handler()
        self._setup_security_handler()
        
    def _setup_console_handler(self):
        """Setup console handler with colored output"""
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(self.log_level)
        
        # Console formatter with colors
        console_formatter = ColoredFormatter(
            '%(asctime)s | %(name)s | %(levelname)s | %(message)s',
            datefmt='%H:%M:%S'
        )
        console_handler.setFormatter(console_formatter)
        self.logger.addHandler(console_handler)
        
    def _setup_file_handler(self):
        """Setup file handler for general logs"""
        log_file = self.logs_dir / f"cybertoolkit_{datetime.now().strftime('%Y%m%d')}.log"
        
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setLevel(logging.DEBUG)  # File logs everything
        
        # File formatter with detailed info
        file_formatter = logging.Formatter(
            '%(asctime)s | %(name)s | %(levelname)s | %(funcName)s:%(lineno)d | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(file_formatter)
        self.logger.addHandler(file_handler)
        
    def _setup_security_handler(self):
        """Setup security-specific handler for audit logs"""
        security_log = self.logs_dir / f"security_{datetime.now().strftime('%Y%m%d')}.log"
        
        security_handler = logging.FileHandler(security_log, encoding='utf-8')
        security_handler.setLevel(logging.WARNING)  # Only warnings and above
        
        # Security formatter with JSON structure
        security_formatter = SecurityFormatter()
        security_handler.setFormatter(security_formatter)
        self.logger.addHandler(security_handler)
        
    def log_security_event(self, event_type: str, target: str, details: Dict[str, Any]):
        """Log security-specific events"""
        security_data = {
            "timestamp": datetime.now().isoformat(),
            "event_type": event_type,
            "target": target,
            "source": self.name,
            "details": details,
            "severity": self._determine_severity(event_type, details)
        }
        
        # Use warning level to ensure it goes to security log
        self.logger.warning(f"SECURITY_EVENT: {json.dumps(security_data)}")
        
    def _determine_severity(self, event_type: str, details: Dict[str, Any]) -> str:
        """Determine severity level for security events"""
        high_risk_events = [
            "successful_login_attempt",
            "weak_credentials_found", 
            "critical_vulnerability",
            "high_risk_prediction"
        ]
        
        medium_risk_events = [
            "scan_completed",
            "brute_force_attempt",
            "phishing_simulation"
        ]
        
        if event_type in high_risk_events:
            return "HIGH"
        elif event_type in medium_risk_events:
            return "MEDIUM"
        else:
            return "LOW"
            
    def info(self, message: str, extra: Optional[Dict] = None):
        """Log info message"""
        self.logger.info(message, extra=extra)
        
    def warning(self, message: str, extra: Optional[Dict] = None):
        """Log warning message"""
        self.logger.warning(message, extra=extra)
        
    def error(self, message: str, extra: Optional[Dict] = None):
        """Log error message"""
        self.logger.error(message, extra=extra)
        
    def debug(self, message: str, extra: Optional[Dict] = None):
        """Log debug message"""
        self.logger.debug(message, extra=extra)
        
    def critical(self, message: str, extra: Optional[Dict] = None):
        """Log critical message"""
        self.logger.critical(message, extra=extra)

class ColoredFormatter(logging.Formatter):
    """Formatter with ANSI color codes for console output"""
    
    # ANSI color codes
    COLORS = {
        'DEBUG': '\033[36m',     # Cyan
        'INFO': '\033[32m',      # Green
        'WARNING': '\033[33m',   # Yellow
        'ERROR': '\033[31m',     # Red
        'CRITICAL': '\033[91m',  # Bright Red
        'RESET': '\033[0m'       # Reset
    }
    
    def format(self, record):
        # Add color to level name
        level_color = self.COLORS.get(record.levelname, self.COLORS['RESET'])
        record.levelname = f"{level_color}{record.levelname}{self.COLORS['RESET']}"
        
        # Format the message
        formatted = super().format(record)
        
        # Add module-specific icons
        if 'nmap' in record.name.lower():
            formatted = f"🔍 {formatted}"
        elif 'brute' in record.name.lower():
            formatted = f"🔐 {formatted}"
        elif 'phishing' in record.name.lower():
            formatted = f"📧 {formatted}"
        elif 'predict' in record.name.lower():
            formatted = f"🤖 {formatted}"
        elif 'cli' in record.name.lower():
            formatted = f"💻 {formatted}"
        elif record.levelname.startswith('\033[31m'):  # Error
            formatted = f"❌ {formatted}"
        elif record.levelname.startswith('\033[33m'):  # Warning
            formatted = f"⚠️ {formatted}"
        
        return formatted

class SecurityFormatter(logging.Formatter):
    """Formatter for security audit logs"""
    
    def format(self, record):
        if record.getMessage().startswith("SECURITY_EVENT:"):
            # Extract JSON from security event
            try:
                json_start = record.getMessage().find("{")
                if json_start != -1:
                    json_data = record.getMessage()[json_start:]
                    parsed_data = json.loads(json_data)
                    
                    # Format as structured log entry
                    return json.dumps({
                        "log_timestamp": datetime.now().isoformat(),
                        "logger": record.name,
                        "level": record.levelname,
                        "security_event": parsed_data
                    }, indent=2)
            except json.JSONDecodeError:
                pass
                
        # Fallback to standard formatting
        return super().format(record)

# Global logger cache
_loggers = {}

def get_logger(name: str, log_level: str = None) -> SecurityLogger:
    """
    Get or create a logger instance
    
    Args:
        name: Logger name (usually __name__)
        log_level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    
    Returns:
        SecurityLogger instance
    """
    # Use environment variable for log level if not specified
    if log_level is None:
        log_level = os.getenv('CYBER_TOOLKIT_LOG_LEVEL', 'INFO')
    
    # Create cache key
    cache_key = f"{name}:{log_level}"
    
    # Return cached logger if exists
    if cache_key in _loggers:
        return _loggers[cache_key]
    
    # Create new logger
    logger = SecurityLogger(name, log_level)
    _loggers[cache_key] = logger
    
    return logger

def log_scan_start(target: str, scan_type: str):
    """Log scan initiation"""
    logger = get_logger("scan_tracker")
    logger.log_security_event(
        event_type="scan_started",
        target=target,
        details={
            "scan_type": scan_type,
            "started_at": datetime.now().isoformat()
        }
    )

def log_scan_complete(target: str, scan_type: str, results: Dict[str, Any]):
    """Log scan completion"""
    logger = get_logger("scan_tracker")
    
    # Determine if results indicate high risk
    high_risk_indicators = []
    if results.get("successful_logins"):
        high_risk_indicators.append("weak_credentials")
    if len(results.get("open_ports", [])) > 15:
        high_risk_indicators.append("many_open_ports")
    if results.get("risk_score", 0) >= 8:
        high_risk_indicators.append("high_risk_score")
        
    logger.log_security_event(
        event_type="scan_completed",
        target=target,
        details={
            "scan_type": scan_type,
            "completed_at": datetime.now().isoformat(),
            "high_risk_indicators": high_risk_indicators,
            "results_summary": {
                "total_findings": len(results.get("vulnerabilities", [])),
                "risk_score": results.get("risk_score"),
                "critical_issues": len([v for v in results.get("vulnerabilities", []) 
                                      if v.get("severity") == "high"])
            }
        }
    )

def log_alert_sent(alert_type: str, target: str, message: str):
    """Log alert notifications"""
    logger = get_logger("alert_system")
    logger.log_security_event(
        event_type="alert_sent",
        target=target,
        details={
            "alert_type": alert_type,
            "message": message,
            "sent_at": datetime.now().isoformat()
        }
    )

def setup_logging():
    """Initialize logging system"""
    # Create logs directory
    Path("logs").mkdir(exist_ok=True)
    
    # Set global logging configuration
    logging.basicConfig(
        level=logging.WARNING,  # Default level for third-party libraries
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Reduce noise from third-party libraries
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)
    logging.getLogger("sklearn").setLevel(logging.WARNING)
    
    # Welcome message
    logger = get_logger("cybertoolkit.startup")
    logger.info("🔒 CyberToolkit logging system initialized")
    logger.info(f"📁 Logs directory: {Path('logs').absolute()}")

if __name__ == "__main__":
    # Test the logging system
    setup_logging()
    
    # Test different loggers
    test_logger = get_logger("test_module")
    
    test_logger.info("This is an info message")
    test_logger.warning("This is a warning message")
    test_logger.error("This is an error message")
    
    # Test security logging
    test_logger.log_security_event(
        event_type="test_event",
        target="example.com",
        details={"test": True, "value": 42}
    )
    
    print("Logging test completed. Check the logs/ directory.")