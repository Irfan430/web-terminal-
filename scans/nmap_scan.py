"""
Nmap and Nikto vulnerability scanner module
Handles port scanning and web vulnerability detection
"""

import subprocess
import json
import re
import time
from typing import Dict, List, Optional
from pathlib import Path
import xml.etree.ElementTree as ET
from shared.logger import get_logger
from shared.utils import save_scan_results, send_alert

logger = get_logger(__name__)

class NmapScanner:
    def __init__(self):
        self.scan_results = {}
        self.reports_dir = Path("reports")
        self.reports_dir.mkdir(exist_ok=True)
        
    def check_nmap_installed(self) -> bool:
        """Check if nmap is installed on the system"""
        try:
            subprocess.run(["nmap", "--version"], 
                         capture_output=True, check=True)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            logger.warning("Nmap not found, using simulation mode")
            return False
            
    def check_nikto_installed(self) -> bool:
        """Check if nikto is installed on the system"""
        try:
            subprocess.run(["nikto", "-Version"], 
                         capture_output=True, check=True)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            logger.warning("Nikto not found, using simulation mode")
            return False
            
    def simulate_nmap_scan(self, target: str) -> Dict:
        """Simulate nmap scan results for demo purposes"""
        logger.info(f"Simulating nmap scan for {target}")
        
        # Simulate realistic scan results
        simulated_ports = [22, 80, 443, 3306, 5432]
        services = {
            22: {"service": "ssh", "version": "OpenSSH 8.9", "state": "open"},
            80: {"service": "http", "version": "Apache 2.4.52", "state": "open"},
            443: {"service": "https", "version": "Apache 2.4.52", "state": "open"},
            3306: {"service": "mysql", "version": "MySQL 8.0.28", "state": "open"},
            5432: {"service": "postgresql", "version": "PostgreSQL 14.2", "state": "open"}
        }
        
        results = {
            "target": target,
            "scan_type": "nmap_simulation",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "open_ports": simulated_ports,
            "services": services,
            "os_detection": "Linux 5.15",
            "vulnerabilities": [
                "SSH version may be vulnerable to timing attacks",
                "MySQL running on default port - consider changing",
                "PostgreSQL exposed - review access controls"
            ]
        }
        
        return results
        
    def parse_nmap_xml(self, xml_output: str) -> Dict:
        """Parse nmap XML output"""
        try:
            root = ET.fromstring(xml_output)
            results = {
                "open_ports": [],
                "services": {},
                "os_detection": None,
                "vulnerabilities": []
            }
            
            for host in root.findall('host'):
                # Parse ports
                for port in host.findall('.//port'):
                    state = port.find('state')
                    if state is not None and state.get('state') == 'open':
                        port_num = int(port.get('portid'))
                        results["open_ports"].append(port_num)
                        
                        service = port.find('service')
                        if service is not None:
                            results["services"][port_num] = {
                                "service": service.get('name', 'unknown'),
                                "version": service.get('version', 'unknown'),
                                "state": "open"
                            }
                            
                # Parse OS detection
                os_elem = host.find('.//osmatch')
                if os_elem is not None:
                    results["os_detection"] = os_elem.get('name')
                    
            return results
        except ET.ParseError as e:
            logger.error(f"Error parsing nmap XML: {e}")
            return {}
            
    def scan(self, target: str, scan_type: str = "basic") -> Dict:
        """
        Perform nmap scan on target
        
        Args:
            target: IP address or domain to scan
            scan_type: Type of scan (basic, aggressive, stealth)
        """
        logger.info(f"Starting nmap scan on {target}")
        
        if not self.check_nmap_installed():
            return self.simulate_nmap_scan(target)
            
        try:
            # Build nmap command based on scan type
            if scan_type == "aggressive":
                cmd = ["nmap", "-A", "-T4", "-oX", "-", target]
            elif scan_type == "stealth":
                cmd = ["nmap", "-sS", "-T2", "-oX", "-", target]
            else:  # basic
                cmd = ["nmap", "-sS", "-sV", "-O", "-oX", "-", target]
                
            # Execute nmap scan
            result = subprocess.run(cmd, capture_output=True, 
                                  text=True, timeout=300)
            
            if result.returncode == 0:
                # Parse XML output
                scan_results = self.parse_nmap_xml(result.stdout)
                scan_results.update({
                    "target": target,
                    "scan_type": f"nmap_{scan_type}",
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "raw_output": result.stdout
                })
                
                # Save results
                save_scan_results(scan_results, "nmap")
                
                # Send alerts for critical findings
                if len(scan_results.get("open_ports", [])) > 10:
                    send_alert(f"High number of open ports detected on {target}")
                    
                logger.info(f"Nmap scan completed for {target}")
                return scan_results
            else:
                logger.error(f"Nmap scan failed: {result.stderr}")
                return self.simulate_nmap_scan(target)
                
        except subprocess.TimeoutExpired:
            logger.error("Nmap scan timed out")
            return {"error": "Scan timeout"}
        except Exception as e:
            logger.error(f"Nmap scan error: {e}")
            return self.simulate_nmap_scan(target)
            
    def nikto_scan(self, target: str, port: int = 80) -> Dict:
        """
        Perform Nikto web vulnerability scan
        
        Args:
            target: Target domain/IP
            port: Port to scan (default 80)
        """
        logger.info(f"Starting Nikto scan on {target}:{port}")
        
        if not self.check_nikto_installed():
            return self.simulate_nikto_scan(target, port)
            
        try:
            cmd = ["nikto", "-h", f"{target}:{port}", "-Format", "json", "-nossl"]
            
            result = subprocess.run(cmd, capture_output=True, 
                                  text=True, timeout=600)
            
            if result.returncode == 0:
                # Parse nikto output
                nikto_results = self.parse_nikto_output(result.stdout)
                nikto_results.update({
                    "target": target,
                    "port": port,
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
                })
                
                # Save results
                save_scan_results(nikto_results, "nikto")
                
                # Send alerts for high-risk vulnerabilities
                high_risk_count = len([v for v in nikto_results.get("vulnerabilities", []) 
                                     if "high" in v.get("severity", "").lower()])
                if high_risk_count > 0:
                    send_alert(f"High-risk web vulnerabilities found on {target}")
                    
                logger.info(f"Nikto scan completed for {target}")
                return nikto_results
            else:
                logger.error(f"Nikto scan failed: {result.stderr}")
                return self.simulate_nikto_scan(target, port)
                
        except subprocess.TimeoutExpired:
            logger.error("Nikto scan timed out")
            return {"error": "Scan timeout"}
        except Exception as e:
            logger.error(f"Nikto scan error: {e}")
            return self.simulate_nikto_scan(target, port)
            
    def simulate_nikto_scan(self, target: str, port: int) -> Dict:
        """Simulate nikto scan results"""
        logger.info(f"Simulating Nikto scan for {target}:{port}")
        
        vulnerabilities = [
            {
                "id": "000001",
                "description": "Server may leak inodes via ETags",
                "severity": "low",
                "url": f"http://{target}:{port}/"
            },
            {
                "id": "000002", 
                "description": "Missing X-Content-Type-Options header",
                "severity": "medium",
                "url": f"http://{target}:{port}/"
            },
            {
                "id": "000003",
                "description": "Possible backup/config files found",
                "severity": "high",
                "url": f"http://{target}:{port}/backup/"
            }
        ]
        
        return {
            "scan_type": "nikto_simulation",
            "vulnerabilities": vulnerabilities,
            "total_tests": 6500,
            "scan_time": "45 seconds"
        }
        
    def parse_nikto_output(self, output: str) -> Dict:
        """Parse nikto scan output"""
        vulnerabilities = []
        
        # Simple parsing for demo - in production, use proper JSON parsing
        lines = output.split('\n')
        for line in lines:
            if '+ ' in line and 'OSVDB' in line:
                vuln = {
                    "description": line.strip(),
                    "severity": "medium",  # Default severity
                    "url": "/"
                }
                vulnerabilities.append(vuln)
                
        return {
            "scan_type": "nikto",
            "vulnerabilities": vulnerabilities,
            "total_tests": len(lines),
            "scan_time": "unknown"
        }
        
    def get_scan_summary(self, target: str) -> Dict:
        """Get summary of all scans for a target"""
        summary = {
            "target": target,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "scans_performed": []
        }
        
        # Load scan results from files
        scan_files = list(self.reports_dir.glob(f"*{target}*.json"))
        for scan_file in scan_files:
            try:
                with open(scan_file, 'r') as f:
                    scan_data = json.load(f)
                    summary["scans_performed"].append(scan_data)
            except Exception as e:
                logger.error(f"Error loading scan file {scan_file}: {e}")
                
        return summary