"""
Safe Brute Force Simulation Module
Simulates brute force attacks for educational and testing purposes
"""

import random
import time
import json
from typing import Dict, List, Optional
from pathlib import Path
import itertools
from shared.logger import get_logger
from shared.utils import save_scan_results, send_alert

logger = get_logger(__name__)

class BruteForceSimulator:
    def __init__(self):
        self.common_passwords = [
            "123456", "password", "123456789", "12345678", "12345",
            "1234567", "1234567890", "qwerty", "abc123", "111111",
            "123123", "admin", "letmein", "welcome", "monkey",
            "password123", "admin123", "root", "toor", "pass"
        ]
        
        self.common_usernames = [
            "admin", "administrator", "root", "user", "test",
            "guest", "demo", "ftp", "mail", "www", "web",
            "operator", "manager", "service", "support"
        ]
        
        self.reports_dir = Path("reports")
        self.reports_dir.mkdir(exist_ok=True)
        
    def generate_wordlist(self, service: str) -> List[Dict[str, str]]:
        """Generate wordlist based on service type"""
        wordlist = []
        
        # Service-specific common credentials
        service_creds = {
            "ssh": [
                {"username": "root", "password": "toor"},
                {"username": "admin", "password": "admin"},
                {"username": "pi", "password": "raspberry"},
                {"username": "ubuntu", "password": "ubuntu"}
            ],
            "ftp": [
                {"username": "ftp", "password": "ftp"},
                {"username": "anonymous", "password": ""},
                {"username": "admin", "password": "admin"},
                {"username": "ftpuser", "password": "password"}
            ],
            "http": [
                {"username": "admin", "password": "admin"},
                {"username": "administrator", "password": "password"},
                {"username": "root", "password": "root"},
                {"username": "user", "password": "user"}
            ]
        }
        
        # Add service-specific credentials
        if service in service_creds:
            wordlist.extend(service_creds[service])
            
        # Add combinations of common usernames and passwords
        for username in self.common_usernames[:5]:  # Limit for demo
            for password in self.common_passwords[:5]:  # Limit for demo
                wordlist.append({"username": username, "password": password})
                
        return wordlist[:20]  # Limit total attempts for demo
        
    def simulate_ssh_brute_force(self, target: str, wordlist: List[Dict]) -> Dict:
        """Simulate SSH brute force attack"""
        logger.info(f"Simulating SSH brute force on {target}")
        
        results = {
            "target": target,
            "service": "ssh",
            "port": 22,
            "scan_type": "brute_force_simulation",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "attempts": [],
            "successful_logins": [],
            "failed_attempts": 0,
            "rate_limited": False
        }
        
        for i, cred in enumerate(wordlist):
            # Simulate delay between attempts
            time.sleep(0.1)
            
            attempt = {
                "username": cred["username"],
                "password": cred["password"],
                "timestamp": time.strftime("%H:%M:%S"),
                "success": False,
                "response_time": random.uniform(0.5, 2.0)
            }
            
            # Simulate occasional success for demo
            if random.random() < 0.05:  # 5% chance of success
                attempt["success"] = True
                results["successful_logins"].append(cred)
                logger.warning(f"Simulated successful login: {cred['username']}:{cred['password']}")
            else:
                results["failed_attempts"] += 1
                
            results["attempts"].append(attempt)
            
            # Simulate rate limiting after many attempts
            if i > 10 and random.random() < 0.3:
                results["rate_limited"] = True
                logger.info("Simulated rate limiting detected")
                break
                
        return results
        
    def simulate_ftp_brute_force(self, target: str, wordlist: List[Dict]) -> Dict:
        """Simulate FTP brute force attack"""
        logger.info(f"Simulating FTP brute force on {target}")
        
        results = {
            "target": target,
            "service": "ftp",
            "port": 21,
            "scan_type": "brute_force_simulation", 
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "attempts": [],
            "successful_logins": [],
            "failed_attempts": 0,
            "anonymous_allowed": False
        }
        
        # Check for anonymous FTP first
        if random.random() < 0.2:  # 20% chance anonymous is allowed
            results["anonymous_allowed"] = True
            results["successful_logins"].append({"username": "anonymous", "password": ""})
            logger.warning("Simulated anonymous FTP access allowed")
            
        for cred in wordlist:
            time.sleep(0.1)
            
            attempt = {
                "username": cred["username"],
                "password": cred["password"],
                "timestamp": time.strftime("%H:%M:%S"),
                "success": False,
                "response_code": "530",  # Authentication failed
                "response_time": random.uniform(0.3, 1.5)
            }
            
            # Simulate occasional success
            if random.random() < 0.03:  # 3% chance
                attempt["success"] = True
                attempt["response_code"] = "230"  # User logged in
                results["successful_logins"].append(cred)
                logger.warning(f"Simulated FTP login: {cred['username']}:{cred['password']}")
            else:
                results["failed_attempts"] += 1
                
            results["attempts"].append(attempt)
            
        return results
        
    def simulate_http_brute_force(self, target: str, wordlist: List[Dict]) -> Dict:
        """Simulate HTTP form brute force attack"""
        logger.info(f"Simulating HTTP brute force on {target}")
        
        results = {
            "target": target,
            "service": "http",
            "port": 80,
            "scan_type": "brute_force_simulation",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "login_page": f"http://{target}/admin/login",
            "attempts": [],
            "successful_logins": [],
            "failed_attempts": 0,
            "captcha_detected": False,
            "account_lockouts": []
        }
        
        failed_attempts_per_user = {}
        
        for cred in wordlist:
            time.sleep(0.2)  # HTTP requests typically slower
            
            username = cred["username"]
            password = cred["password"]
            
            # Track failed attempts per user
            if username not in failed_attempts_per_user:
                failed_attempts_per_user[username] = 0
                
            attempt = {
                "username": username,
                "password": password,
                "timestamp": time.strftime("%H:%M:%S"),
                "success": False,
                "status_code": 401,  # Unauthorized
                "response_time": random.uniform(0.8, 3.0),
                "captcha_required": False
            }
            
            # Simulate account lockout after multiple failures
            if failed_attempts_per_user[username] >= 5:
                attempt["status_code"] = 423  # Locked
                if username not in results["account_lockouts"]:
                    results["account_lockouts"].append(username)
                    logger.warning(f"Simulated account lockout for {username}")
            else:
                # Simulate success
                if random.random() < 0.04:  # 4% chance
                    attempt["success"] = True
                    attempt["status_code"] = 200  # Success
                    results["successful_logins"].append(cred)
                    logger.warning(f"Simulated HTTP login: {username}:{password}")
                else:
                    results["failed_attempts"] += 1
                    failed_attempts_per_user[username] += 1
                    
                # Simulate CAPTCHA after many attempts
                if results["failed_attempts"] > 8 and random.random() < 0.4:
                    attempt["captcha_required"] = True
                    results["captcha_detected"] = True
                    
            results["attempts"].append(attempt)
            
        return results
        
    def simulate(self, target: str, service: str = "ssh", 
                custom_wordlist: Optional[List[Dict]] = None) -> Dict:
        """
        Run brute force simulation
        
        Args:
            target: Target IP/domain
            service: Service to test (ssh, ftp, http)
            custom_wordlist: Optional custom credential list
        """
        logger.info(f"Starting brute force simulation: {service} on {target}")
        
        # Validate service
        if service not in ["ssh", "ftp", "http"]:
            raise ValueError(f"Unsupported service: {service}")
            
        # Generate or use custom wordlist
        wordlist = custom_wordlist if custom_wordlist else self.generate_wordlist(service)
        
        try:
            # Run simulation based on service
            if service == "ssh":
                results = self.simulate_ssh_brute_force(target, wordlist)
            elif service == "ftp":
                results = self.simulate_ftp_brute_force(target, wordlist)
            elif service == "http":
                results = self.simulate_http_brute_force(target, wordlist)
                
            # Add summary statistics
            results["summary"] = {
                "total_attempts": len(results["attempts"]),
                "successful_logins": len(results["successful_logins"]),
                "success_rate": len(results["successful_logins"]) / len(results["attempts"]) * 100 if results["attempts"] else 0,
                "time_taken": len(results["attempts"]) * 0.15,  # Approximate time
                "recommendations": self.generate_recommendations(results)
            }
            
            # Save results
            save_scan_results(results, f"bruteforce_{service}")
            
            # Send alerts if successful logins found
            if results["successful_logins"]:
                send_alert(f"Brute force simulation found weak credentials on {target} ({service})")
                
            logger.info(f"Brute force simulation completed for {target}")
            return results
            
        except Exception as e:
            logger.error(f"Brute force simulation failed: {e}")
            return {"error": str(e)}
            
    def generate_recommendations(self, results: Dict) -> List[str]:
        """Generate security recommendations based on results"""
        recommendations = []
        
        if results["successful_logins"]:
            recommendations.append("❌ Weak credentials detected - implement strong password policies")
            recommendations.append("🔒 Enable multi-factor authentication (MFA)")
            
        if results.get("rate_limited"):
            recommendations.append("✅ Rate limiting is active - good security practice")
        else:
            recommendations.append("⚠️  Implement rate limiting to prevent brute force attacks")
            
        if results.get("account_lockouts"):
            recommendations.append("✅ Account lockout policy is active")
        elif results["service"] == "http":
            recommendations.append("⚠️  Consider implementing account lockout policies")
            
        if results.get("captcha_detected"):
            recommendations.append("✅ CAPTCHA protection detected")
        elif results["service"] == "http":
            recommendations.append("💡 Consider implementing CAPTCHA for additional protection")
            
        if results.get("anonymous_allowed") and results["service"] == "ftp":
            recommendations.append("❌ Anonymous FTP access allowed - security risk")
            
        # General recommendations
        recommendations.extend([
            "🔐 Use key-based authentication where possible",
            "📊 Monitor and log authentication attempts",
            "🚫 Disable unnecessary services and accounts",
            "🔄 Regular security audits and password updates"
        ])
        
        return recommendations
        
    def generate_report(self, target: str) -> Dict:
        """Generate comprehensive brute force test report"""
        report = {
            "target": target,
            "report_type": "brute_force_assessment",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "services_tested": [],
            "overall_security_score": 0,
            "critical_findings": [],
            "recommendations": []
        }
        
        # Load all brute force results for the target
        scan_files = list(self.reports_dir.glob(f"bruteforce_*{target}*.json"))
        
        total_score = 0
        services_count = 0
        
        for scan_file in scan_files:
            try:
                with open(scan_file, 'r') as f:
                    scan_data = json.load(f)
                    report["services_tested"].append(scan_data)
                    
                    # Calculate security score for this service
                    service_score = self.calculate_security_score(scan_data)
                    total_score += service_score
                    services_count += 1
                    
                    # Add critical findings
                    if scan_data.get("successful_logins"):
                        report["critical_findings"].append({
                            "service": scan_data["service"],
                            "issue": "Weak credentials found",
                            "credentials": scan_data["successful_logins"]
                        })
                        
            except Exception as e:
                logger.error(f"Error loading scan file {scan_file}: {e}")
                
        # Calculate overall score
        if services_count > 0:
            report["overall_security_score"] = total_score / services_count
            
        return report
        
    def calculate_security_score(self, scan_data: Dict) -> float:
        """Calculate security score based on scan results"""
        score = 10.0  # Start with perfect score
        
        # Deduct points for weaknesses
        if scan_data.get("successful_logins"):
            score -= 4.0  # Major deduction for successful logins
            
        if not scan_data.get("rate_limited") and not scan_data.get("account_lockouts"):
            score -= 2.0  # No rate limiting or lockouts
            
        if scan_data.get("anonymous_allowed"):
            score -= 3.0  # Anonymous access allowed
            
        if not scan_data.get("captcha_detected") and scan_data["service"] == "http":
            score -= 1.0  # No CAPTCHA protection
            
        return max(0.0, score)  # Ensure score doesn't go below 0