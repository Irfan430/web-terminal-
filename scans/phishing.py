"""
Phishing Simulation Module
Sends educational phishing emails for security awareness training
"""

import smtplib
import random
import time
import json
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, List, Optional
from pathlib import Path
import os
from shared.logger import get_logger
from shared.utils import save_scan_results, send_alert

logger = get_logger(__name__)

class PhishingSimulator:
    def __init__(self):
        self.reports_dir = Path("reports")
        self.reports_dir.mkdir(exist_ok=True)
        
        # Email templates for different types of phishing simulations
        self.templates = {
            "banking": {
                "subject": "🔒 Urgent: Verify Your Account - Security Alert",
                "sender_name": "Security Team",
                "sender_email": "security@bankingsystem.com",
                "template": """
Dear Valued Customer,

We have detected unusual activity on your account. For your security, 
we need you to verify your account information immediately.

URGENT ACTION REQUIRED:
- Login attempts from unknown devices detected
- Account access will be suspended in 24 hours if not verified

Click here to verify your account: [VERIFICATION_LINK]

If you do not verify within 24 hours, your account will be temporarily 
suspended for security reasons.

Thank you for your immediate attention to this matter.

Security Department
Banking Security Team

---
This is a PHISHING SIMULATION for security awareness training.
If you clicked the link, please report this to your IT security team.
                """
            },
            "tech": {
                "subject": "🚨 Microsoft Security Alert - Action Required",
                "sender_name": "Microsoft Security",
                "sender_email": "security-noreply@microsoft.com",
                "template": """
Microsoft Security Alert

Hello,

We've detected a new sign-in to your Microsoft account from an 
unrecognized device.

Device: Windows PC
Location: Unknown Location
Time: {timestamp}

If this was you, you can safely ignore this email.

If this wasn't you, your account may be compromised.
Secure your account: [SECURITY_LINK]

Change your password immediately and review your account activity.

Microsoft Account Team

---
PHISHING SIMULATION: This is a training exercise.
Do not click links in suspicious emails.
                """
            },
            "social": {
                "subject": "🎉 You've received a friend request!",
                "sender_name": "Social Network",
                "sender_email": "notifications@socialnetwork.com",
                "template": """
Hi there!

Great news! Someone wants to connect with you.

{sender_name} wants to be your friend on Social Network.

View Profile: [PROFILE_LINK]
Accept Request: [ACCEPT_LINK]

You have 3 more pending friend requests waiting for you.

See all notifications: [NOTIFICATIONS_LINK]

Stay connected!
The Social Network Team

---
SECURITY AWARENESS: This is a phishing simulation.
Always verify the sender before clicking links.
                """
            },
            "package": {
                "subject": "📦 Package Delivery Failed - Action Required",
                "sender_name": "Delivery Service",
                "sender_email": "delivery@packageservice.com",
                "template": """
Package Delivery Notification

Dear Customer,

We attempted to deliver your package but no one was available 
at the delivery address.

Package Details:
- Tracking Number: PKG-{tracking_number}
- Delivery Date: {delivery_date}
- Status: DELIVERY FAILED

To reschedule delivery: [RESCHEDULE_LINK]
Track your package: [TRACKING_LINK]

Please reschedule within 3 business days or your package 
will be returned to sender.

Customer Service
Package Delivery Service

---
PHISHING AWARENESS: This is a training simulation.
Verify delivery notifications through official websites.
                """
            }
        }
        
    def generate_tracking_number(self) -> str:
        """Generate realistic tracking number"""
        return f"{''.join(random.choices('0123456789ABCDEF', k=12))}"
        
    def generate_phishing_links(self) -> Dict[str, str]:
        """Generate safe phishing simulation links"""
        base_url = "https://phishing-simulation.local"
        
        return {
            "VERIFICATION_LINK": f"{base_url}/verify-account?sim=banking",
            "SECURITY_LINK": f"{base_url}/security-check?sim=tech", 
            "PROFILE_LINK": f"{base_url}/profile?sim=social",
            "ACCEPT_LINK": f"{base_url}/accept-friend?sim=social",
            "NOTIFICATIONS_LINK": f"{base_url}/notifications?sim=social",
            "RESCHEDULE_LINK": f"{base_url}/reschedule?sim=package",
            "TRACKING_LINK": f"{base_url}/track?sim=package"
        }
        
    def customize_template(self, template_type: str, target_email: str) -> Dict[str, str]:
        """Customize email template with dynamic content"""
        if template_type not in self.templates:
            raise ValueError(f"Unknown template type: {template_type}")
            
        template = self.templates[template_type].copy()
        links = self.generate_phishing_links()
        
        # Replace placeholders in template
        content = template["template"]
        
        # Dynamic content based on template type
        if template_type == "tech":
            content = content.format(
                timestamp=time.strftime("%Y-%m-%d %H:%M:%S")
            )
        elif template_type == "social":
            fake_names = ["John Smith", "Sarah Johnson", "Mike Wilson", "Emma Davis"]
            content = content.format(
                sender_name=random.choice(fake_names)
            )
        elif template_type == "package":
            content = content.format(
                tracking_number=self.generate_tracking_number(),
                delivery_date=time.strftime("%Y-%m-%d")
            )
            
        # Replace link placeholders
        for placeholder, link in links.items():
            content = content.replace(f"[{placeholder}]", link)
            
        template["template"] = content
        template["target_email"] = target_email
        template["simulation_id"] = f"SIM-{int(time.time())}"
        
        return template
        
    def simulate_email_send(self, template_data: Dict, target_email: str) -> Dict:
        """Simulate sending phishing email (for demo purposes)"""
        logger.info(f"Simulating phishing email to {target_email}")
        
        # Simulate email sending process
        time.sleep(random.uniform(0.5, 2.0))  # Simulate network delay
        
        results = {
            "target_email": target_email,
            "template_type": template_data.get("template_type", "unknown"),
            "subject": template_data["subject"],
            "sender": f"{template_data['sender_name']} <{template_data['sender_email']}>",
            "simulation_id": template_data["simulation_id"],
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "status": "sent",
            "delivery_simulation": {
                "smtp_response": "250 Message accepted for delivery",
                "delivery_time": random.uniform(0.8, 3.2),
                "message_id": f"<{template_data['simulation_id']}@phishing-sim.local>"
            }
        }
        
        # Simulate occasional delivery issues
        if random.random() < 0.1:  # 10% chance of delivery issues
            results["status"] = "failed"
            results["error"] = random.choice([
                "Mailbox full",
                "Invalid recipient",
                "Spam filter blocked",
                "Server temporarily unavailable"
            ])
            logger.warning(f"Simulated delivery failure: {results['error']}")
        else:
            logger.info(f"Phishing simulation email 'sent' to {target_email}")
            
        return results
        
    def send_training_email(self, target_email: str, template_type: str = "banking",
                          custom_template: Optional[Dict] = None) -> Dict:
        """
        Send phishing simulation email
        
        Args:
            target_email: Target email address
            template_type: Type of phishing template (banking, tech, social, package)
            custom_template: Optional custom email template
        """
        logger.info(f"Starting phishing simulation for {target_email}")
        
        try:
            # Validate email format (basic validation)
            if "@" not in target_email or "." not in target_email:
                raise ValueError("Invalid email format")
                
            # Use custom template or predefined template
            if custom_template:
                template_data = custom_template
                template_data["template_type"] = "custom"
            else:
                template_data = self.customize_template(template_type, target_email)
                template_data["template_type"] = template_type
                
            # Simulate sending email
            send_results = self.simulate_email_send(template_data, target_email)
            
            # Create comprehensive results
            results = {
                "target_email": target_email,
                "template_type": template_data["template_type"],
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "scan_type": "phishing_simulation",
                "email_details": {
                    "subject": template_data["subject"],
                    "sender_name": template_data["sender_name"],
                    "sender_email": template_data["sender_email"],
                    "content_preview": template_data["template"][:200] + "..."
                },
                "send_results": send_results,
                "simulation_metrics": {
                    "email_sent": send_results["status"] == "sent",
                    "potential_click_indicators": self.analyze_email_risk(template_data),
                    "security_training_value": self.calculate_training_value(template_type)
                },
                "recommendations": self.generate_security_recommendations(template_type)
            }
            
            # Save results
            save_scan_results(results, "phishing_simulation")
            
            # Send alert if this represents a security training need
            if results["simulation_metrics"]["security_training_value"] >= 7:
                send_alert(f"High-value phishing simulation completed for {target_email}")
                
            logger.info(f"Phishing simulation completed for {target_email}")
            return results
            
        except Exception as e:
            logger.error(f"Phishing simulation failed: {e}")
            return {"error": str(e)}
            
    def analyze_email_risk(self, template_data: Dict) -> Dict:
        """Analyze the risk factors present in the phishing email"""
        risk_factors = {
            "urgency_indicators": 0,
            "authority_spoofing": 0,
            "suspicious_links": 0,
            "emotional_manipulation": 0,
            "trust_exploitation": 0
        }
        
        content = template_data["template"].lower()
        
        # Check for urgency indicators
        urgency_words = ["urgent", "immediate", "expire", "suspend", "within", "hours"]
        risk_factors["urgency_indicators"] = sum(1 for word in urgency_words if word in content)
        
        # Check for authority spoofing
        authority_terms = ["security", "bank", "microsoft", "official", "department"]
        risk_factors["authority_spoofing"] = sum(1 for term in authority_terms if term in content)
        
        # Check for suspicious links (simulation links)
        risk_factors["suspicious_links"] = content.count("https://phishing-simulation.local")
        
        # Check for emotional manipulation
        emotion_words = ["alert", "warning", "compromised", "suspicious", "detected"]
        risk_factors["emotional_manipulation"] = sum(1 for word in emotion_words if word in content)
        
        # Check for trust exploitation
        trust_words = ["verify", "confirm", "update", "secure", "protect"]
        risk_factors["trust_exploitation"] = sum(1 for word in trust_words if word in content)
        
        return risk_factors
        
    def calculate_training_value(self, template_type: str) -> int:
        """Calculate the training value of the phishing simulation (1-10)"""
        training_values = {
            "banking": 9,    # High value - common attack vector
            "tech": 8,       # High value - tech support scams
            "social": 6,     # Medium value - social engineering
            "package": 7,    # Medium-high value - delivery scams
            "custom": 5      # Default for custom templates
        }
        
        return training_values.get(template_type, 5)
        
    def generate_security_recommendations(self, template_type: str) -> List[str]:
        """Generate security recommendations based on template type"""
        common_recommendations = [
            "🔍 Always verify sender identity through official channels",
            "🚫 Never click links in suspicious emails",
            "📞 Call the organization directly if unsure about email authenticity",
            "🔒 Use multi-factor authentication where available",
            "📧 Report suspicious emails to your IT security team"
        ]
        
        specific_recommendations = {
            "banking": [
                "🏦 Banks never ask for credentials via email",
                "💳 Log in directly to your bank's website, not through email links",
                "📱 Use official banking mobile apps for account access"
            ],
            "tech": [
                "💻 Microsoft and other tech companies don't send unsolicited security emails",
                "🔐 Change passwords through official websites only",
                "📞 Verify security alerts by calling official support numbers"
            ],
            "social": [
                "👥 Be cautious of friend requests from unknown people",
                "🔗 Social media links can lead to malicious sites",
                "🔒 Check privacy settings regularly on social platforms"
            ],
            "package": [
                "📦 Verify tracking numbers on official carrier websites",
                "🚚 Delivery companies provide tracking without requiring personal info",
                "📧 Be suspicious of unexpected delivery notifications"
            ]
        }
        
        recommendations = common_recommendations.copy()
        if template_type in specific_recommendations:
            recommendations.extend(specific_recommendations[template_type])
            
        return recommendations
        
    def generate_campaign_report(self, campaign_results: List[Dict]) -> Dict:
        """Generate comprehensive phishing campaign report"""
        if not campaign_results:
            return {"error": "No campaign results provided"}
            
        report = {
            "campaign_summary": {
                "total_emails": len(campaign_results),
                "successful_sends": len([r for r in campaign_results if r.get("send_results", {}).get("status") == "sent"]),
                "failed_sends": len([r for r in campaign_results if r.get("send_results", {}).get("status") == "failed"]),
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
            },
            "template_breakdown": {},
            "risk_analysis": {
                "high_risk_targets": [],
                "medium_risk_targets": [],
                "low_risk_targets": []
            },
            "training_recommendations": [],
            "overall_security_posture": 0
        }
        
        # Analyze template usage
        for result in campaign_results:
            template_type = result.get("template_type", "unknown")
            if template_type not in report["template_breakdown"]:
                report["template_breakdown"][template_type] = {
                    "count": 0,
                    "success_rate": 0,
                    "avg_training_value": 0
                }
            report["template_breakdown"][template_type]["count"] += 1
            
        # Calculate success rates and training values
        for template_type, data in report["template_breakdown"].items():
            template_results = [r for r in campaign_results if r.get("template_type") == template_type]
            successful = len([r for r in template_results if r.get("send_results", {}).get("status") == "sent"])
            data["success_rate"] = (successful / len(template_results) * 100) if template_results else 0
            data["avg_training_value"] = self.calculate_training_value(template_type)
            
        # Generate overall recommendations
        report["training_recommendations"] = [
            "📚 Conduct regular security awareness training",
            "🎯 Focus on phishing recognition techniques", 
            "📧 Implement email security controls",
            "📊 Regular phishing simulation campaigns",
            "🔍 Monitor and measure security awareness metrics"
        ]
        
        return report
        
    def bulk_simulate(self, email_list: List[str], template_type: str = "banking") -> List[Dict]:
        """Run phishing simulation for multiple email addresses"""
        logger.info(f"Starting bulk phishing simulation for {len(email_list)} targets")
        
        results = []
        for email in email_list:
            try:
                result = self.send_training_email(email, template_type)
                results.append(result)
                
                # Small delay between emails to avoid overwhelming
                time.sleep(random.uniform(0.5, 1.0))
                
            except Exception as e:
                logger.error(f"Failed to send simulation email to {email}: {e}")
                results.append({
                    "target_email": email,
                    "error": str(e),
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
                })
                
        logger.info(f"Bulk phishing simulation completed: {len(results)} emails processed")
        
        # Generate campaign report
        campaign_report = self.generate_campaign_report(results)
        
        # Save campaign report
        report_file = self.reports_dir / f"phishing_campaign_{int(time.time())}.json"
        with open(report_file, 'w') as f:
            json.dump(campaign_report, f, indent=2)
            
        return results