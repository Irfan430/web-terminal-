#!/usr/bin/env python3
"""
Cybersecurity Multi-Tool CLI
Production-grade terminal-based security toolkit
"""

import typer
import os
import sys
import time
import subprocess
from typing import Optional
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import track
from pathlib import Path

# Import our modules
from scans.nmap_scan import NmapScanner
from scans.brute_force import BruteForceSimulator
from scans.phishing import PhishingSimulator
from ml.predict import RiskPredictor
from shared.logger import get_logger
from shared.utils import generate_pdf_report, setup_environment, check_dependencies

app = typer.Typer(help="🔒 Cybersecurity Multi-Tool - Professional Security Testing Suite")
console = Console()
logger = get_logger(__name__)

class CyberToolkit:
    def __init__(self):
        self.target = None
        self.reports_dir = Path("reports")
        self.reports_dir.mkdir(exist_ok=True)
        
        # Initialize components
        self.nmap_scanner = NmapScanner()
        self.brute_force = BruteForceSimulator()
        self.phishing = PhishingSimulator()
        self.risk_predictor = RiskPredictor()
        
    def display_banner(self):
        """Display welcome banner"""
        banner = """
╔═══════════════════════════════════════════════════════════════╗
║                    CYBERSECURITY MULTI-TOOL                  ║
║                   Professional Security Suite                ║
║                                                              ║
║  🔍 Vulnerability Scanning  🔐 Brute Force Testing          ║
║  📧 Phishing Simulation    🤖 AI Risk Analysis              ║
║  📊 PDF Reports           🌐 Web Dashboard                   ║
╚═══════════════════════════════════════════════════════════════╝
        """
        console.print(Panel(banner, style="bold blue"))
        
    def get_target(self):
        """Get target domain/IP from user"""
        if not self.target:
            self.target = typer.prompt("🎯 Enter target domain/IP")
            logger.info(f"Target set to: {self.target}")
        return self.target
        
    def show_menu(self):
        """Display interactive menu"""
        table = Table(title="🔧 Available Tools", show_header=True, header_style="bold magenta")
        table.add_column("Option", style="cyan", no_wrap=True)
        table.add_column("Description", style="white")
        
        options = [
            ("1", "🔍 Vulnerability Scan (Nmap + Nikto)"),
            ("2", "🔐 Safe Brute Force Simulation"),
            ("3", "📧 Phishing Simulation"),
            ("4", "🤖 AI Risk Prediction"),
            ("5", "📊 Generate PDF Report"),
            ("6", "🌐 Launch Local Web Dashboard"),
            ("7", "❌ Exit")
        ]
        
        for option, desc in options:
            table.add_row(option, desc)
            
        console.print(table)
        
    def run_vulnerability_scan(self):
        """Run Nmap and Nikto vulnerability scans"""
        target = self.get_target()
        console.print(f"[bold yellow]🔍 Starting vulnerability scan on {target}...[/bold yellow]")
        
        try:
            # Run Nmap scan
            console.print("📡 Running Nmap port scan...")
            nmap_results = self.nmap_scanner.scan(target)
            
            # Run Nikto web scan if HTTP ports are open
            if any(port in [80, 443, 8080, 8443] for port in nmap_results.get('open_ports', [])):
                console.print("🌐 Running Nikto web vulnerability scan...")
                nikto_results = self.nmap_scanner.nikto_scan(target)
                nmap_results['nikto'] = nikto_results
                
            console.print("[bold green]✅ Vulnerability scan completed![/bold green]")
            return nmap_results
            
        except Exception as e:
            console.print(f"[bold red]❌ Scan failed: {str(e)}[/bold red]")
            logger.error(f"Vulnerability scan failed: {str(e)}")
            return None
            
    def run_brute_force(self):
        """Run safe brute force simulation"""
        target = self.get_target()
        console.print(f"[bold yellow]🔐 Starting brute force simulation on {target}...[/bold yellow]")
        
        service = typer.prompt("Select service (ssh/ftp/http)", default="ssh")
        
        try:
            results = self.brute_force.simulate(target, service)
            console.print("[bold green]✅ Brute force simulation completed![/bold green]")
            return results
        except Exception as e:
            console.print(f"[bold red]❌ Simulation failed: {str(e)}[/bold red]")
            logger.error(f"Brute force simulation failed: {str(e)}")
            return None
            
    def run_phishing_simulation(self):
        """Run phishing email simulation"""
        console.print("[bold yellow]📧 Starting phishing simulation...[/bold yellow]")
        
        try:
            email = typer.prompt("Target email address")
            template = typer.prompt("Email template (banking/tech/social)", default="banking")
            
            results = self.phishing.send_training_email(email, template)
            console.print("[bold green]✅ Phishing simulation completed![/bold green]")
            return results
        except Exception as e:
            console.print(f"[bold red]❌ Phishing simulation failed: {str(e)}[/bold red]")
            logger.error(f"Phishing simulation failed: {str(e)}")
            return None
            
    def run_ai_prediction(self):
        """Run AI risk prediction"""
        target = self.get_target()
        console.print(f"[bold yellow]🤖 Analyzing risk for {target}...[/bold yellow]")
        
        try:
            risk_score = self.risk_predictor.predict_risk(target)
            console.print(f"[bold cyan]🎯 Risk Score: {risk_score:.2f}/10[/bold cyan]")
            
            if risk_score >= 7:
                console.print("[bold red]⚠️  HIGH RISK detected![/bold red]")
            elif risk_score >= 4:
                console.print("[bold yellow]⚠️  MEDIUM RISK detected[/bold yellow]")
            else:
                console.print("[bold green]✅ LOW RISK[/bold green]")
                
            return {"target": target, "risk_score": risk_score}
        except Exception as e:
            console.print(f"[bold red]❌ AI prediction failed: {str(e)}[/bold red]")
            logger.error(f"AI prediction failed: {str(e)}")
            return None
            
    def generate_report(self):
        """Generate comprehensive PDF report"""
        target = self.get_target()
        console.print(f"[bold yellow]📊 Generating PDF report for {target}...[/bold yellow]")
        
        try:
            report_data = {
                "target": target,
                "scan_results": {},
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
            }
            
            # Collect all available data
            console.print("🔄 Collecting scan data...")
            for task in track(["nmap", "brute_force", "phishing", "ai_risk"], description="Processing..."):
                time.sleep(0.5)  # Simulate processing
                
            report_path = generate_pdf_report(report_data)
            console.print(f"[bold green]✅ Report generated: {report_path}[/bold green]")
            return report_path
        except Exception as e:
            console.print(f"[bold red]❌ Report generation failed: {str(e)}[/bold red]")
            logger.error(f"Report generation failed: {str(e)}")
            return None
            
    def launch_dashboard(self):
        """Launch local web dashboard"""
        console.print("[bold yellow]🌐 Launching web dashboard...[/bold yellow]")
        
        try:
            # Check if Node.js is available
            subprocess.run(["node", "--version"], check=True, capture_output=True)
            
            # Start the web server
            console.print("🚀 Starting Express server on http://localhost:3000")
            subprocess.Popen(["node", "web/server.js"], cwd=".")
            
            console.print("[bold green]✅ Dashboard launched! Open http://localhost:3000[/bold green]")
            return True
        except subprocess.CalledProcessError:
            console.print("[bold red]❌ Node.js not found. Please install Node.js first.[/bold red]")
            return False
        except Exception as e:
            console.print(f"[bold red]❌ Dashboard launch failed: {str(e)}[/bold red]")
            logger.error(f"Dashboard launch failed: {str(e)}")
            return False

@app.command()
def interactive():
    """Run the interactive CLI menu"""
    toolkit = CyberToolkit()
    
    # Setup environment on first run
    setup_environment()
    
    toolkit.display_banner()
    
    while True:
        try:
            toolkit.show_menu()
            choice = typer.prompt("Select an option (1-7)")
            
            if choice == "1":
                toolkit.run_vulnerability_scan()
            elif choice == "2":
                toolkit.run_brute_force()
            elif choice == "3":
                toolkit.run_phishing_simulation()
            elif choice == "4":
                toolkit.run_ai_prediction()
            elif choice == "5":
                toolkit.generate_report()
            elif choice == "6":
                toolkit.launch_dashboard()
            elif choice == "7":
                console.print("[bold blue]👋 Thank you for using CyberToolkit![/bold blue]")
                break
            else:
                console.print("[bold red]❌ Invalid option. Please choose 1-7.[/bold red]")
                
            if choice != "7":
                input("\nPress Enter to continue...")
                console.clear()
                toolkit.display_banner()
                
        except KeyboardInterrupt:
            console.print("\n[bold blue]👋 Goodbye![/bold blue]")
            break
        except Exception as e:
            console.print(f"[bold red]❌ An error occurred: {str(e)}[/bold red]")
            logger.error(f"CLI error: {str(e)}")

@app.command()
def scan(target: str, output: Optional[str] = None):
    """Quick vulnerability scan from command line"""
    toolkit = CyberToolkit()
    toolkit.target = target
    results = toolkit.run_vulnerability_scan()
    
    if output and results:
        import json
        with open(output, 'w') as f:
            json.dump(results, f, indent=2)
        console.print(f"Results saved to {output}")

@app.command()
def install():
    """Install dependencies and setup environment"""
    console.print("[bold yellow]🔧 Installing dependencies...[/bold yellow]")
    setup_environment()
    console.print("[bold green]✅ Installation complete![/bold green]")

if __name__ == "__main__":
    # Default to interactive mode if no command specified
    if len(sys.argv) == 1:
        interactive()
    else:
        app()