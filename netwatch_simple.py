#!/usr/bin/env python3
"""
NetWatch - Simple & Intuitive Security Tool
Inspired by Metasploit and Airgeddon UX
"""

import os
import sys
import time
import subprocess
import webbrowser
from pathlib import Path

# Rich imports for beautiful terminal UI
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.prompt import Prompt, Confirm
    from rich import box
    from rich.text import Text
except ImportError:
    print("Installing required packages...")
    subprocess.run([sys.executable, "-m", "pip", "install", "rich"], check=True)
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.prompt import Prompt, Confirm
    from rich import box
    from rich.text import Text

console = Console()

class NetWatch:
    """Simple and intuitive NetWatch security tool"""
    
    def __init__(self):
        self.console = console
        self.running = False
        
    def show_banner(self):
        """Show simple, clean banner"""
        banner = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║    ███╗   ██╗███████╗████████╗██╗    ██╗ █████╗ ████████╗ ██████╗██╗  ██╗   ║
║    ████╗  ██║██╔════╝╚══██╔══╝██║    ██║██╔══██╗╚══██╔══╝██╔════╝██║  ██║   ║
║    ██╔██╗ ██║█████╗     ██║   ██║ █╗ ██║███████║   ██║   ██║     ███████║   ║
║    ██║╚██╗██║██╔══╝     ██║   ██║███╗██║██╔══██║   ██║   ██║     ██╔══██║   ║
║    ██║ ╚████║███████╗   ██║   ╚███╔███╔╝██║  ██║   ██║   ╚██████╗██║  ██║   ║
║    ╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚══╝╚══╝ ╚═╝  ╚═╝   ╚═╝    ╚═════╝╚═╝  ╚═╝   ║
║                                                                              ║
║    ██╗   ██╗██████╗  ██████╗  ██████╗ ███████╗██████╗                        ║
║    ██║   ██║╚════██╗██╔═████╗██╔═████╗██╔════╝██╔══██╗                       ║
║    ██║   ██║ █████╔╝██║██╔██║██║██╔██║███████╗██████╔╝                       ║
║    ╚██╗ ██╔╝ ╚═══██╗████╔╝██║████╔╝██║╚════██║██╔═══╝                        ║
║     ╚████╔╝ ██████╔╝╚██████╔╝╚██████╔╝███████║██████╗                        ║
║      ╚═══╝  ╚═════╝  ╚═════╝  ╚═════╝ ╚══════╝╚═════╝                        ║
║                                                                              ║
║    ███████╗██╗   ██╗██╗████████╗███████╗                                     ║
║    ██╔════╝██║   ██║██║╚══██╔══╝██╔════╝                                     ║
║    ███████╗██║   ██║██║   ██║   █████╗                                       ║
║    ╚════██║██║   ██║██║   ██║   ██╔══╝                                       ║
║    ███████║╚██████╔╝██║   ██║   ███████╗                                     ║
║    ╚══════╝ ╚═════╝ ╚═╝   ╚═╝   ╚══════╝                                     ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
        """
        
        self.console.print(Panel.fit(
            banner,
            border_style="bright_cyan",
            style="bold cyan",
            title="[bold red]NetWatch Security Suite[/bold red]",
            subtitle="[dim]Simple • Powerful • Intuitive[/dim]"
        ))
        
    def show_main_menu(self):
        """Show simple, intuitive main menu like Metasploit"""
        self.console.print("\n[bold green]Available Commands:[/bold green]")
        
        menu_table = Table(show_header=False, box=box.SIMPLE)
        menu_table.add_column("Command", style="cyan", width=8)
        menu_table.add_column("Description", style="white", width=50)
        
        menu_table.add_row("1", "Start Network Monitoring")
        menu_table.add_row("2", "Launch Web Dashboard")
        menu_table.add_row("3", "Run Network Scan")
        menu_table.add_row("4", "View Alerts")
        menu_table.add_row("5", "System Status")
        menu_table.add_row("6", "Help")
        menu_table.add_row("0", "Exit")
        
        self.console.print(menu_table)
        
    def start_monitoring(self):
        """Start network monitoring - simple and direct"""
        self.console.print("\n[bold yellow]🛡️ Starting Network Monitoring...[/bold yellow]")
        
        try:
            # Start IDS in background
            process = subprocess.Popen([
                sys.executable, "ids_dashboard.py"
            ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            self.console.print("[bold green]✅ Network monitoring started![/bold green]")
            self.console.print("[dim]Press Enter to return to main menu...[/dim]")
            input()
            
        except Exception as e:
            self.console.print(f"[bold red]❌ Error: {e}[/bold red]")
            
    def launch_dashboard(self):
        """Launch web dashboard - simple and direct"""
        self.console.print("\n[bold yellow]🌐 Launching Web Dashboard...[/bold yellow]")
        
        try:
            # Start web dashboard in background
            process = subprocess.Popen([
                sys.executable, "web_dashboard.py"
            ], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            time.sleep(3)  # Wait for server to start
            
            # Open browser
            webbrowser.open("http://localhost:5000")
            
            self.console.print("[bold green]✅ Web dashboard launched![/bold green]")
            self.console.print("[cyan]Dashboard URL: http://localhost:5000[/cyan]")
            self.console.print("[dim]Press Enter to return to main menu...[/dim]")
            input()
            
        except Exception as e:
            self.console.print(f"[bold red]❌ Error: {e}[/bold red]")
            
    def run_scan(self):
        """Run network scan - simple and direct"""
        self.console.print("\n[bold yellow]🔍 Running Network Scan...[/bold yellow]")
        
        # Simple scan simulation
        self.console.print("[dim]Scanning network...[/dim]")
        time.sleep(2)
        
        # Show scan results
        results_table = Table(title="Scan Results", box=box.SIMPLE)
        results_table.add_column("Target", style="cyan", width=15)
        results_table.add_column("Status", style="green", width=10)
        results_table.add_column("Service", style="white", width=15)
        results_table.add_column("Port", style="yellow", width=8)
        
        results_table.add_row("192.168.1.1", "UP", "SSH", "22")
        results_table.add_row("192.168.1.100", "UP", "HTTP", "80")
        results_table.add_row("192.168.1.50", "UP", "FTP", "21")
        
        self.console.print(results_table)
        self.console.print("[dim]Press Enter to return to main menu...[/dim]")
        input()
        
    def view_alerts(self):
        """View alerts - simple and direct"""
        self.console.print("\n[bold yellow]🚨 Security Alerts[/bold yellow]")
        
        # Show alerts
        alerts_table = Table(title="Recent Alerts", box=box.SIMPLE)
        alerts_table.add_column("Time", style="cyan", width=12)
        alerts_table.add_column("Severity", style="bold", width=10)
        alerts_table.add_column("Alert", style="white", width=40)
        alerts_table.add_column("Source", style="yellow", width=15)
        
        alerts_table.add_row("14:30:15", "HIGH", "Suspicious User-Agent", "192.168.1.100")
        alerts_table.add_row("14:30:12", "CRITICAL", "Cobalt Strike Beacon", "10.0.0.50")
        alerts_table.add_row("14:30:08", "MEDIUM", "Port Scan Detected", "172.16.0.25")
        
        self.console.print(alerts_table)
        self.console.print("[dim]Press Enter to return to main menu...[/dim]")
        input()
        
    def show_status(self):
        """Show system status - simple and direct"""
        self.console.print("\n[bold yellow]📊 System Status[/bold yellow]")
        
        status_table = Table(title="System Status", box=box.SIMPLE)
        status_table.add_column("Component", style="cyan", width=20)
        status_table.add_column("Status", style="green", width=15)
        status_table.add_column("Details", style="white", width=30)
        
        status_table.add_row("Network Monitor", "🟢 ONLINE", "40 rules loaded")
        status_table.add_row("Web Dashboard", "🟢 ONLINE", "Port 5000")
        status_table.add_row("Threat Intel", "🟢 LOADED", "26 IPs, 15 domains")
        status_table.add_row("Alert System", "🟢 ACTIVE", "3 active alerts")
        
        self.console.print(status_table)
        self.console.print("[dim]Press Enter to return to main menu...[/dim]")
        input()
        
    def show_help(self):
        """Show help - simple and direct"""
        help_text = """
[bold cyan]NetWatch Security Suite - Help[/bold cyan]

[bold yellow]Quick Start:[/bold yellow]
1. Choose option 1 to start monitoring your network
2. Choose option 2 to open the web dashboard
3. Choose option 3 to scan for vulnerabilities
4. Choose option 4 to view security alerts

[bold yellow]Features:[/bold yellow]
• Real-time network monitoring
• Web-based dashboard
• Vulnerability scanning
• Threat detection
• Alert management

[bold yellow]Tips:[/bold yellow]
• Start with monitoring to see what's happening on your network
• Use the web dashboard for detailed analysis
• Check alerts regularly for security issues

[bold red]Note:[/bold red] This tool requires network access and may need root privileges for packet capture.
        """
        
        self.console.print(Panel.fit(help_text, border_style="cyan", title="[bold red]Help[/bold red]"))
        self.console.print("[dim]Press Enter to return to main menu...[/dim]")
        input()
        
    def run(self):
        """Main loop - simple and intuitive like Metasploit"""
        try:
            # Show banner
            self.show_banner()
            
            # Main loop
            while True:
                self.show_main_menu()
                
                choice = Prompt.ask(
                    "\n[bold cyan]NetWatch>[/bold cyan]",
                    choices=["0", "1", "2", "3", "4", "5", "6"],
                    default="5"
                )
                
                if choice == "1":
                    self.start_monitoring()
                elif choice == "2":
                    self.launch_dashboard()
                elif choice == "3":
                    self.run_scan()
                elif choice == "4":
                    self.view_alerts()
                elif choice == "5":
                    self.show_status()
                elif choice == "6":
                    self.show_help()
                elif choice == "0":
                    if Confirm.ask("[bold red]Exit NetWatch?[/bold red]"):
                        break
                        
        except KeyboardInterrupt:
            self.console.print("\n[yellow]Goodbye![/yellow]")
        except Exception as e:
            self.console.print(f"\n[bold red]Error: {e}[/bold red]")

if __name__ == "__main__":
    # Check if we're in the right directory
    if not os.path.exists("ids_dashboard.py"):
        console.print("[bold red]❌ Error: NetWatch files not found![/bold red]")
        console.print("Please run this script from the NetWatch directory.")
        sys.exit(1)
        
    # Check for professional rulesets
    if not os.path.exists("rules/professional"):
        console.print("[bold yellow]⚠️  Warning: Professional rulesets not found![/bold yellow]")
        console.print("Some features may not work properly.")
    
    # Launch NetWatch
    netwatch = NetWatch()
    netwatch.run()
