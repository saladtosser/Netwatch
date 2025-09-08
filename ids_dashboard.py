import asyncio
import json
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime, timedelta
from collections import Counter, defaultdict
import re
import os
import time
import hashlib
import ipaddress
import threading
from typing import Dict, List, Optional, Tuple

from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from pyfiglet import Figlet
from scapy.all import AsyncSniffer, IP, TCP, UDP, sniff

# ============================
# Console & Banner Setup
# ============================
console = Console()

RULES_DIR = "rules/professional"
MAX_HISTORY = 100

# ============================
# Logging Setup
# ============================
logger = logging.getLogger("NetWatchLogger")
logger.setLevel(logging.DEBUG)
handler = RotatingFileHandler("alerts.log", maxBytes=10*1024*1024, backupCount=3)
formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)

# ============================
# Banner Function
# ============================
def banner():
    f = Figlet(font="slant")
    art = f.renderText("NETWATCH v2")
    console.print(Panel.fit(
        art + "\n[bold red]NetSec Operator Console[/bold red]\n",
        border_style="red", style="bold white"
    ))

# ============================
# Rule Parsing & Loading
# ============================
def load_rules():
    rules = []
    if not os.path.exists(RULES_DIR):
        console.log(f"[yellow]Professional rules directory not found: {RULES_DIR}[/yellow]")
        return rules
    
    for fname in os.listdir(RULES_DIR):
        if fname.endswith(".rules"):
            try:
                with open(os.path.join(RULES_DIR, fname), "r") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        try:
                            rule = parse_rule(line)
                            if rule:
                                rules.append(rule)
                        except Exception as e:
                            # Skip malformed rules silently for professional rulesets
                            pass
                console.log(f"[green]Loaded professional rules from {fname}[/green]")
            except Exception as e:
                console.log(f"[red]Error loading {fname}: {e}[/red]")
    
    console.log(f"[green]Total professional rules loaded: {len(rules)}[/green]")
    return rules

# Simplified Snort/Suricata style parser
def parse_rule(line):
    if not line.startswith("alert"):
        return None
    try:
        header, options = line.split("(", 1)
        options = options.strip(")")
        parts = header.split()
        action, proto, src, sport, direction, dst, dport = parts[:7]
        opt_dict = {}
        for opt in options.split(";"):
            opt = opt.strip()
            if not opt:
                continue
            if ":" in opt:
                k, v = opt.split(":", 1)
                opt_dict[k.strip()] = v.strip().strip('"')
        return {
            "action": action,
            "proto": proto,
            "src": src,
            "sport": sport,
            "dst": dst,
            "dport": dport,
            "options": opt_dict
        }
    except Exception as e:
        console.log(f"[red]Error parsing rule:[/red] {line} ({e})")
        return None

# ============================
# Advanced Threat Intelligence
# ============================
THREAT_INTEL = {
    "malicious_ips": set(),
    "malicious_domains": set(),
    "malicious_hashes": set(),
    "cve_database": {},
    "reputation_cache": {}
}

# Behavioral Analysis
BEHAVIORAL_BASELINE = {
    "normal_ports": defaultdict(int),
    "normal_protocols": defaultdict(int),
    "normal_traffic_volume": 0,
    "normal_connection_patterns": defaultdict(list)
}

# ============================
# Event / Alert Handling
# ============================
ALERT_HISTORY = {}
THREAT_SCORE = defaultdict(int)

def load_threat_intelligence():
    """Load threat intelligence feeds"""
    # Load malicious IPs
    malicious_ips_file = "threat_intel/malicious_ips.txt"
    if os.path.exists(malicious_ips_file):
        with open(malicious_ips_file, 'r') as f:
            THREAT_INTEL["malicious_ips"] = set(line.strip() for line in f)
    
    # Load malicious domains
    malicious_domains_file = "threat_intel/malicious_domains.txt"
    if os.path.exists(malicious_domains_file):
        with open(malicious_domains_file, 'r') as f:
            THREAT_INTEL["malicious_domains"] = set(line.strip() for line in f)
    
    console.log(f"[green]Loaded {len(THREAT_INTEL['malicious_ips'])} malicious IPs and {len(THREAT_INTEL['malicious_domains'])} malicious domains[/green]")

def check_threat_intelligence(ip, domain=None):
    """Check if IP/domain is in threat intelligence"""
    threat_score = 0
    if ip in THREAT_INTEL["malicious_ips"]:
        threat_score += 100
    if domain and domain in THREAT_INTEL["malicious_domains"]:
        threat_score += 100
    return threat_score

def update_behavioral_baseline(pkt):
    """Update behavioral baseline for anomaly detection"""
    if not IP in pkt:
        return
    
    ip = pkt[IP]
    src_ip = ip.src
    dst_ip = ip.dst
    
    # Update port usage patterns
    if hasattr(pkt, 'sport'):
        BEHAVIORAL_BASELINE["normal_ports"][pkt.sport] += 1
    if hasattr(pkt, 'dport'):
        BEHAVIORAL_BASELINE["normal_ports"][pkt.dport] += 1
    
    # Update protocol patterns
    if pkt.haslayer(TCP):
        BEHAVIORAL_BASELINE["normal_protocols"]["TCP"] += 1
    elif pkt.haslayer(UDP):
        BEHAVIORAL_BASELINE["normal_protocols"]["UDP"] += 1
    
    # Update traffic volume
    BEHAVIORAL_BASELINE["normal_traffic_volume"] += len(pkt)

def detect_anomalies(pkt):
    """Detect behavioral anomalies"""
    anomalies = []
    if not IP in pkt:
        return anomalies
    
    ip = pkt[IP]
    
    # Check for unusual port usage
    if hasattr(pkt, 'dport'):
        port = pkt.dport
        if port not in BEHAVIORAL_BASELINE["normal_ports"] or BEHAVIORAL_BASELINE["normal_ports"][port] < 5:
            anomalies.append({
                "type": "unusual_port",
                "severity": "medium",
                "description": f"Unusual port {port} usage detected"
            })
    
    # Check for large data transfers
    if len(pkt) > 1000000:  # 1MB
        anomalies.append({
            "type": "large_transfer",
            "severity": "high",
            "description": f"Large data transfer detected: {len(pkt)} bytes"
        })
    
    return anomalies

def correlate_alert(alert):
    """Enhanced alert correlation with threat scoring"""
    sid = alert.get("sid", "0")
    src_ip = alert.get("src", "")
    dst_ip = alert.get("dst", "")
    
    now = time.time()
    ALERT_HISTORY.setdefault(sid, []).append(now)
    window = [t for t in ALERT_HISTORY[sid] if now - t < 60]
    ALERT_HISTORY[sid] = window
    
    # Calculate threat score
    threat_score = check_threat_intelligence(src_ip) + check_threat_intelligence(dst_ip)
    THREAT_SCORE[src_ip] += threat_score
    THREAT_SCORE[dst_ip] += threat_score
    
    # Escalation logic
    if len(window) >= 5:
        alert["escalated"] = True
        alert["msg"] = f"[ESCALATED] {alert['msg']}"
        alert["threat_score"] = threat_score + 50
    else:
        alert["escalated"] = False
        alert["threat_score"] = threat_score
    
    # Add behavioral analysis
    alert["behavioral_anomalies"] = []
    
    return alert

# ============================
# Packet Matching
# ============================
def match_packet(pkt, rules):
    """Enhanced packet matching with behavioral analysis"""
    if not IP in pkt:
        return []
    
    alerts = []
    ip = pkt[IP]
    sport = pkt.sport if hasattr(pkt, "sport") else None
    dport = pkt.dport if hasattr(pkt, "dport") else None
    
    # Update behavioral baseline
    update_behavioral_baseline(pkt)
    
    # Check for behavioral anomalies
    anomalies = detect_anomalies(pkt)
    
    # Process rules
    for rule in rules:
        if rule["proto"].lower() == "tcp" and not pkt.haslayer(TCP):
            continue
        if rule["proto"].lower() == "udp" and not pkt.haslayer(UDP):
            continue
        
        opts = rule["options"]
        match = True
        
        # Content matching
        if "content" in opts:
            raw = bytes(pkt).decode(errors="ignore")
            if opts["content"] not in raw:
                match = False
        
        # Size matching
        if "dsize" in opts:
            dsize_rule = opts["dsize"]
            if dsize_rule.startswith(">"):
                size_limit = int(dsize_rule[1:])
                if len(pkt) <= size_limit:
                    match = False
            elif dsize_rule.startswith("<"):
                size_limit = int(dsize_rule[1:])
                if len(pkt) >= size_limit:
                    match = False
        
        if match:
            alert = {
                "msg": opts.get("msg", "Suspicious traffic detected"),
                "sid": opts.get("sid", "0"),
                "src": ip.src,
                "dst": ip.dst,
                "sport": sport,
                "dport": dport,
                "proto": rule["proto"],
                "timestamp": time.time(),
                "packet_size": len(pkt),
                "rule_class": opts.get("classtype", "unknown"),
                "behavioral_anomalies": anomalies
            }
            alerts.append(alert)
    
    return alerts

# ============================
# IDS Packet Handler
# ============================
def handle_packet(pkt, rules):
    """Enhanced packet handler with advanced analytics"""
    alerts = match_packet(pkt, rules)
    for alert in alerts:
        alert = correlate_alert(alert)
        
        # Enhanced alert display
        severity_color = "red" if alert.get("threat_score", 0) > 100 else "yellow" if alert.get("threat_score", 0) > 50 else "green"
        escalated_text = " [ESCALATED]" if alert.get("escalated", False) else ""
        
        console.print(f"[bold {severity_color}][!] ALERT{escalated_text}:[/bold {severity_color}] {alert['msg']}")
        console.print(f"    [cyan]SID:[/cyan] {alert['sid']} | [cyan]Threat Score:[/cyan] {alert.get('threat_score', 0)}")
        console.print(f"    [cyan]Traffic:[/cyan] {alert['src']}:{alert['sport']} -> {alert['dst']}:{alert['dport']} ({alert['proto']})")
        console.print(f"    [cyan]Size:[/cyan] {alert.get('packet_size', 0)} bytes | [cyan]Class:[/cyan] {alert.get('rule_class', 'unknown')}")
        
        if alert.get('behavioral_anomalies'):
            console.print(f"    [yellow]Behavioral Anomalies:[/yellow] {len(alert['behavioral_anomalies'])} detected")
        
        logger.info(json.dumps(alert))

# ============================
# Live Async IDS
# ============================
async def async_ids(rules):
    loop = asyncio.get_event_loop()
    queue = asyncio.Queue()

    def scapy_callback(pkt):
        loop.call_soon_threadsafe(queue.put_nowait, pkt)

    sniffer = AsyncSniffer(prn=scapy_callback, store=0)
    sniffer.start()

    try:
        while True:
            pkt = await queue.get()
            handle_packet(pkt, rules)
    except asyncio.CancelledError:
        sniffer.stop()
        console.log("[red]IDS Stopped.[/red]")

# ============================
# Real-time Dashboard
# ============================
def create_dashboard():
    """Create real-time security dashboard"""
    layout = Layout()
    layout.split_column(
        Layout(Panel.fit("[bold red]NetWatch v2 - Enterprise Security Console[/bold red]", border_style="red"), size=3),
        Layout(name="main"),
        Layout(Panel.fit("[dim]Press Ctrl+C to return to menu[/dim]", border_style="dim"), size=1)
    )
    
    layout["main"].split_row(
        Layout(name="alerts"),
        Layout(name="stats")
    )
    
    return layout

async def update_dashboard(layout, rules):
    """Update dashboard with real-time data"""
    with Live(layout, refresh_per_second=2) as live:
        while True:
            # Alerts panel
            alerts_table = Table(title="Recent Alerts", show_header=True, header_style="bold magenta")
            alerts_table.add_column("Time", style="dim", width=8)
            alerts_table.add_column("Severity", style="bold", width=10)
            alerts_table.add_column("Alert", width=50)
            alerts_table.add_column("Source", style="cyan", width=15)
            alerts_table.add_column("Threat Score", style="red", width=12)
            
            # Add recent alerts (last 10)
            recent_alerts = list(ALERT_HISTORY.items())[-10:]
            for sid, timestamps in recent_alerts:
                if timestamps:
                    latest_time = datetime.fromtimestamp(timestamps[-1]).strftime("%H:%M:%S")
                    alerts_table.add_row(latest_time, "HIGH", f"SID: {sid}", "Unknown", "100")
            
            layout["alerts"].update(Panel(alerts_table, title="[bold blue]Active Alerts[/bold blue]", border_style="blue"))
            
            # Stats panel
            stats_table = Table(title="System Statistics", show_header=True, header_style="bold green")
            stats_table.add_column("Metric", style="bold", width=20)
            stats_table.add_column("Value", style="cyan", width=15)
            
            stats_table.add_row("Rules Loaded", str(len(rules)))
            stats_table.add_row("Active Alerts", str(len(ALERT_HISTORY)))
            stats_table.add_row("Threat IPs", str(len(THREAT_INTEL["malicious_ips"])))
            stats_table.add_row("Threat Domains", str(len(THREAT_INTEL["malicious_domains"])))
            stats_table.add_row("Packets Analyzed", str(BEHAVIORAL_BASELINE["normal_traffic_volume"]))
            
            layout["stats"].update(Panel(stats_table, title="[bold green]System Stats[/bold green]", border_style="green"))
            
            await asyncio.sleep(1)

# ============================
# Main Menu / Console Loop
# ============================
async def main():
    banner()
    rules = load_rules()
    load_threat_intelligence()

    while True:
        console.print("[bold cyan]netwatch> [/bold cyan]", end="")
        cmd = input().strip()
        if cmd.lower() in ["exit", "quit"]:
            break
        elif cmd.lower() in ["ids", "start ids"]:
            console.log("[green]Starting live IDS... Press Ctrl+C to exit IDS.[/green]")
            try:
                await async_ids(rules)
            except KeyboardInterrupt:
                console.log("[yellow]Returning to main console...[/yellow]")
        elif cmd.lower() == "dashboard":
            console.log("[green]Starting real-time dashboard... Press Ctrl+C to exit.[/green]")
            try:
                layout = create_dashboard()
                await update_dashboard(layout, rules)
            except KeyboardInterrupt:
                console.log("[yellow]Returning to main console...[/yellow]")
        elif cmd.lower() == "stats":
            console.print(f"[green]Rules loaded:[/green] {len(rules)}")
            console.print(f"[green]Threat IPs:[/green] {len(THREAT_INTEL['malicious_ips'])}")
            console.print(f"[green]Threat Domains:[/green] {len(THREAT_INTEL['malicious_domains'])}")
            console.print(f"[green]Active alerts:[/green] {len(ALERT_HISTORY)}")
        elif cmd.lower() == "help":
            console.print("Commands: ids, dashboard, stats, help, exit")
        else:
            console.print(f"Unknown command: {cmd}")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        console.log("[red]NetWatch console exiting...[/red]")
