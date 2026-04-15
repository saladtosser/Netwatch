#!/usr/bin/env python3
"""
NetWatch CLI - Command-line interface for NetWatch management
"""

import argparse
import asyncio
import json
import sys
import os
from typing import Dict, Any, List
from datetime import datetime, timedelta

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from response.playbooks import ResponseEngine
from storage.db import StorageManager, init_db
from storage.models import Alert, Event
from rules.engine import RuleEngine


class NetWatchCLI:
    """NetWatch command-line interface"""
    
    def __init__(self):
        self.response_engine = None
        self.storage = None
        self.rule_engine = None
    
    async def init_components(self, config_path: str = "/etc/netwatch/config.yaml"):
        """Initialize components"""
        try:
            import yaml
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
        except FileNotFoundError:
            print(f"Config file not found: {config_path}")
            print("Using default configuration")
            config = {
                'storage': {'type': 'sqlite', 'path': './netwatch.db'},
                'response': {'dry_run': True}
            }
        
        # Initialize components
        self.response_engine = ResponseEngine(config.get('response', {}))
        self.storage = StorageManager(config.get('storage', {}))
        await self.storage.initialize()
        
        self.rule_engine = RuleEngine(config.get('rules', {}))
        await self.rule_engine.load_rules()
    
    async def block_ip(self, ip: str, timeout: int = 3600, dry_run: bool = True):
        """Block an IP address"""
        print(f"{'[DRY RUN] ' if dry_run else ''}Blocking IP: {ip} for {timeout} seconds")
        
        playbook = {
            'name': 'block-ip',
            'steps': [{
                'action': 'block_ip',
                'args': {
                    'ip': ip,
                    'timeout': timeout
                }
            }]
        }
        
        context = {'src_ip': ip}
        
        try:
            await self.response_engine._execute_playbook(playbook, context)
            print("✅ IP blocked successfully")
        except Exception as e:
            print(f"❌ Error blocking IP: {e}")
    
    async def unblock_ip(self, ip: str, dry_run: bool = True):
        """Unblock an IP address"""
        print(f"{'[DRY RUN] ' if dry_run else ''}Unblocking IP: {ip}")
        
        playbook = {
            'name': 'unblock-ip',
            'steps': [{
                'action': 'unblock_ip',
                'args': {'ip': ip}
            }]
        }
        
        context = {'src_ip': ip}
        
        try:
            await self.response_engine._execute_playbook(playbook, context)
            print("✅ IP unblocked successfully")
        except Exception as e:
            print(f"❌ Error unblocking IP: {e}")
    
    async def list_alerts(self, limit: int = 20, severity: str = None):
        """List recent alerts"""
        alerts = await self.storage.get_recent_alerts(limit=limit, severity=severity)
        
        if not alerts:
            print("No alerts found")
            return
        
        print(f"\n📊 Recent Alerts (limit: {limit})")
        print("-" * 80)
        print(f"{'ID':<12} {'Time':<20} {'Severity':<8} {'Title':<30}")
        print("-" * 80)
        
        for alert in alerts:
            alert_id = alert['alert_id'][:12]
            timestamp = alert['ts'][:19].replace('T', ' ')
            severity = alert['severity']
            title = alert['title'][:30]
            
            print(f"{alert_id:<12} {timestamp:<20} {severity:<8} {title:<30}")
    
    async def show_alert(self, alert_id: str):
        """Show detailed alert information"""
        try:
            with self.storage.SessionLocal() as session:
                alert = session.query(Alert).filter(Alert.alert_id == alert_id).first()
                
                if not alert:
                    print(f"Alert not found: {alert_id}")
                    return
                
                print(f"\n🚨 Alert Details: {alert_id}")
                print("=" * 60)
                print(f"Title: {alert.title}")
                print(f"Severity: {alert.severity}")
                print(f"Score: {alert.score}")
                print(f"Timestamp: {alert.ts}")
                print(f"Rule: {alert.rule_name}")
                print(f"Acknowledged: {alert.acknowledged}")
                print(f"Resolved: {alert.resolved}")
                
                if alert.evidence:
                    print(f"\nEvidence ({len(alert.evidence)} events):")
                    for i, event in enumerate(alert.evidence[:5]):  # Show first 5
                        print(f"  {i+1}. {event.get('event_type', 'unknown')} - {event.get('src_ip', 'N/A')}")
                
                if alert.playbook:
                    print(f"\nPlaybook Actions: {alert.playbook}")
                
        except Exception as e:
            print(f"❌ Error retrieving alert: {e}")
    
    async def acknowledge_alert(self, alert_id: str, user: str = "cli-user"):
        """Acknowledge an alert"""
        success = await self.storage.acknowledge_alert(alert_id, user)
        if success:
            print(f"✅ Alert {alert_id} acknowledged")
        else:
            print(f"❌ Failed to acknowledge alert {alert_id}")
    
    async def resolve_alert(self, alert_id: str):
        """Resolve an alert"""
        success = await self.storage.resolve_alert(alert_id)
        if success:
            print(f"✅ Alert {alert_id} resolved")
        else:
            print(f"❌ Failed to resolve alert {alert_id}")
    
    async def test_rule(self, rule_file: str, event_file: str = None):
        """Test a rule against sample events"""
        print(f"Testing rule: {rule_file}")
        
        # Load rule
        try:
            import yaml
            with open(rule_file, 'r') as f:
                rule = yaml.safe_load(f)
        except Exception as e:
            print(f"❌ Error loading rule: {e}")
            return
        
        # Load test events
        if event_file:
            try:
                with open(event_file, 'r') as f:
                    events = json.load(f)
            except Exception as e:
                print(f"❌ Error loading events: {e}")
                return
        else:
            # Generate sample events
            events = self._generate_sample_events(rule)
        
        print(f"Testing against {len(events)} events...")
        
        # Test rule
        matches = []
        for event in events:
            try:
                match = await self.rule_engine._evaluate_rule(rule, event)
                if match:
                    matches.append(match)
            except Exception as e:
                print(f"❌ Error evaluating rule: {e}")
        
        print(f"✅ Rule test completed: {len(matches)} matches found")
        
        for i, match in enumerate(matches):
            print(f"\nMatch {i+1}:")
            print(f"  Title: {match['title']}")
            print(f"  Severity: {match['severity']}")
            print(f"  Score: {match['score']}")
    
    def _generate_sample_events(self, rule: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate sample events for rule testing"""
        events = []
        
        # Generate events based on rule type
        if rule.get('type') == 'simple':
            # Generate single event
            event = {
                'id': 'test-001',
                'ts': datetime.utcnow().isoformat(),
                'event_type': 'test_event',
                'src_ip': '192.168.1.100',
                'dst_ip': '10.0.0.1',
                'severity': 'medium',
                'message': 'Test event for rule validation'
            }
            events.append(event)
        
        elif rule.get('type') == 'correlation':
            # Generate multiple related events
            base_time = datetime.utcnow()
            
            # Generate auth failures
            for i in range(5):
                event = {
                    'id': f'test-auth-fail-{i}',
                    'ts': (base_time - timedelta(minutes=i)).isoformat(),
                    'event_type': 'auth_failed',
                    'src_ip': '192.168.1.100',
                    'user': 'testuser',
                    'severity': 'medium'
                }
                events.append(event)
            
            # Generate auth success
            event = {
                'id': 'test-auth-success',
                'ts': base_time.isoformat(),
                'event_type': 'auth_success',
                'src_ip': '192.168.1.100',
                'user': 'testuser',
                'severity': 'low'
            }
            events.append(event)
        
        return events
    
    async def inject_event(self, event_data: str):
        """Inject a test event into the system"""
        try:
            event = json.loads(event_data)
            
            # Add required fields
            event.setdefault('id', f"injected-{datetime.utcnow().timestamp()}")
            event.setdefault('ts', datetime.utcnow().isoformat())
            event.setdefault('_collector', 'cli')
            event.setdefault('_collected_at', datetime.utcnow().isoformat())
            event.setdefault('_event_id', f"cli-{datetime.utcnow().timestamp()}")
            
            # Store event
            success = await self.storage.store_event(event)
            if success:
                print("✅ Event injected successfully")
            else:
                print("❌ Failed to inject event")
                
        except json.JSONDecodeError as e:
            print(f"❌ Invalid JSON: {e}")
        except Exception as e:
            print(f"❌ Error injecting event: {e}")
    
    async def stats(self):
        """Show system statistics"""
        print("\n📊 NetWatch Statistics")
        print("=" * 40)
        
        # Storage stats
        storage_stats = self.storage.get_stats()
        print(f"Events Stored: {storage_stats['events_stored']}")
        print(f"Alerts Stored: {storage_stats['alerts_stored']}")
        print(f"Storage Errors: {storage_stats['errors']}")
        
        # Response engine stats
        response_stats = self.response_engine.get_stats()
        print(f"Playbooks Loaded: {response_stats['playbooks_loaded']}")
        print(f"Dry Run Mode: {response_stats['dry_run']}")
        
        # Rule engine stats
        rule_stats = self.rule_engine.stats
        print(f"Rules Loaded: {rule_stats['rules_loaded']}")
        print(f"Events Evaluated: {rule_stats['events_evaluated']}")
        print(f"Rule Matches: {rule_stats['matches']}")
        
        # Alert stats
        alert_stats = await self.storage.get_alert_stats(hours=24)
        print(f"\n24h Alert Summary:")
        print(f"  Total: {alert_stats.get('total_alerts', 0)}")
        print(f"  Critical: {alert_stats.get('severity_breakdown', {}).get('critical', 0)}")
        print(f"  High: {alert_stats.get('severity_breakdown', {}).get('high', 0)}")
        print(f"  Medium: {alert_stats.get('severity_breakdown', {}).get('medium', 0)}")
        print(f"  Low: {alert_stats.get('severity_breakdown', {}).get('low', 0)}")


async def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(description='NetWatch CLI')
    parser.add_argument('--config', default='/etc/netwatch/config.yaml',
                       help='Configuration file path')
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Block IP command
    block_parser = subparsers.add_parser('block-ip', help='Block an IP address')
    block_parser.add_argument('ip', help='IP address to block')
    block_parser.add_argument('--timeout', type=int, default=3600,
                             help='Block timeout in seconds')
    block_parser.add_argument('--force', action='store_true',
                             help='Execute without dry-run')
    
    # Unblock IP command
    unblock_parser = subparsers.add_parser('unblock-ip', help='Unblock an IP address')
    unblock_parser.add_argument('ip', help='IP address to unblock')
    unblock_parser.add_argument('--force', action='store_true',
                               help='Execute without dry-run')
    
    # List alerts command
    alerts_parser = subparsers.add_parser('alerts', help='List recent alerts')
    alerts_parser.add_argument('--limit', type=int, default=20,
                              help='Number of alerts to show')
    alerts_parser.add_argument('--severity', choices=['critical', 'high', 'medium', 'low'],
                              help='Filter by severity')
    
    # Show alert command
    show_parser = subparsers.add_parser('show-alert', help='Show alert details')
    show_parser.add_argument('alert_id', help='Alert ID to show')
    
    # Acknowledge alert command
    ack_parser = subparsers.add_parser('ack-alert', help='Acknowledge an alert')
    ack_parser.add_argument('alert_id', help='Alert ID to acknowledge')
    ack_parser.add_argument('--user', default='cli-user', help='User acknowledging')
    
    # Resolve alert command
    resolve_parser = subparsers.add_parser('resolve-alert', help='Resolve an alert')
    resolve_parser.add_argument('alert_id', help='Alert ID to resolve')
    
    # Test rule command
    test_parser = subparsers.add_parser('test-rule', help='Test a rule')
    test_parser.add_argument('rule_file', help='Rule file to test')
    test_parser.add_argument('--events', help='Events file (optional)')
    
    # Inject event command
    inject_parser = subparsers.add_parser('inject-event', help='Inject a test event')
    inject_parser.add_argument('event_json', help='Event JSON data')
    
    # Stats command
    subparsers.add_parser('stats', help='Show system statistics')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    # Initialize CLI
    cli = NetWatchCLI()
    await cli.init_components(args.config)
    
    # Execute command
    try:
        if args.command == 'block-ip':
            await cli.block_ip(args.ip, args.timeout, dry_run=not args.force)
        elif args.command == 'unblock-ip':
            await cli.unblock_ip(args.ip, dry_run=not args.force)
        elif args.command == 'alerts':
            await cli.list_alerts(args.limit, args.severity)
        elif args.command == 'show-alert':
            await cli.show_alert(args.alert_id)
        elif args.command == 'ack-alert':
            await cli.acknowledge_alert(args.alert_id, args.user)
        elif args.command == 'resolve-alert':
            await cli.resolve_alert(args.alert_id)
        elif args.command == 'test-rule':
            await cli.test_rule(args.rule_file, args.events)
        elif args.command == 'inject-event':
            await cli.inject_event(args.event_json)
        elif args.command == 'stats':
            await cli.stats()
    except KeyboardInterrupt:
        print("\n❌ Operation cancelled")
    except Exception as e:
        print(f"❌ Error: {e}")
    finally:
        if cli.storage:
            await cli.storage.close()


if __name__ == '__main__':
    asyncio.run(main())
