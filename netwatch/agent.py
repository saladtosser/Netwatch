#!/usr/bin/env python3
"""
NetWatch Agent - Core orchestrator for SIEM/IDS/IPS functionality
"""

import asyncio
import signal
import sys
import logging
import logging.handlers
from pathlib import Path
from typing import Dict, List, Optional, Any
import yaml
from datetime import datetime
import os

from .collectors.base import BaseCollector
from .parser.normalizer import EventNormalizer
from .rules.engine import RuleEngine
from .correlation.correlator import CorrelationEngine
from .response.playbooks import ResponseEngine
from .storage.db import StorageManager
from .api.server import APIServer


class NetWatchAgent:
    """
    Core NetWatch Agent - Orchestrates all security monitoring components
    """
    
    def __init__(self, config_path: str = "/etc/netwatch/config.yaml"):
        self.config_path = Path(config_path)
        self.config = self._load_config()
        self.logger = self._setup_logging()
        
        # Core components
        self.event_queue = asyncio.Queue(maxsize=10000)
        self.alert_queue = asyncio.Queue(maxsize=1000)
        
        # Initialize subsystems
        self.collectors: Dict[str, BaseCollector] = {}
        self.normalizer = EventNormalizer()
        self.rule_engine = RuleEngine(self.config.get('rules', {}))
        self.correlation_engine = CorrelationEngine()
        self.response_engine = ResponseEngine(self.config.get('response', {}))
        self.storage = StorageManager(self.config.get('storage', {}))
        self.api_server = APIServer(self)
        
        # Runtime state
        self.running = False
        self.tasks: List[asyncio.Task] = []
        
        self.logger.info(f"NetWatch Agent v3.0.0 initialized")
    
    def _load_config(self) -> Dict[str, Any]:
        """Load YAML configuration"""
        default_config = {
            'agent': {
                'name': 'netwatch-01',
                'environment': 'production',
                'dry_run': False
            },
            'logging': {
                'level': 'INFO',
                'file': '/var/log/netwatch/agent.log',
                'max_bytes': 10485760,  # 10MB
                'backup_count': 5
            },
            'collectors': {
                'filetail': {
                    'enabled': True,
                    'files': ['/var/log/auth.log', '/var/log/syslog']
                },
                'syslog': {
                    'enabled': True,
                    'host': '0.0.0.0',
                    'port': 514
                },
                'suricata': {
                    'enabled': False,
                    'eve_path': '/var/log/suricata/eve.json'
                },
                'netflow': {
                    'enabled': False,
                    'port': 2055
                },
                'scapy': {
                    'enabled': True,
                    'interface': 'any'
                }
            },
            'rules': {
                'path': '/etc/netwatch/rules/',
                'reload_interval': 300  # 5 minutes
            },
            'storage': {
                'type': 'sqlite',
                'path': '/var/lib/netwatch/netwatch.db'
            },
            'api': {
                'enabled': True,
                'host': '127.0.0.1',
                'port': 8080
            },
            'response': {
                'enabled': True,
                'dry_run': False,
                'playbooks_path': '/etc/netwatch/playbooks/'
            }
        }
        
        if self.config_path.exists():
            try:
                with open(self.config_path, 'r') as f:
                    user_config = yaml.safe_load(f)
                    # Deep merge with defaults
                    return self._deep_merge(default_config, user_config)
            except Exception as e:
                print(f"Error loading config: {e}, using defaults")
                return default_config
        else:
            # Create default config
            self.config_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.config_path, 'w') as f:
                yaml.dump(default_config, f, default_flow_style=False)
            return default_config
    
    def _deep_merge(self, base: Dict, override: Dict) -> Dict:
        """Deep merge configuration dictionaries"""
        result = base.copy()
        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._deep_merge(result[key], value)
            else:
                result[key] = value
        return result
    
    def _setup_logging(self) -> logging.Logger:
        """Setup secure logging with rotation"""
        logger = logging.getLogger('netwatch')
        logger.setLevel(getattr(logging, self.config['logging']['level']))
        
        # Create log directory
        log_path = Path(self.config['logging']['file'])
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        # File handler with rotation
        file_handler = logging.handlers.RotatingFileHandler(
            log_path,
            maxBytes=self.config['logging']['max_bytes'],
            backupCount=self.config['logging']['backup_count']
        )
        file_handler.setFormatter(
            logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
        )
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(
            logging.Formatter('%(levelname)s: %(message)s')
        )
        
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)
        
        return logger
    
    def _initialize_collectors(self):
        """Initialize enabled collectors"""
        collector_config = self.config.get('collectors', {})
        
        # Dynamic import and initialization
        if collector_config.get('filetail', {}).get('enabled'):
            from .collectors.filetail import FileTailCollector
            self.collectors['filetail'] = FileTailCollector(
                collector_config['filetail'],
                self.event_queue
            )
            self.logger.info("FileTail collector initialized")
        
        if collector_config.get('syslog', {}).get('enabled'):
            from .collectors.syslog import SyslogCollector
            self.collectors['syslog'] = SyslogCollector(
                collector_config['syslog'],
                self.event_queue
            )
            self.logger.info("Syslog collector initialized")
        
        if collector_config.get('suricata', {}).get('enabled'):
            from .collectors.suricata import SuricataCollector
            self.collectors['suricata'] = SuricataCollector(
                collector_config['suricata'],
                self.event_queue
            )
            self.logger.info("Suricata collector initialized")
        
        if collector_config.get('netflow', {}).get('enabled'):
            from .collectors.netflow import NetFlowCollector
            self.collectors['netflow'] = NetFlowCollector(
                collector_config['netflow'],
                self.event_queue
            )
            self.logger.info("NetFlow collector initialized")
        
        if collector_config.get('scapy', {}).get('enabled'):
            from .collectors.scapy_collector import ScapyCollector
            self.collectors['scapy'] = ScapyCollector(
                collector_config['scapy'],
                self.event_queue
            )
            self.logger.info("Scapy collector initialized")
    
    async def _process_events(self):
        """Main event processing pipeline"""
        while self.running:
            try:
                # Get raw event from queue
                raw_event = await asyncio.wait_for(
                    self.event_queue.get(),
                    timeout=1.0
                )
                
                # Normalize event
                normalized = await self.normalizer.normalize(raw_event)
                if not normalized:
                    continue
                
                # Store normalized event
                await self.storage.store_event(normalized)
                
                # Evaluate rules
                rule_matches = await self.rule_engine.evaluate(normalized)
                
                # Check correlations
                correlation_alerts = await self.correlation_engine.correlate(
                    normalized, 
                    rule_matches
                )
                
                # Generate alerts
                for alert in correlation_alerts:
                    await self.alert_queue.put(alert)
                    self.logger.info(f"Alert generated: {alert['title']} [{alert['severity']}]")
                
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                self.logger.error(f"Error processing event: {e}")
    
    async def _process_alerts(self):
        """Process and respond to alerts"""
        while self.running:
            try:
                alert = await asyncio.wait_for(
                    self.alert_queue.get(),
                    timeout=1.0
                )
                
                # Store alert
                await self.storage.store_alert(alert)
                
                # Execute response playbooks
                if self.config['response']['enabled']:
                    await self.response_engine.execute(alert)
                
                # Log alert (JSON format for SIEM integration)
                self.logger.info(f"ALERT: {alert}")
                
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                self.logger.error(f"Error processing alert: {e}")
    
    async def _reload_rules(self):
        """Periodically reload rules"""
        while self.running:
            try:
                await asyncio.sleep(self.config['rules']['reload_interval'])
                self.logger.info("Reloading rules...")
                await self.rule_engine.reload_rules()
            except Exception as e:
                self.logger.error(f"Error reloading rules: {e}")
    
    async def start(self):
        """Start the NetWatch agent"""
        self.logger.info("Starting NetWatch Agent...")
        self.running = True
        
        # Initialize components
        self._initialize_collectors()
        await self.storage.initialize()
        await self.rule_engine.load_rules()
        
        # Start collectors
        for name, collector in self.collectors.items():
            self.tasks.append(
                asyncio.create_task(collector.start())
            )
            self.logger.info(f"Started {name} collector")
        
        # Start processing pipelines
        self.tasks.append(asyncio.create_task(self._process_events()))
        self.tasks.append(asyncio.create_task(self._process_alerts()))
        self.tasks.append(asyncio.create_task(self._reload_rules()))
        
        # Start API server
        if self.config['api']['enabled']:
            self.tasks.append(
                asyncio.create_task(self.api_server.start())
            )
        
        self.logger.info("NetWatch Agent started successfully")
        
        # Wait for shutdown signal
        try:
            await asyncio.gather(*self.tasks)
        except asyncio.CancelledError:
            pass
    
    async def stop(self):
        """Stop the NetWatch agent"""
        self.logger.info("Stopping NetWatch Agent...")
        self.running = False
        
        # Stop collectors
        for name, collector in self.collectors.items():
            await collector.stop()
            self.logger.info(f"Stopped {name} collector")
        
        # Cancel all tasks
        for task in self.tasks:
            task.cancel()
        
        # Wait for tasks to complete
        await asyncio.gather(*self.tasks, return_exceptions=True)
        
        # Cleanup
        await self.storage.close()
        
        self.logger.info("NetWatch Agent stopped")
    
    def run(self):
        """Main entry point - run as daemon"""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        # Setup signal handlers
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(
                sig,
                lambda: asyncio.create_task(self.stop())
            )
        
        try:
            loop.run_until_complete(self.start())
        except KeyboardInterrupt:
            pass
        finally:
            loop.run_until_complete(self.stop())
            loop.close()


def main():
    """CLI entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description='NetWatch SIEM/IDS/IPS Agent')
    parser.add_argument(
        '-c', '--config',
        default='/etc/netwatch/config.yaml',
        help='Configuration file path'
    )
    parser.add_argument(
        '-d', '--daemon',
        action='store_true',
        help='Run as daemon'
    )
    
    args = parser.parse_args()
    
    # Create agent and run
    agent = NetWatchAgent(args.config)
    
    if args.daemon:
        # Daemonize process
        import daemon
        with daemon.DaemonContext():
            agent.run()
    else:
        agent.run()


if __name__ == '__main__':
    main()

