"""
End-to-end integration tests for NetWatch
"""

import pytest
import asyncio
import tempfile
import os
import json
from datetime import datetime, timedelta

# Add parent directory to path
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent import NetWatchAgent
from parser.normalizer import EventNormalizer
from rules.engine import RuleEngine
from response.playbooks import ResponseEngine
from storage.db import StorageManager


class TestNetWatchE2E:
    """End-to-end integration tests"""
    
    @pytest.fixture
    async def netwatch_agent(self):
        """Create NetWatch agent for testing"""
        # Create temporary config
        config = {
            'agent': {
                'name': 'test-agent',
                'environment': 'test',
                'dry_run': True
            },
            'logging': {
                'level': 'DEBUG',
                'file': '/tmp/test_netwatch.log'
            },
            'collectors': {
                'filetail': {'enabled': False},
                'syslog': {'enabled': False},
                'suricata': {'enabled': False},
                'netflow': {'enabled': False},
                'scapy': {'enabled': False}
            },
            'rules': {
                'path': '/tmp/test_rules',
                'reload_interval': 300
            },
            'storage': {
                'type': 'sqlite',
                'path': '/tmp/test_netwatch.db'
            },
            'api': {'enabled': False},
            'response': {
                'enabled': True,
                'dry_run': True,
                'playbooks_path': '/tmp/test_playbooks'
            }
        }
        
        # Create test directories
        os.makedirs('/tmp/test_rules', exist_ok=True)
        os.makedirs('/tmp/test_playbooks', exist_ok=True)
        
        # Create test rule
        ssh_rule = {
            'name': 'SSH Brute Force Test',
            'id': 'ssh-brute-test',
            'description': 'Test rule for SSH brute force',
            'enabled': True,
            'severity': 'high',
            'type': 'aggregation',
            'aggregation': {
                'field': 'src_ip',
                'threshold': 3,
                'timeframe': 60,
                'group_by': ['src_ip']
            },
            'detection': {
                'fields': {
                    'event_type': 'auth_failed'
                }
            },
            'tags': ['authentication', 'brute_force'],
            'response': {
                'playbook': ['block-src-ip']
            }
        }
        
        with open('/tmp/test_rules/ssh_brute_test.yaml', 'w') as f:
            import yaml
            yaml.dump(ssh_rule, f)
        
        # Create test playbook
        playbook = {
            'name': 'block-src-ip',
            'description': 'Block source IP',
            'steps': [{
                'action': 'block_ip',
                'args': {
                    'ip': '{src_ip}',
                    'timeout': 3600
                }
            }]
        }
        
        with open('/tmp/test_playbooks/block_src_ip.yaml', 'w') as f:
            yaml.dump(playbook, f)
        
        # Create agent
        agent = NetWatchAgent('/tmp/test_config.yaml')
        agent.config = config
        
        # Initialize components
        await agent.storage.initialize()
        await agent.rule_engine.load_rules()
        
        yield agent
        
        # Cleanup
        await agent.storage.close()
        for file in ['/tmp/test_netwatch.db', '/tmp/test_netwatch.log']:
            if os.path.exists(file):
                os.unlink(file)
    
    @pytest.mark.asyncio
    async def test_ssh_brute_force_detection(self, netwatch_agent):
        """Test SSH brute force detection end-to-end"""
        # Generate SSH brute force events
        base_time = datetime.utcnow()
        events = []
        
        for i in range(5):  # 5 failed attempts
            event = {
                'id': f'ssh-fail-{i}',
                'ts': (base_time - timedelta(seconds=i*10)).isoformat(),
                'src_ip': '192.168.1.100',
                'dst_ip': '10.0.0.1',
                'dst_port': 22,
                'proto': 'TCP',
                'event_type': 'auth_failed',
                'severity': 'medium',
                'message': f'Failed SSH login attempt {i+1}',
                'raw': f'Failed password for user from 192.168.1.100 port 12345 ssh2',
                '_collector': 'FileTailCollector',
                '_collected_at': datetime.utcnow().isoformat(),
                '_event_id': f'evt-{i}'
            }
            events.append(event)
        
        # Process events through the pipeline
        alerts_generated = []
        
        for event in events:
            # Normalize event
            normalized = await netwatch_agent.normalizer.normalize(event)
            assert normalized is not None
            
            # Store event
            await netwatch_agent.storage.store_event(normalized)
            
            # Evaluate rules
            rule_matches = await netwatch_agent.rule_engine.evaluate(normalized)
            
            # Check correlations
            correlation_alerts = await netwatch_agent.correlation_engine.correlate(
                normalized, 
                rule_matches
            )
            
            # Collect alerts
            alerts_generated.extend(correlation_alerts)
        
        # Should have generated at least one alert after 3+ failures
        assert len(alerts_generated) > 0
        
        # Verify alert content
        alert = alerts_generated[0]
        assert alert['title'] == 'SSH Brute Force Test'
        assert alert['severity'] == 'high'
        assert alert['score'] > 0
        assert len(alert['evidence']) >= 3
        
        # Verify alert was stored
        stored_alerts = await netwatch_agent.storage.get_recent_alerts(limit=10)
        assert len(stored_alerts) > 0
        
        # Verify response would be executed (dry run)
        if alert.get('playbook'):
            context = netwatch_agent.response_engine._build_context(alert)
            success = await netwatch_agent.response_engine.execute(alert)
            assert success is True
    
    @pytest.mark.asyncio
    async def test_data_exfiltration_detection(self, netwatch_agent):
        """Test data exfiltration detection"""
        # Create data exfiltration rule
        exfil_rule = {
            'name': 'Data Exfiltration Test',
            'id': 'data-exfil-test',
            'description': 'Test rule for data exfiltration',
            'enabled': True,
            'severity': 'critical',
            'type': 'simple',
            'detection': {
                'fields': {
                    'event_type': 'network_flow'
                },
                'condition': '$_meta.bytes > 10000000'  # > 10MB
            },
            'tags': ['exfiltration', 'data_loss'],
            'response': {
                'playbook': ['block-dst-ip', 'capture-packets']
            }
        }
        
        # Save rule
        with open('/tmp/test_rules/data_exfil_test.yaml', 'w') as f:
            import yaml
            yaml.dump(exfil_rule, f)
        
        # Reload rules
        await netwatch_agent.rule_engine.load_rules()
        
        # Generate large data transfer event
        event = {
            'id': 'exfil-001',
            'ts': datetime.utcnow().isoformat(),
            'src_ip': '192.168.1.50',
            'dst_ip': '8.8.8.8',  # External IP
            'src_port': 12345,
            'dst_port': 443,
            'proto': 'TCP',
            'event_type': 'network_flow',
            'severity': 'medium',
            'message': 'Large data transfer detected',
            'raw': 'Flow data',
            '_meta': {
                'bytes': 15000000,  # 15MB
                'packets': 1000,
                'collector': 'NetFlowCollector'
            },
            '_collector': 'NetFlowCollector',
            '_collected_at': datetime.utcnow().isoformat(),
            '_event_id': 'exfil-001'
        }
        
        # Process event
        normalized = await netwatch_agent.normalizer.normalize(event)
        assert normalized is not None
        
        # Store event
        await netwatch_agent.storage.store_event(normalized)
        
        # Evaluate rules
        rule_matches = await netwatch_agent.rule_engine.evaluate(normalized)
        
        # Should match the exfiltration rule
        assert len(rule_matches) > 0
        
        alert = rule_matches[0]
        assert alert['title'] == 'Data Exfiltration Test'
        assert alert['severity'] == 'critical'
    
    @pytest.mark.asyncio
    async def test_event_normalization_pipeline(self, netwatch_agent):
        """Test event normalization pipeline"""
        # Test different event types
        test_events = [
            {
                'source': 'syslog',
                'raw': 'Jan 1 12:00:00 host sshd[1234]: Failed password for user from 192.168.1.100 port 12345 ssh2',
                '_collector': 'SyslogCollector',
                '_collected_at': datetime.utcnow().isoformat(),
                '_event_id': 'syslog-001'
            },
            {
                'source': 'suricata',
                'event_type': 'suricata_alert',
                'signature': 'ET MALWARE Win32/Agent Connection',
                'src_ip': '192.168.1.200',
                'dst_ip': '10.0.0.1',
                'severity': 'high',
                'raw': '{"timestamp":"2024-01-01T12:00:00.000000+0000","flow_id":123,"event_type":"alert"}',
                '_collector': 'SuricataCollector',
                '_collected_at': datetime.utcnow().isoformat(),
                '_event_id': 'suricata-001'
            },
            {
                'source': 'scapy',
                'event_type': 'packet',
                'src_ip': '192.168.1.100',
                'dst_ip': '8.8.8.8',
                'proto': 'TCP',
                'packet_size': 1500,
                'threat_score': 75,
                'raw': 'Packet data',
                '_collector': 'ScapyCollector',
                '_collected_at': datetime.utcnow().isoformat(),
                '_event_id': 'scapy-001'
            }
        ]
        
        normalized_events = []
        
        for event in test_events:
            normalized = await netwatch_agent.normalizer.normalize(event)
            assert normalized is not None
            assert normalized['id'] is not None
            assert normalized['ts'] is not None
            assert normalized['event_type'] is not None
            
            normalized_events.append(normalized)
        
        # Verify all events were normalized
        assert len(normalized_events) == 3
        
        # Verify different event types
        event_types = [e['event_type'] for e in normalized_events]
        assert 'auth_failed' in event_types or 'syslog' in event_types
        assert 'ids_alert' in event_types
        assert 'packet' in event_types
    
    @pytest.mark.asyncio
    async def test_storage_persistence(self, netwatch_agent):
        """Test data persistence across restarts"""
        # Store some test data
        test_event = {
            'id': 'persist-test-001',
            'ts': datetime.utcnow().isoformat(),
            'src_ip': '192.168.1.100',
            'event_type': 'test_event',
            'severity': 'low',
            'message': 'Test persistence',
            'raw': 'Test data',
            '_collector': 'TestCollector',
            '_collected_at': datetime.utcnow().isoformat(),
            '_event_id': 'persist-001'
        }
        
        # Store event
        await netwatch_agent.storage.store_event(test_event)
        
        # Store alert
        test_alert = {
            'alert_id': 'persist-alert-001',
            'ts': datetime.utcnow().isoformat(),
            'title': 'Test Alert',
            'severity': 'medium',
            'score': 50,
            'evidence': [test_event],
            'playbook': []
        }
        
        await netwatch_agent.storage.store_alert(test_alert)
        
        # Close storage
        await netwatch_agent.storage.close()
        
        # Recreate storage manager (simulating restart)
        new_storage = StorageManager({
            'type': 'sqlite',
            'path': '/tmp/test_netwatch.db'
        })
        await new_storage.initialize()
        
        # Verify data persistence
        events = await new_storage.get_recent_events(limit=10)
        alerts = await new_storage.get_recent_alerts(limit=10)
        
        assert len(events) >= 1
        assert len(alerts) >= 1
        
        # Find our test data
        test_event_found = any(e['id'] == 'persist-test-001' for e in events)
        test_alert_found = any(a['alert_id'] == 'persist-alert-001' for a in alerts)
        
        assert test_event_found
        assert test_alert_found
        
        await new_storage.close()
    
    @pytest.mark.asyncio
    async def test_performance_under_load(self, netwatch_agent):
        """Test performance under load"""
        import time
        
        # Generate many events
        num_events = 100
        events = []
        
        for i in range(num_events):
            event = {
                'id': f'perf-test-{i}',
                'ts': datetime.utcnow().isoformat(),
                'src_ip': f'192.168.1.{i % 254 + 1}',
                'dst_ip': '10.0.0.1',
                'event_type': 'test_event',
                'severity': 'low',
                'message': f'Performance test event {i}',
                'raw': f'Raw data {i}',
                '_collector': 'TestCollector',
                '_collected_at': datetime.utcnow().isoformat(),
                '_event_id': f'perf-{i}'
            }
            events.append(event)
        
        # Process events and measure time
        start_time = time.time()
        
        for event in events:
            normalized = await netwatch_agent.normalizer.normalize(event)
            await netwatch_agent.storage.store_event(normalized)
            await netwatch_agent.rule_engine.evaluate(normalized)
        
        end_time = time.time()
        processing_time = end_time - start_time
        
        # Should process 100 events in reasonable time (< 10 seconds)
        assert processing_time < 10.0
        
        # Calculate events per second
        events_per_second = num_events / processing_time
        print(f"Processed {num_events} events in {processing_time:.2f}s ({events_per_second:.1f} events/sec)")
        
        # Should achieve at least 10 events per second
        assert events_per_second >= 10.0


if __name__ == '__main__':
    pytest.main([__file__])

