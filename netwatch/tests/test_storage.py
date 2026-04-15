"""
Test suite for storage layer
"""

import pytest
import asyncio
import tempfile
import os
from datetime import datetime, timedelta

# Add parent directory to path
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from storage.db import StorageManager, init_db
from storage.models import Alert, Event, SystemMetrics


class TestStorageManager:
    """Test storage manager functionality"""
    
    @pytest.fixture
    async def storage_manager(self):
        """Create storage manager for testing"""
        # Use temporary SQLite database
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as tmp:
            db_path = tmp.name
        
        config = {
            'type': 'sqlite',
            'path': db_path
        }
        
        storage = StorageManager(config)
        await storage.initialize()
        
        yield storage
        
        # Cleanup
        await storage.close()
        os.unlink(db_path)
    
    @pytest.fixture
    def sample_event(self):
        """Sample event for testing"""
        return {
            'id': 'test-event-001',
            'ts': datetime.utcnow().isoformat(),
            'src_ip': '192.168.1.100',
            'dst_ip': '10.0.0.1',
            'src_port': 12345,
            'dst_port': 22,
            'proto': 'TCP',
            'user': 'testuser',
            'host': 'testhost',
            'process': 'sshd',
            'pid': 1234,
            'event_type': 'auth_failed',
            'severity': 'medium',
            'tags': ['authentication', 'ssh'],
            'message': 'Failed SSH login attempt',
            'raw': 'raw log data',
            '_meta': {
                'collector': 'FileTailCollector',
                'event_id': 'meta-001'
            }
        }
    
    @pytest.fixture
    def sample_alert(self):
        """Sample alert for testing"""
        return {
            'alert_id': 'test-alert-001',
            'ts': datetime.utcnow().isoformat(),
            'title': 'SSH Brute Force Attack',
            'description': 'Multiple failed SSH login attempts',
            'severity': 'high',
            'score': 85,
            'rule': {
                'name': 'ssh-brute-force',
                'id': 'rule-001',
                'file': '/etc/netwatch/rules/ssh.yaml'
            },
            'evidence': [{
                'id': 'evt-001',
                'event_type': 'auth_failed',
                'src_ip': '192.168.1.100'
            }],
            'context': {
                'attack_type': 'brute_force',
                'target_service': 'ssh'
            },
            'playbook': ['block-src-ip', 'notify-security']
        }
    
    @pytest.mark.asyncio
    async def test_store_event(self, storage_manager, sample_event):
        """Test event storage"""
        success = await storage_manager.store_event(sample_event)
        assert success is True
        
        # Verify event was stored
        events = await storage_manager.get_recent_events(limit=1)
        assert len(events) == 1
        assert events[0]['id'] == sample_event['id']
        assert events[0]['src_ip'] == sample_event['src_ip']
        assert events[0]['event_type'] == sample_event['event_type']
    
    @pytest.mark.asyncio
    async def test_store_alert(self, storage_manager, sample_alert):
        """Test alert storage"""
        success = await storage_manager.store_alert(sample_alert)
        assert success is True
        
        # Verify alert was stored
        alerts = await storage_manager.get_recent_alerts(limit=1)
        assert len(alerts) == 1
        assert alerts[0]['alert_id'] == sample_alert['alert_id']
        assert alerts[0]['title'] == sample_alert['title']
        assert alerts[0]['severity'] == sample_alert['severity']
    
    @pytest.mark.asyncio
    async def test_store_system_metrics(self, storage_manager):
        """Test system metrics storage"""
        metrics = {
            'cpu_percent': 45.2,
            'memory_percent': 67.8,
            'disk_percent': 23.1,
            'network_bytes_sent': 1024000,
            'network_bytes_recv': 2048000,
            'events_per_second': 150.5,
            'alerts_per_second': 2.3,
            'queue_depth': 25,
            'active_collectors': 3,
            'active_rules': 15,
            'collector_stats': {
                'filetail': {'events': 1000},
                'syslog': {'events': 500}
            }
        }
        
        success = await storage_manager.store_system_metrics(metrics)
        assert success is True
    
    @pytest.mark.asyncio
    async def test_get_recent_events_with_filter(self, storage_manager, sample_event):
        """Test getting recent events with type filter"""
        # Store multiple events
        await storage_manager.store_event(sample_event)
        
        # Create another event with different type
        other_event = sample_event.copy()
        other_event['id'] = 'test-event-002'
        other_event['event_type'] = 'network_scan'
        await storage_manager.store_event(other_event)
        
        # Filter by event type
        auth_events = await storage_manager.get_recent_events(
            limit=10, 
            event_type='auth_failed'
        )
        assert len(auth_events) == 1
        assert auth_events[0]['event_type'] == 'auth_failed'
        
        scan_events = await storage_manager.get_recent_events(
            limit=10,
            event_type='network_scan'
        )
        assert len(scan_events) == 1
        assert scan_events[0]['event_type'] == 'network_scan'
    
    @pytest.mark.asyncio
    async def test_get_recent_alerts_with_filter(self, storage_manager, sample_alert):
        """Test getting recent alerts with severity filter"""
        # Store multiple alerts
        await storage_manager.store_alert(sample_alert)
        
        # Create another alert with different severity
        other_alert = sample_alert.copy()
        other_alert['alert_id'] = 'test-alert-002'
        other_alert['severity'] = 'low'
        await storage_manager.store_alert(other_alert)
        
        # Filter by severity
        high_alerts = await storage_manager.get_recent_alerts(
            limit=10,
            severity='high'
        )
        assert len(high_alerts) == 1
        assert high_alerts[0]['severity'] == 'high'
        
        low_alerts = await storage_manager.get_recent_alerts(
            limit=10,
            severity='low'
        )
        assert len(low_alerts) == 1
        assert low_alerts[0]['severity'] == 'low'
    
    @pytest.mark.asyncio
    async def test_acknowledge_alert(self, storage_manager, sample_alert):
        """Test alert acknowledgment"""
        # Store alert
        await storage_manager.store_alert(sample_alert)
        
        # Acknowledge alert
        success = await storage_manager.acknowledge_alert(
            sample_alert['alert_id'], 
            'test-user'
        )
        assert success is True
        
        # Verify acknowledgment
        alerts = await storage_manager.get_recent_alerts(limit=1)
        assert alerts[0]['acknowledged'] is True
    
    @pytest.mark.asyncio
    async def test_resolve_alert(self, storage_manager, sample_alert):
        """Test alert resolution"""
        # Store alert
        await storage_manager.store_alert(sample_alert)
        
        # Resolve alert
        success = await storage_manager.resolve_alert(sample_alert['alert_id'])
        assert success is True
        
        # Verify resolution
        alerts = await storage_manager.get_recent_alerts(limit=1)
        assert alerts[0]['resolved'] is True
    
    @pytest.mark.asyncio
    async def test_get_alert_stats(self, storage_manager, sample_alert):
        """Test alert statistics"""
        # Store multiple alerts with different severities
        await storage_manager.store_alert(sample_alert)
        
        other_alert = sample_alert.copy()
        other_alert['alert_id'] = 'test-alert-002'
        other_alert['severity'] = 'critical'
        await storage_manager.store_alert(other_alert)
        
        # Get stats
        stats = await storage_manager.get_alert_stats(hours=24)
        
        assert stats['total_alerts'] == 2
        assert stats['severity_breakdown']['high'] == 1
        assert stats['severity_breakdown']['critical'] == 1
        assert stats['unacknowledged'] == 2
        assert stats['unresolved'] == 2
    
    @pytest.mark.asyncio
    async def test_acknowledge_nonexistent_alert(self, storage_manager):
        """Test acknowledging non-existent alert"""
        success = await storage_manager.acknowledge_alert('nonexistent', 'user')
        assert success is False
    
    @pytest.mark.asyncio
    async def test_resolve_nonexistent_alert(self, storage_manager):
        """Test resolving non-existent alert"""
        success = await storage_manager.resolve_alert('nonexistent')
        assert success is False
    
    def test_storage_stats(self, storage_manager):
        """Test storage statistics"""
        stats = storage_manager.get_stats()
        
        assert 'events_stored' in stats
        assert 'alerts_stored' in stats
        assert 'errors' in stats
        assert 'last_cleanup' in stats
        
        assert stats['events_stored'] >= 0
        assert stats['alerts_stored'] >= 0
        assert stats['errors'] >= 0


class TestDatabaseInit:
    """Test database initialization"""
    
    def test_init_db_sqlite(self):
        """Test SQLite database initialization"""
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as tmp:
            db_path = tmp.name
        
        try:
            # Initialize database
            init_db(f"sqlite:///{db_path}")
            
            # Verify database file was created
            assert os.path.exists(db_path)
            
        finally:
            # Cleanup
            if os.path.exists(db_path):
                os.unlink(db_path)


if __name__ == '__main__':
    pytest.main([__file__])

