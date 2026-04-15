"""
Test suite for response engine and playbooks
"""

import pytest
import asyncio
import tempfile
import os
from unittest.mock import patch, MagicMock

# Add parent directory to path
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from response.playbooks import ResponseEngine, ActionError


class TestResponseEngine:
    """Test response engine functionality"""
    
    @pytest.fixture
    def response_engine(self):
        """Create response engine for testing"""
        config = {
            'dry_run': True,  # Always dry run in tests
            'playbooks_path': '/tmp/test_playbooks'
        }
        return ResponseEngine(config)
    
    @pytest.fixture
    def sample_alert(self):
        """Sample alert for testing"""
        return {
            'alert_id': 'test-alert-001',
            'title': 'Test SSH Brute Force',
            'severity': 'high',
            'score': 85,
            'ts': '2024-01-01T12:00:00Z',
            'evidence': [{
                'src_ip': '192.168.1.100',
                'dst_ip': '10.0.0.1',
                'event_type': 'auth_failed',
                'user': 'testuser'
            }],
            'playbook': ['block-src-ip']
        }
    
    def test_response_engine_init(self, response_engine):
        """Test response engine initialization"""
        assert response_engine.dry_run is True
        assert response_engine.playbooks == {}
        assert response_engine.audit_log == []
    
    @pytest.mark.asyncio
    async def test_block_ip_dry_run(self, response_engine):
        """Test IP blocking in dry run mode"""
        playbook = {
            'name': 'block-ip',
            'steps': [{
                'action': 'block_ip',
                'args': {
                    'ip': '192.168.1.100',
                    'timeout': 3600
                }
            }]
        }
        
        context = {'src_ip': '192.168.1.100'}
        
        # Should not raise exception in dry run
        await response_engine._execute_playbook(playbook, context)
        
        # Check audit log
        assert len(response_engine.audit_log) > 0
        assert response_engine.audit_log[-1]['action'] == 'playbook_executed'
    
    @pytest.mark.asyncio
    async def test_unblock_ip_dry_run(self, response_engine):
        """Test IP unblocking in dry run mode"""
        playbook = {
            'name': 'unblock-ip',
            'steps': [{
                'action': 'unblock_ip',
                'args': {'ip': '192.168.1.100'}
            }]
        }
        
        context = {'src_ip': '192.168.1.100'}
        
        # Should not raise exception in dry run
        await response_engine._execute_playbook(playbook, context)
    
    @pytest.mark.asyncio
    async def test_kill_process_dry_run(self, response_engine):
        """Test process killing in dry run mode"""
        playbook = {
            'name': 'kill-process',
            'steps': [{
                'action': 'kill_process',
                'args': {'pid': 12345}
            }]
        }
        
        context = {}
        
        # Should not raise exception in dry run
        await response_engine._execute_playbook(playbook, context)
    
    @pytest.mark.asyncio
    async def test_notify_action(self, response_engine):
        """Test notification action"""
        playbook = {
            'name': 'notify',
            'steps': [{
                'action': 'notify',
                'args': {
                    'channel': 'log',
                    'message': 'Test notification'
                }
            }]
        }
        
        context = {}
        
        # Should not raise exception
        await response_engine._execute_playbook(playbook, context)
    
    @pytest.mark.asyncio
    async def test_capture_packets_dry_run(self, response_engine):
        """Test packet capture in dry run mode"""
        playbook = {
            'name': 'capture-packets',
            'steps': [{
                'action': 'capture_packets',
                'args': {
                    'filter': 'host 192.168.1.100',
                    'duration': 60,
                    'output': '/tmp/test.pcap'
                }
            }]
        }
        
        context = {}
        
        # Should not raise exception in dry run
        await response_engine._execute_playbook(playbook, context)
    
    def test_template_args(self, response_engine):
        """Test argument templating"""
        args = {
            'ip': '{src_ip}',
            'message': 'Alert from {src_ip} targeting {dst_ip}',
            'timeout': 3600
        }
        
        context = {
            'src_ip': '192.168.1.100',
            'dst_ip': '10.0.0.1'
        }
        
        rendered = response_engine._template_args(args, context)
        
        assert rendered['ip'] == '192.168.1.100'
        assert rendered['message'] == 'Alert from 192.168.1.100 targeting 10.0.0.1'
        assert rendered['timeout'] == 3600
    
    def test_rate_limiting(self, response_engine):
        """Test rate limiting functionality"""
        context = {'src_ip': '192.168.1.100'}
        
        # First 10 calls should pass
        for i in range(10):
            assert response_engine._check_rate_limit('block_ip', context) is True
        
        # 11th call should be rate limited
        assert response_engine._check_rate_limit('block_ip', context) is False
    
    @pytest.mark.asyncio
    async def test_condition_evaluation(self, response_engine):
        """Test condition evaluation"""
        context = {
            'severity': 'high',
            'score': 85,
            'src_ip': '192.168.1.100'
        }
        
        # Test simple condition
        condition = '{severity} == "high"'
        assert response_engine._evaluate_condition(condition, context) is True
        
        # Test numeric condition
        condition = '{score} > 80'
        assert response_engine._evaluate_condition(condition, context) is True
        
        # Test false condition
        condition = '{severity} == "low"'
        assert response_engine._evaluate_condition(condition, context) is False
    
    @pytest.mark.asyncio
    async def test_playbook_with_condition(self, response_engine):
        """Test playbook execution with conditions"""
        playbook = {
            'name': 'conditional-block',
            'steps': [
                {
                    'action': 'block_ip',
                    'args': {'ip': '{src_ip}'},
                    'condition': '{severity} == "high"'
                },
                {
                    'action': 'notify',
                    'args': {'message': 'Low severity alert'},
                    'condition': '{severity} == "low"'
                }
            ]
        }
        
        # High severity - should block
        context = {'src_ip': '192.168.1.100', 'severity': 'high'}
        await response_engine._execute_playbook(playbook, context)
        
        # Low severity - should notify
        context = {'src_ip': '192.168.1.100', 'severity': 'low'}
        await response_engine._execute_playbook(playbook, context)
    
    def test_audit_logging(self, response_engine):
        """Test audit logging functionality"""
        initial_count = len(response_engine.audit_log)
        
        response_engine._audit_log('test_action', {'test': 'data'})
        
        assert len(response_engine.audit_log) == initial_count + 1
        assert response_engine.audit_log[-1]['action'] == 'test_action'
        assert response_engine.audit_log[-1]['data']['test'] == 'data'
    
    def test_get_stats(self, response_engine):
        """Test statistics retrieval"""
        stats = response_engine.get_stats()
        
        assert 'playbooks_loaded' in stats
        assert 'audit_entries' in stats
        assert 'rate_limited_ips' in stats
        assert 'dry_run' in stats
        assert stats['dry_run'] is True


class TestActionError:
    """Test ActionError exception"""
    
    def test_action_error_creation(self):
        """Test ActionError creation"""
        error = ActionError("Test error message")
        assert str(error) == "Test error message"
    
    def test_action_error_inheritance(self):
        """Test ActionError inheritance"""
        error = ActionError("Test error")
        assert isinstance(error, Exception)


if __name__ == '__main__':
    pytest.main([__file__])

