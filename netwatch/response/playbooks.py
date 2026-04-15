"""
Response Engine - Safe, executable playbooks with dry-run support
"""

import shlex
import subprocess
import logging
import asyncio
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
import json
import os

log = logging.getLogger("netwatch.response")


class ActionError(Exception):
    """Exception raised when an action fails"""
    pass


class ResponseEngine:
    """
    Response engine for executing security playbooks
    Supports dry-run, rate limiting, and idempotent operations
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.dry_run = config.get('dry_run', True)  # Default to safe mode
        self.rate_limits = {}  # Track action frequency
        self.audit_log = []
        
        # Load playbooks
        self.playbooks = {}
        self._load_playbooks()
    
    def _load_playbooks(self):
        """Load playbooks from configuration"""
        playbooks_path = self.config.get('playbooks_path', '/etc/netwatch/playbooks/')
        
        if os.path.exists(playbooks_path):
            for playbook_file in os.listdir(playbooks_path):
                if playbook_file.endswith('.yaml'):
                    try:
                        import yaml
                        with open(os.path.join(playbooks_path, playbook_file), 'r') as f:
                            playbook = yaml.safe_load(f)
                            self.playbooks[playbook['name']] = playbook
                            log.info(f"Loaded playbook: {playbook['name']}")
                    except Exception as e:
                        log.error(f"Error loading playbook {playbook_file}: {e}")
    
    async def execute(self, alert: Dict[str, Any]) -> bool:
        """
        Execute response playbooks for an alert
        
        Args:
            alert: Alert dictionary with playbook information
            
        Returns:
            bool: True if execution succeeded
        """
        playbook_names = alert.get('playbook', [])
        if not playbook_names:
            return True
        
        context = self._build_context(alert)
        
        for playbook_name in playbook_names:
            try:
                if playbook_name in self.playbooks:
                    await self._execute_playbook(self.playbooks[playbook_name], context)
                else:
                    # Inline playbook from alert
                    await self._execute_inline_playbook(playbook_name, context)
                
                self._audit_log('playbook_executed', {
                    'playbook': playbook_name,
                    'alert_id': alert.get('alert_id'),
                    'context': context
                })
                
            except Exception as e:
                log.error(f"Error executing playbook {playbook_name}: {e}")
                self._audit_log('playbook_failed', {
                    'playbook': playbook_name,
                    'error': str(e),
                    'alert_id': alert.get('alert_id')
                })
                return False
        
        return True
    
    def _build_context(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """Build execution context from alert and evidence"""
        context = {
            'alert_id': alert.get('alert_id'),
            'title': alert.get('title'),
            'severity': alert.get('severity'),
            'score': alert.get('score'),
            'timestamp': alert.get('ts')
        }
        
        # Extract common fields from evidence
        evidence = alert.get('evidence', [])
        if evidence:
            # Get the most recent event
            latest_event = evidence[-1] if isinstance(evidence, list) else evidence
            
            context.update({
                'src_ip': latest_event.get('src_ip'),
                'dst_ip': latest_event.get('dst_ip'),
                'src_port': latest_event.get('src_port'),
                'dst_port': latest_event.get('dst_port'),
                'user': latest_event.get('user'),
                'host': latest_event.get('host'),
                'process': latest_event.get('process'),
                'event_type': latest_event.get('event_type')
            })
        
        return context
    
    async def _execute_playbook(self, playbook: Dict[str, Any], context: Dict[str, Any]):
        """Execute a named playbook"""
        steps = playbook.get('steps', [])
        
        for step in steps:
            action = step.get('action')
            args = step.get('args', {})
            condition = step.get('condition')
            
            # Check condition
            if condition and not self._evaluate_condition(condition, context):
                log.info(f"Skipping step {action} - condition not met")
                continue
            
            # Rate limiting
            if not self._check_rate_limit(action, context):
                log.warning(f"Rate limit exceeded for action {action}")
                continue
            
            # Execute action
            await self._execute_action(action, args, context)
    
    async def _execute_inline_playbook(self, playbook_data: Any, context: Dict[str, Any]):
        """Execute inline playbook from alert"""
        if isinstance(playbook_data, list):
            # List of actions
            for action_data in playbook_data:
                action = action_data.get('action')
                args = action_data.get('args', {})
                await self._execute_action(action, args, context)
        elif isinstance(playbook_data, dict):
            # Single action
            action = playbook_data.get('action')
            args = playbook_data.get('args', {})
            await self._execute_action(action, args, context)
    
    async def _execute_action(self, action: str, args: Dict[str, Any], context: Dict[str, Any]):
        """Execute a single action"""
        # Template arguments
        rendered_args = self._template_args(args, context)
        
        log.info(f"Executing action: {action} with args: {rendered_args}")
        
        if action == "block_ip":
            await self._block_ip(rendered_args)
        elif action == "unblock_ip":
            await self._unblock_ip(rendered_args)
        elif action == "kill_process":
            await self._kill_process(rendered_args)
        elif action == "notify":
            await self._notify(rendered_args)
        elif action == "capture_packets":
            await self._capture_packets(rendered_args)
        elif action == "quarantine_file":
            await self._quarantine_file(rendered_args)
        else:
            log.warning(f"Unknown action: {action}")
    
    def _template_args(self, args: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """Template arguments with context variables"""
        from string import Template
        
        rendered = {}
        for key, value in args.items():
            if isinstance(value, str):
                try:
                    rendered[key] = Template(value).safe_substitute(context)
                except Exception as e:
                    log.error(f"Template error for {key}: {e}")
                    rendered[key] = value
            else:
                rendered[key] = value
        
        return rendered
    
    def _evaluate_condition(self, condition: str, context: Dict[str, Any]) -> bool:
        """Evaluate condition string"""
        try:
            # Simple condition evaluation (safe subset)
            # Replace variables with values
            for key, value in context.items():
                if isinstance(value, str):
                    condition = condition.replace(f'{{{key}}}', f'"{value}"')
                else:
                    condition = condition.replace(f'{{{key}}}', str(value))
            
            # Evaluate (UNSAFE - use ast.literal_eval in production)
            return eval(condition, {"__builtins__": {}}, {})
        except Exception as e:
            log.error(f"Error evaluating condition: {condition}: {e}")
            return False
    
    def _check_rate_limit(self, action: str, context: Dict[str, Any]) -> bool:
        """Check if action is rate limited"""
        key = f"{action}:{context.get('src_ip', 'unknown')}"
        now = datetime.utcnow()
        
        if key not in self.rate_limits:
            self.rate_limits[key] = []
        
        # Remove old entries (older than 1 hour)
        self.rate_limits[key] = [
            ts for ts in self.rate_limits[key]
            if now - ts < timedelta(hours=1)
        ]
        
        # Check limit (max 10 actions per hour per IP)
        if len(self.rate_limits[key]) >= 10:
            return False
        
        self.rate_limits[key].append(now)
        return True
    
    def _audit_log(self, action: str, data: Dict[str, Any]):
        """Log action for audit trail"""
        entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'action': action,
            'data': data
        }
        self.audit_log.append(entry)
        
        # Keep only last 1000 entries
        if len(self.audit_log) > 1000:
            self.audit_log = self.audit_log[-1000:]
    
    # Action implementations
    
    async def _block_ip(self, args: Dict[str, Any]):
        """Block IP address using nftables/iptables"""
        ip = args.get('ip')
        timeout = args.get('timeout', 3600)
        
        if not ip:
            raise ActionError("IP address required for block_ip action")
        
        # Try nftables first, fallback to iptables
        try:
            await self._block_ip_nft(ip, timeout)
        except ActionError:
            log.warning(f"nftables failed for {ip}, trying iptables")
            await self._block_ip_iptables(ip, timeout)
    
    async def _block_ip_nft(self, ip: str, timeout: int):
        """Block IP using nftables"""
        # Create table/chain if needed
        create_table = "nft list table inet netwatch || nft add table inet netwatch"
        create_chain = ("nft list chain inet netwatch input || "
                       "nft add chain inet netwatch input { type filter hook input priority 0; }")
        
        await self._run_cmd(create_table)
        await self._run_cmd(create_chain)
        
        # Add blocking rule
        rule = f"nft add rule inet netwatch input ip saddr {ip} counter comment \"netwatch:block:{ip}\" drop"
        await self._run_cmd(rule)
        
        log.info(f"Blocked {ip} with nftables")
    
    async def _block_ip_iptables(self, ip: str, timeout: int):
        """Block IP using iptables"""
        # Check if rule exists, if not add it
        check_cmd = f"iptables -C INPUT -s {ip} -j DROP"
        add_cmd = f"iptables -I INPUT -s {ip} -j DROP"
        
        try:
            await self._run_cmd(check_cmd)
            log.info(f"IP {ip} already blocked")
        except ActionError:
            await self._run_cmd(add_cmd)
            log.info(f"Blocked {ip} with iptables")
    
    async def _unblock_ip(self, args: Dict[str, Any]):
        """Unblock IP address"""
        ip = args.get('ip')
        
        if not ip:
            raise ActionError("IP address required for unblock_ip action")
        
        # Try nftables first
        try:
            await self._unblock_ip_nft(ip)
        except ActionError:
            log.warning(f"nftables unblock failed for {ip}, trying iptables")
            await self._unblock_ip_iptables(ip)
    
    async def _unblock_ip_nft(self, ip: str):
        """Unblock IP using nftables"""
        # List rules and find the one to delete
        list_cmd = "nft list chain inet netwatch input"
        result = await self._run_cmd(list_cmd, capture_output=True)
        
        if f"netwatch:block:{ip}" in result:
            # Find and delete the rule
            del_cmd = f"nft list chain inet netwatch input | grep '{ip}' | awk '{{print $NF}}' | xargs -r -I{{}} nft delete rule inet netwatch input handle {{}}"
            await self._run_cmd(del_cmd, shell=True)
            log.info(f"Unblocked {ip} with nftables")
    
    async def _unblock_ip_iptables(self, ip: str):
        """Unblock IP using iptables"""
        unblock_cmd = f"iptables -D INPUT -s {ip} -j DROP || true"
        await self._run_cmd(unblock_cmd)
        log.info(f"Unblocked {ip} with iptables")
    
    async def _kill_process(self, args: Dict[str, Any]):
        """Kill process by PID or name"""
        pid = args.get('pid')
        process_name = args.get('process')
        
        if pid:
            kill_cmd = f"kill -9 {pid}"
            await self._run_cmd(kill_cmd)
            log.info(f"Killed process {pid}")
        elif process_name:
            kill_cmd = f"pkill -f {process_name}"
            await self._run_cmd(kill_cmd)
            log.info(f"Killed processes matching {process_name}")
        else:
            raise ActionError("PID or process name required for kill_process")
    
    async def _notify(self, args: Dict[str, Any]):
        """Send notification"""
        channel = args.get('channel', 'log')
        message = args.get('message', 'NetWatch Alert')
        
        if channel == 'slack':
            await self._send_slack_notification(args)
        elif channel == 'email':
            await self._send_email_notification(args)
        else:
            # Default to log
            log.warning(f"NOTIFICATION: {message}")
    
    async def _send_slack_notification(self, args: Dict[str, Any]):
        """Send Slack notification"""
        webhook_url = args.get('webhook_url')
        message = args.get('message', 'NetWatch Alert')
        
        if not webhook_url:
            log.error("Slack webhook URL required")
            return
        
        payload = {
            'text': message,
            'username': 'NetWatch',
            'icon_emoji': ':shield:'
        }
        
        # Send HTTP POST (implement with aiohttp in production)
        log.info(f"Slack notification: {message}")
    
    async def _send_email_notification(self, args: Dict[str, Any]):
        """Send email notification"""
        recipients = args.get('recipients', [])
        subject = args.get('subject', 'NetWatch Alert')
        message = args.get('message', 'NetWatch Alert')
        
        if not recipients:
            log.error("Email recipients required")
            return
        
        # Send email (implement with smtplib in production)
        log.info(f"Email notification to {recipients}: {subject}")
    
    async def _capture_packets(self, args: Dict[str, Any]):
        """Capture packets for forensics"""
        filter_expr = args.get('filter', '')
        duration = args.get('duration', 60)
        output_file = args.get('output', f"/tmp/netwatch_capture_{datetime.utcnow().timestamp()}.pcap")
        
        capture_cmd = f"timeout {duration} tcpdump -i any -w {output_file} {filter_expr}"
        await self._run_cmd(capture_cmd)
        
        log.info(f"Captured packets to {output_file}")
    
    async def _quarantine_file(self, args: Dict[str, Any]):
        """Quarantine suspicious file"""
        file_path = args.get('file_path')
        quarantine_dir = args.get('quarantine_dir', '/var/quarantine')
        
        if not file_path:
            raise ActionError("File path required for quarantine_file")
        
        # Create quarantine directory
        await self._run_cmd(f"mkdir -p {quarantine_dir}")
        
        # Move file to quarantine
        filename = os.path.basename(file_path)
        quarantine_path = os.path.join(quarantine_dir, f"{datetime.utcnow().timestamp()}_{filename}")
        
        move_cmd = f"mv {file_path} {quarantine_path}"
        await self._run_cmd(move_cmd)
        
        log.info(f"Quarantined {file_path} to {quarantine_path}")
    
    async def _run_cmd(self, cmd: str, capture_output: bool = False, shell: bool = False) -> str:
        """Run system command safely"""
        if self.dry_run:
            log.info(f"(DRY RUN) Would execute: {cmd}")
            return ""
        
        log.debug(f"Executing: {cmd}")
        
        try:
            if shell:
                process = await asyncio.create_subprocess_shell(
                    cmd,
                    stdout=asyncio.subprocess.PIPE if capture_output else None,
                    stderr=asyncio.subprocess.PIPE if capture_output else None
                )
            else:
                process = await asyncio.create_subprocess_exec(
                    *shlex.split(cmd),
                    stdout=asyncio.subprocess.PIPE if capture_output else None,
                    stderr=asyncio.subprocess.PIPE if capture_output else None
                )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                error_msg = stderr.decode() if stderr else "Command failed"
                raise ActionError(f"Command failed: {error_msg}")
            
            return stdout.decode() if capture_output and stdout else ""
            
        except Exception as e:
            raise ActionError(f"Error executing command: {e}")
    
    def get_audit_log(self) -> List[Dict[str, Any]]:
        """Get audit log for compliance"""
        return self.audit_log.copy()
    
    def get_stats(self) -> Dict[str, Any]:
        """Get response engine statistics"""
        return {
            'playbooks_loaded': len(self.playbooks),
            'audit_entries': len(self.audit_log),
            'rate_limited_ips': len(self.rate_limits),
            'dry_run': self.dry_run
        }
