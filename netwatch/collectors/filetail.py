"""
FileTail Collector - Follow and parse Linux log files
"""

import asyncio
import aiofiles
import os
from pathlib import Path
from typing import Dict, Any, List
import re
from datetime import datetime

from .base import BaseCollector


class FileTailCollector(BaseCollector):
    """
    Collector that tails log files and emits events
    Supports multiple files with automatic rotation detection
    """
    
    def __init__(self, config: Dict[str, Any], event_queue: asyncio.Queue):
        super().__init__(config, event_queue)
        self.files: List[str] = config.get('files', ['/var/log/syslog'])
        self.file_handles = {}
        self.file_positions = {}
        self.check_interval = config.get('check_interval', 1.0)
    
    async def start(self) -> None:
        """Start tailing configured files"""
        await super().start()
        
        # Initialize file handles and positions
        for filepath in self.files:
            if os.path.exists(filepath):
                self.file_positions[filepath] = self._get_file_size(filepath)
                self.logger.info(f"Monitoring file: {filepath}")
            else:
                self.logger.warning(f"File not found: {filepath}")
        
        # Start collection task
        asyncio.create_task(self.collect())
    
    async def stop(self) -> None:
        """Stop tailing files"""
        await super().stop()
        
        # Close file handles
        for handle in self.file_handles.values():
            if handle:
                await handle.close()
    
    async def collect(self) -> None:
        """Main collection loop - tail files for new lines"""
        while self.running:
            try:
                for filepath in self.files:
                    if not os.path.exists(filepath):
                        continue
                    
                    # Check for file rotation
                    current_size = self._get_file_size(filepath)
                    last_position = self.file_positions.get(filepath, 0)
                    
                    if current_size < last_position:
                        # File was rotated
                        self.logger.info(f"File rotation detected: {filepath}")
                        last_position = 0
                    
                    if current_size > last_position:
                        # Read new lines
                        async with aiofiles.open(filepath, 'r') as f:
                            await f.seek(last_position)
                            
                            async for line in f:
                                line = line.strip()
                                if line:
                                    event = self._parse_line(filepath, line)
                                    if event:
                                        await self.emit(event)
                            
                            # Update position
                            self.file_positions[filepath] = await f.tell()
                
                # Sleep before next check
                await asyncio.sleep(self.check_interval)
                
            except Exception as e:
                self.logger.error(f"Error in collect loop: {e}")
                self.stats['errors'] += 1
                await asyncio.sleep(self.check_interval)
    
    def _get_file_size(self, filepath: str) -> int:
        """Get current file size"""
        try:
            return os.path.getsize(filepath)
        except:
            return 0
    
    def _parse_line(self, filepath: str, line: str) -> Optional[Dict[str, Any]]:
        """Parse a log line into an event"""
        try:
            event = {
                'source_file': filepath,
                'raw': line,
                'timestamp': datetime.utcnow().isoformat()
            }
            
            # Parse based on file type
            if 'auth.log' in filepath:
                event['log_type'] = 'auth'
                event.update(self._parse_auth_log(line))
            elif 'syslog' in filepath:
                event['log_type'] = 'syslog'
                event.update(self._parse_syslog(line))
            elif 'apache' in filepath or 'access' in filepath:
                event['log_type'] = 'apache'
                event.update(self._parse_apache_log(line))
            else:
                event['log_type'] = 'generic'
            
            return event
            
        except Exception as e:
            self.logger.debug(f"Error parsing line: {e}")
            return None
    
    def _parse_auth_log(self, line: str) -> Dict[str, Any]:
        """Parse auth.log format"""
        parsed = {}
        
        # SSH failed login pattern
        ssh_fail = re.search(
            r'Failed password for (?:invalid user )?(\S+) from (\S+) port (\d+)',
            line
        )
        if ssh_fail:
            parsed['event_type'] = 'ssh_failed_login'
            parsed['user'] = ssh_fail.group(1)
            parsed['src_ip'] = ssh_fail.group(2)
            parsed['src_port'] = int(ssh_fail.group(3))
            return parsed
        
        # SSH successful login
        ssh_success = re.search(
            r'Accepted (\S+) for (\S+) from (\S+) port (\d+)',
            line
        )
        if ssh_success:
            parsed['event_type'] = 'ssh_successful_login'
            parsed['auth_method'] = ssh_success.group(1)
            parsed['user'] = ssh_success.group(2)
            parsed['src_ip'] = ssh_success.group(3)
            parsed['src_port'] = int(ssh_success.group(4))
            return parsed
        
        # sudo command
        sudo_cmd = re.search(
            r'sudo:\s+(\S+).*COMMAND=(.+)',
            line
        )
        if sudo_cmd:
            parsed['event_type'] = 'sudo_command'
            parsed['user'] = sudo_cmd.group(1)
            parsed['command'] = sudo_cmd.group(2)
            return parsed
        
        return parsed
    
    def _parse_syslog(self, line: str) -> Dict[str, Any]:
        """Parse syslog format"""
        parsed = {}
        
        # Standard syslog pattern
        syslog_pattern = re.match(
            r'^(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s+(.+)',
            line
        )
        if syslog_pattern:
            parsed['timestamp'] = syslog_pattern.group(1)
            parsed['host'] = syslog_pattern.group(2)
            parsed['process'] = syslog_pattern.group(3)
            if syslog_pattern.group(4):
                parsed['pid'] = int(syslog_pattern.group(4))
            parsed['message'] = syslog_pattern.group(5)
        
        return parsed
    
    def _parse_apache_log(self, line: str) -> Dict[str, Any]:
        """Parse Apache/Nginx access log format"""
        parsed = {}
        
        # Common Log Format
        clf_pattern = re.match(
            r'^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"(\S+)\s+([^\s]+)\s+([^"]+)"\s+(\d+)\s+(\d+)',
            line
        )
        if clf_pattern:
            parsed['src_ip'] = clf_pattern.group(1)
            parsed['timestamp'] = clf_pattern.group(2)
            parsed['method'] = clf_pattern.group(3)
            parsed['uri'] = clf_pattern.group(4)
            parsed['http_version'] = clf_pattern.group(5)
            parsed['status_code'] = int(clf_pattern.group(6))
            parsed['response_size'] = int(clf_pattern.group(7))
        
        return parsed

