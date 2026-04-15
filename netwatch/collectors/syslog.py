"""
Syslog Collector - Listen for syslog messages on UDP/TCP
"""

import asyncio
import socket
from typing import Dict, Any, Tuple
import re
from datetime import datetime

from .base import BaseCollector


class SyslogProtocol(asyncio.DatagramProtocol):
    """UDP protocol handler for syslog"""
    
    def __init__(self, collector):
        self.collector = collector
    
    def datagram_received(self, data: bytes, addr: Tuple[str, int]) -> None:
        """Handle received UDP datagram"""
        asyncio.create_task(self.collector.handle_message(data, addr))


class SyslogCollector(BaseCollector):
    """
    Collector that listens for syslog messages
    Supports both UDP and TCP on port 514
    """
    
    def __init__(self, config: Dict[str, Any], event_queue: asyncio.Queue):
        super().__init__(config, event_queue)
        self.host = config.get('host', '0.0.0.0')
        self.port = config.get('port', 514)
        self.protocol = config.get('protocol', 'udp')  # 'udp', 'tcp', or 'both'
        self.transport = None
        self.server = None
    
    async def start(self) -> None:
        """Start syslog listener"""
        await super().start()
        
        loop = asyncio.get_event_loop()
        
        if self.protocol in ['udp', 'both']:
            # Start UDP listener
            self.transport, _ = await loop.create_datagram_endpoint(
                lambda: SyslogProtocol(self),
                local_addr=(self.host, self.port)
            )
            self.logger.info(f"Syslog UDP listener started on {self.host}:{self.port}")
        
        if self.protocol in ['tcp', 'both']:
            # Start TCP listener
            self.server = await asyncio.start_server(
                self.handle_tcp_client,
                self.host,
                self.port
            )
            self.logger.info(f"Syslog TCP listener started on {self.host}:{self.port}")
        
        # Start collection task
        asyncio.create_task(self.collect())
    
    async def stop(self) -> None:
        """Stop syslog listener"""
        await super().stop()
        
        if self.transport:
            self.transport.close()
        
        if self.server:
            self.server.close()
            await self.server.wait_closed()
    
    async def collect(self) -> None:
        """Keep the collector running"""
        # For syslog, collection happens via callbacks
        # This method just keeps the collector alive
        while self.running:
            await asyncio.sleep(1)
    
    async def handle_tcp_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Handle TCP syslog client"""
        addr = writer.get_extra_info('peername')
        
        try:
            while True:
                data = await reader.read(4096)
                if not data:
                    break
                
                await self.handle_message(data, addr)
                
        except Exception as e:
            self.logger.error(f"Error handling TCP client {addr}: {e}")
        finally:
            writer.close()
            await writer.wait_closed()
    
    async def handle_message(self, data: bytes, addr: Tuple[str, int]) -> None:
        """Process syslog message"""
        try:
            message = data.decode('utf-8', errors='ignore').strip()
            
            if not message:
                return
            
            event = self._parse_syslog(message, addr)
            if event:
                await self.emit(event)
                
        except Exception as e:
            self.logger.error(f"Error handling syslog message: {e}")
            self.stats['errors'] += 1
    
    def _parse_syslog(self, message: str, addr: Tuple[str, int]) -> Optional[Dict[str, Any]]:
        """Parse syslog message into event"""
        try:
            event = {
                'source_ip': addr[0],
                'source_port': addr[1],
                'raw': message,
                'timestamp': datetime.utcnow().isoformat()
            }
            
            # Parse RFC3164 syslog format
            # <priority>timestamp hostname process[pid]: message
            
            # Extract priority if present
            priority_match = re.match(r'^<(\d+)>(.+)', message)
            if priority_match:
                priority = int(priority_match.group(1))
                event['facility'] = priority >> 3
                event['severity'] = priority & 0x07
                message = priority_match.group(2)
            
            # Parse timestamp, host, and message
            # Multiple formats to try
            patterns = [
                # RFC3164: MMM dd HH:mm:ss hostname process[pid]: message
                r'^(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s+(.+)',
                # RFC5424: timestamp hostname appname procid msgid message
                r'^(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.+)',
                # Simple: hostname message
                r'^(\S+)\s+(.+)'
            ]
            
            for pattern in patterns:
                match = re.match(pattern, message)
                if match:
                    groups = match.groups()
                    if len(groups) >= 5:  # Full syslog format
                        event['timestamp'] = groups[0]
                        event['host'] = groups[1]
                        event['process'] = groups[2]
                        if groups[3]:
                            event['pid'] = int(groups[3])
                        event['message'] = groups[4]
                    elif len(groups) >= 2:  # Simple format
                        event['host'] = groups[0]
                        event['message'] = groups[1]
                    break
            
            # Detect event types from message content
            event.update(self._detect_event_type(event.get('message', '')))
            
            return event
            
        except Exception as e:
            self.logger.debug(f"Error parsing syslog: {e}")
            return None
    
    def _detect_event_type(self, message: str) -> Dict[str, Any]:
        """Detect event type from message content"""
        detected = {}
        
        # SSH events
        if 'sshd' in message or 'SSH' in message:
            if 'Failed password' in message:
                detected['event_type'] = 'ssh_failed_login'
            elif 'Accepted' in message:
                detected['event_type'] = 'ssh_successful_login'
            elif 'Connection closed' in message:
                detected['event_type'] = 'ssh_disconnect'
        
        # Firewall events
        elif 'iptables' in message or 'nftables' in message:
            detected['event_type'] = 'firewall_event'
            if 'DROP' in message:
                detected['action'] = 'drop'
            elif 'ACCEPT' in message:
                detected['action'] = 'accept'
        
        # System events
        elif 'kernel' in message:
            detected['event_type'] = 'kernel_event'
            if 'Out of memory' in message:
                detected['severity'] = 'critical'
        
        # Service events
        elif 'systemd' in message:
            detected['event_type'] = 'service_event'
            if 'Started' in message:
                detected['action'] = 'start'
            elif 'Stopped' in message:
                detected['action'] = 'stop'
        
        return detected

