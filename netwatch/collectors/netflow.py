"""
NetFlow Collector - Basic IPFIX/NetFlow v5 collection
"""

import asyncio
import struct
import socket
from typing import Dict, Any, List, Tuple
from datetime import datetime

from .base import BaseCollector


class NetFlowProtocol(asyncio.DatagramProtocol):
    """UDP protocol handler for NetFlow"""
    
    def __init__(self, collector):
        self.collector = collector
    
    def datagram_received(self, data: bytes, addr: Tuple[str, int]) -> None:
        """Handle received NetFlow datagram"""
        asyncio.create_task(self.collector.handle_netflow(data, addr))


class NetFlowCollector(BaseCollector):
    """
    Basic NetFlow v5 and IPFIX collector
    Provides flow-level network visibility
    """
    
    def __init__(self, config: Dict[str, Any], event_queue: asyncio.Queue):
        super().__init__(config, event_queue)
        self.host = config.get('host', '0.0.0.0')
        self.port = config.get('port', 2055)
        self.transport = None
    
    async def start(self) -> None:
        """Start NetFlow listener"""
        await super().start()
        
        loop = asyncio.get_event_loop()
        
        # Start UDP listener for NetFlow
        self.transport, _ = await loop.create_datagram_endpoint(
            lambda: NetFlowProtocol(self),
            local_addr=(self.host, self.port)
        )
        
        self.logger.info(f"NetFlow collector started on {self.host}:{self.port}")
        
        # Start collection task
        asyncio.create_task(self.collect())
    
    async def stop(self) -> None:
        """Stop NetFlow listener"""
        await super().stop()
        
        if self.transport:
            self.transport.close()
    
    async def collect(self) -> None:
        """Keep collector running"""
        while self.running:
            await asyncio.sleep(1)
    
    async def handle_netflow(self, data: bytes, addr: Tuple[str, int]) -> None:
        """Process NetFlow packet"""
        try:
            # Determine NetFlow version
            version = struct.unpack('!H', data[0:2])[0]
            
            if version == 5:
                flows = self._parse_netflow_v5(data)
            elif version == 9:
                flows = self._parse_netflow_v9(data)
            elif version == 10:
                flows = self._parse_ipfix(data)
            else:
                self.logger.debug(f"Unsupported NetFlow version: {version}")
                return
            
            # Emit flow events
            for flow in flows:
                flow['source_ip'] = addr[0]
                flow['netflow_version'] = version
                await self.emit(flow)
                
        except Exception as e:
            self.logger.error(f"Error handling NetFlow: {e}")
            self.stats['errors'] += 1
    
    def _parse_netflow_v5(self, data: bytes) -> List[Dict[str, Any]]:
        """Parse NetFlow v5 packet"""
        flows = []
        
        try:
            # Parse header (24 bytes)
            header = struct.unpack('!HHIIIIBBH', data[0:24])
            version = header[0]
            count = header[1]
            sys_uptime = header[2]
            unix_secs = header[3]
            unix_nsecs = header[4]
            flow_sequence = header[5]
            engine_type = header[6]
            engine_id = header[7]
            sampling = header[8]
            
            # Parse flow records (48 bytes each)
            offset = 24
            for i in range(count):
                if offset + 48 > len(data):
                    break
                
                # Unpack flow record
                flow_data = struct.unpack('!IIIHHIIIIHHHHHHHBBBBHHBBH', 
                                        data[offset:offset+48])
                
                flow = {
                    'event_type': 'netflow_v5',
                    'timestamp': datetime.utcnow().isoformat(),
                    'src_ip': socket.inet_ntoa(struct.pack('!I', flow_data[0])),
                    'dst_ip': socket.inet_ntoa(struct.pack('!I', flow_data[1])),
                    'next_hop': socket.inet_ntoa(struct.pack('!I', flow_data[2])),
                    'input_iface': flow_data[3],
                    'output_iface': flow_data[4],
                    'packets': flow_data[5],
                    'bytes': flow_data[6],
                    'start_time': flow_data[7],
                    'end_time': flow_data[8],
                    'src_port': flow_data[9],
                    'dst_port': flow_data[10],
                    'tcp_flags': flow_data[13],
                    'proto': flow_data[14],
                    'tos': flow_data[15],
                    'src_as': flow_data[16],
                    'dst_as': flow_data[17],
                    'src_mask': flow_data[18],
                    'dst_mask': flow_data[19]
                }
                
                # Detect anomalies
                flow.update(self._detect_flow_anomalies(flow))
                
                flows.append(flow)
                offset += 48
                
        except Exception as e:
            self.logger.debug(f"Error parsing NetFlow v5: {e}")
        
        return flows
    
    def _parse_netflow_v9(self, data: bytes) -> List[Dict[str, Any]]:
        """Parse NetFlow v9 packet (simplified)"""
        flows = []
        
        try:
            # NetFlow v9 is template-based, this is a simplified parser
            # In production, you'd need to maintain template cache
            
            header = struct.unpack('!HHIIIIH', data[0:20])
            version = header[0]
            count = header[1]
            sys_uptime = header[2]
            unix_secs = header[3]
            sequence = header[4]
            source_id = header[5]
            
            # For now, just create a basic flow event
            flow = {
                'event_type': 'netflow_v9',
                'timestamp': datetime.utcnow().isoformat(),
                'flow_count': count,
                'source_id': source_id,
                'sequence': sequence,
                'raw_size': len(data)
            }
            
            flows.append(flow)
            
        except Exception as e:
            self.logger.debug(f"Error parsing NetFlow v9: {e}")
        
        return flows
    
    def _parse_ipfix(self, data: bytes) -> List[Dict[str, Any]]:
        """Parse IPFIX packet (simplified)"""
        flows = []
        
        try:
            # IPFIX is similar to NetFlow v9 but with different header
            header = struct.unpack('!HHIII', data[0:16])
            version = header[0]
            length = header[1]
            export_time = header[2]
            sequence = header[3]
            observation_domain = header[4]
            
            flow = {
                'event_type': 'ipfix',
                'timestamp': datetime.fromtimestamp(export_time).isoformat(),
                'observation_domain': observation_domain,
                'sequence': sequence,
                'raw_size': length
            }
            
            flows.append(flow)
            
        except Exception as e:
            self.logger.debug(f"Error parsing IPFIX: {e}")
        
        return flows
    
    def _detect_flow_anomalies(self, flow: Dict) -> Dict[str, Any]:
        """Detect anomalies in flow data"""
        anomalies = {}
        tags = []
        
        # Large data transfer
        if flow.get('bytes', 0) > 100000000:  # > 100MB
            tags.append('large_transfer')
            anomalies['severity'] = 'medium'
        
        # Long-lived connection
        duration = flow.get('end_time', 0) - flow.get('start_time', 0)
        if duration > 3600000:  # > 1 hour in milliseconds
            tags.append('long_connection')
        
        # Suspicious ports
        suspicious_ports = [22, 23, 3389, 445, 135, 139]
        if flow.get('dst_port') in suspicious_ports:
            tags.append('suspicious_port')
            anomalies['severity'] = 'high'
        
        # Port scan pattern
        if flow.get('packets', 0) == 1 and flow.get('tcp_flags') == 2:  # Single SYN
            tags.append('port_scan')
        
        # Data exfiltration pattern
        if (flow.get('src_port', 0) > 1024 and 
            flow.get('dst_port', 0) == 443 and
            flow.get('bytes', 0) > 10000000):
            tags.append('potential_exfiltration')
            anomalies['severity'] = 'high'
        
        if tags:
            anomalies['tags'] = tags
        
        return anomalies

