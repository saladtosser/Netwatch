"""
Scapy Collector - Low-level packet capture and analysis
"""

import asyncio
from typing import Dict, Any, Optional
from datetime import datetime
import threading

from .base import BaseCollector

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, ARP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class ScapyCollector(BaseCollector):
    """
    Packet-level collector using Scapy for deep packet inspection
    Provides IDS functionality at the network layer
    """
    
    def __init__(self, config: Dict[str, Any], event_queue: asyncio.Queue):
        super().__init__(config, event_queue)
        
        if not SCAPY_AVAILABLE:
            self.logger.error("Scapy not installed. Install with: pip install scapy")
            raise ImportError("Scapy required for packet capture")
        
        self.interface = config.get('interface', 'any')
        self.filter = config.get('filter', '')  # BPF filter
        self.packet_count = config.get('packet_count', 0)  # 0 = infinite
        self.timeout = config.get('timeout', None)
        self.sniffer_thread = None
        self.loop = None
    
    async def start(self) -> None:
        """Start packet capture"""
        await super().start()
        
        # Get event loop for thread-safe operations
        self.loop = asyncio.get_event_loop()
        
        # Start sniffer in separate thread (Scapy blocks)
        self.sniffer_thread = threading.Thread(
            target=self._sniff_packets,
            daemon=True
        )
        self.sniffer_thread.start()
        
        self.logger.info(f"Scapy collector started on interface: {self.interface}")
    
    async def stop(self) -> None:
        """Stop packet capture"""
        await super().stop()
        
        # Scapy doesn't have a clean stop mechanism
        # The thread will stop when running=False is checked
    
    async def collect(self) -> None:
        """Keep collector alive"""
        while self.running:
            await asyncio.sleep(1)
    
    def _sniff_packets(self) -> None:
        """Run packet sniffer (blocking)"""
        try:
            sniff(
                iface=self.interface if self.interface != 'any' else None,
                filter=self.filter,
                prn=self._process_packet,
                count=self.packet_count,
                timeout=self.timeout,
                stop_filter=lambda x: not self.running
            )
        except PermissionError:
            self.logger.error("Permission denied for packet capture. Run with sudo.")
        except Exception as e:
            self.logger.error(f"Error in packet capture: {e}")
    
    def _process_packet(self, packet) -> None:
        """Process captured packet"""
        try:
            event = self._parse_packet(packet)
            if event:
                # Thread-safe event emission
                asyncio.run_coroutine_threadsafe(
                    self.emit(event),
                    self.loop
                )
        except Exception as e:
            self.logger.debug(f"Error processing packet: {e}")
    
    def _parse_packet(self, packet) -> Optional[Dict[str, Any]]:
        """Parse packet into event"""
        try:
            event = {
                'source': 'scapy',
                'event_type': 'packet',
                'timestamp': datetime.utcnow().isoformat(),
                'packet_size': len(packet)
            }
            
            # Parse IP layer
            if IP in packet:
                ip = packet[IP]
                event['src_ip'] = ip.src
                event['dst_ip'] = ip.dst
                event['ip_ttl'] = ip.ttl
                event['ip_proto'] = ip.proto
                
                # Detect IP spoofing
                if self._is_spoofed_ip(ip.src):
                    event['tags'] = event.get('tags', []) + ['ip_spoofing']
            
            # Parse TCP layer
            if TCP in packet:
                tcp = packet[TCP]
                event['proto'] = 'TCP'
                event['src_port'] = tcp.sport
                event['dst_port'] = tcp.dport
                event['tcp_flags'] = tcp.flags
                event['tcp_seq'] = tcp.seq
                event['tcp_ack'] = tcp.ack
                
                # Detect port scans
                if self._is_port_scan(tcp):
                    event['event_type'] = 'port_scan'
                    event['tags'] = event.get('tags', []) + ['port_scan']
                
                # Detect SYN flood
                if tcp.flags == 'S' and not tcp.ack:
                    event['tags'] = event.get('tags', []) + ['syn_packet']
            
            # Parse UDP layer
            elif UDP in packet:
                udp = packet[UDP]
                event['proto'] = 'UDP'
                event['src_port'] = udp.sport
                event['dst_port'] = udp.dport
                
                # Detect DNS amplification
                if udp.dport == 53 and len(packet) > 512:
                    event['tags'] = event.get('tags', []) + ['dns_amplification']
            
            # Parse ICMP layer
            elif ICMP in packet:
                icmp = packet[ICMP]
                event['proto'] = 'ICMP'
                event['icmp_type'] = icmp.type
                event['icmp_code'] = icmp.code
                
                # Detect ICMP flood
                if icmp.type == 8:  # Echo request
                    event['tags'] = event.get('tags', []) + ['ping']
                
                # Detect ICMP redirect
                if icmp.type == 5:
                    event['event_type'] = 'icmp_redirect'
                    event['severity'] = 'high'
            
            # Parse DNS layer
            if DNS in packet:
                dns = packet[DNS]
                event['dns_query'] = self._get_dns_query(dns)
                event['dns_response'] = self._get_dns_response(dns)
                
                # Detect DNS tunneling
                if event['dns_query'] and len(event['dns_query']) > 50:
                    event['tags'] = event.get('tags', []) + ['dns_tunneling']
            
            # Parse ARP layer
            if ARP in packet:
                arp = packet[ARP]
                event['proto'] = 'ARP'
                event['arp_op'] = arp.op
                event['arp_src_mac'] = arp.hwsrc
                event['arp_dst_mac'] = arp.hwdst
                event['arp_src_ip'] = arp.psrc
                event['arp_dst_ip'] = arp.pdst
                
                # Detect ARP spoofing
                if arp.op == 2:  # ARP reply
                    event['tags'] = event.get('tags', []) + ['arp_reply']
            
            # Detect large packets (potential data exfiltration)
            if event['packet_size'] > 1500:
                event['tags'] = event.get('tags', []) + ['large_packet']
            
            # Detect fragmented packets
            if IP in packet and packet[IP].flags & 1:  # MF flag
                event['tags'] = event.get('tags', []) + ['fragmented']
            
            # Calculate threat score
            event['threat_score'] = self._calculate_threat_score(event)
            
            return event
            
        except Exception as e:
            self.logger.debug(f"Error parsing packet: {e}")
            return None
    
    def _is_spoofed_ip(self, ip: str) -> bool:
        """Check if IP appears to be spoofed"""
        # Check for private IPs from external interfaces
        private_ranges = [
            '10.', '172.16.', '172.17.', '172.18.', '172.19.',
            '172.20.', '172.21.', '172.22.', '172.23.', '172.24.',
            '172.25.', '172.26.', '172.27.', '172.28.', '172.29.',
            '172.30.', '172.31.', '192.168.', '127.'
        ]
        
        # This is a simple check - in production, you'd verify against routing tables
        return any(ip.startswith(range) for range in private_ranges)
    
    def _is_port_scan(self, tcp) -> bool:
        """Detect potential port scan"""
        # SYN scan detection
        if tcp.flags == 'S':
            # Check for common scan patterns
            if tcp.dport in [21, 22, 23, 25, 80, 443, 445, 3389]:
                return True
        
        # NULL scan
        if tcp.flags == 0:
            return True
        
        # FIN scan
        if tcp.flags == 'F':
            return True
        
        # XMAS scan
        if tcp.flags == 'FPU':
            return True
        
        return False
    
    def _get_dns_query(self, dns) -> Optional[str]:
        """Extract DNS query"""
        if dns.qr == 0 and dns.qd:  # Query
            return dns.qd.qname.decode('utf-8', errors='ignore')
        return None
    
    def _get_dns_response(self, dns) -> Optional[str]:
        """Extract DNS response"""
        if dns.qr == 1 and dns.an:  # Response
            answers = []
            for i in range(dns.ancount):
                if hasattr(dns.an[i], 'rdata'):
                    answers.append(str(dns.an[i].rdata))
            return ','.join(answers)
        return None
    
    def _calculate_threat_score(self, event: Dict) -> int:
        """Calculate threat score based on packet characteristics"""
        score = 0
        tags = event.get('tags', [])
        
        # High severity
        if 'ip_spoofing' in tags:
            score += 80
        if 'arp_spoofing' in tags:
            score += 70
        if event.get('event_type') == 'icmp_redirect':
            score += 90
        
        # Medium severity
        if 'port_scan' in tags:
            score += 50
        if 'dns_tunneling' in tags:
            score += 60
        if 'dns_amplification' in tags:
            score += 50
        
        # Low severity
        if 'large_packet' in tags:
            score += 20
        if 'fragmented' in tags:
            score += 15
        if 'syn_packet' in tags:
            score += 10
        
        return min(score, 100)

