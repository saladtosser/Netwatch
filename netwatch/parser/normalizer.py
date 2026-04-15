"""
Event Normalizer - Transform raw events into canonical schema
"""

import re
import json
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime
import hashlib
import ipaddress


class EventNormalizer:
    """
    Normalizes events from various sources into a canonical schema
    
    Canonical Schema:
    {
        'id': str,              # Unique event ID
        'ts': str,              # ISO timestamp
        'src_ip': str,          # Source IP address
        'dst_ip': str,          # Destination IP address  
        'src_port': int,        # Source port
        'dst_port': int,        # Destination port
        'proto': str,           # Protocol (TCP/UDP/ICMP/etc)
        'user': str,            # Username if available
        'host': str,            # Hostname
        'event_type': str,      # Normalized event type
        'process': str,         # Process name
        'pid': int,             # Process ID
        'tags': List[str],      # Event tags/labels
        'severity': str,        # low/medium/high/critical
        'message': str,         # Human-readable message
        'raw': str,             # Original raw event
        '_meta': Dict           # Additional metadata
    }
    """
    
    def __init__(self):
        self.logger = logging.getLogger('netwatch.normalizer')
        self.stats = {
            'events_normalized': 0,
            'events_failed': 0
        }
    
    async def normalize(self, raw_event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Normalize a raw event into canonical schema
        
        Args:
            raw_event: Raw event from collector
            
        Returns:
            Normalized event or None if normalization fails
        """
        try:
            # Determine source and normalize accordingly
            source = raw_event.get('_collector', 'unknown')
            
            if source == 'FileTailCollector':
                normalized = self._normalize_filetail(raw_event)
            elif source == 'SyslogCollector':
                normalized = self._normalize_syslog(raw_event)
            elif source == 'SuricataCollector':
                normalized = self._normalize_suricata(raw_event)
            elif source == 'NetFlowCollector':
                normalized = self._normalize_netflow(raw_event)
            elif source == 'ScapyCollector':
                normalized = self._normalize_scapy(raw_event)
            else:
                normalized = self._normalize_generic(raw_event)
            
            if normalized:
                # Add common fields
                normalized = self._add_common_fields(normalized, raw_event)
                
                # Validate and enrich
                normalized = self._validate_and_enrich(normalized)
                
                self.stats['events_normalized'] += 1
                return normalized
            else:
                self.stats['events_failed'] += 1
                return None
                
        except Exception as e:
            self.logger.error(f"Error normalizing event: {e}")
            self.stats['events_failed'] += 1
            return None
    
    def _normalize_filetail(self, event: Dict) -> Dict[str, Any]:
        """Normalize FileTail collector events"""
        normalized = {
            'event_type': event.get('event_type', 'log_event'),
            'host': event.get('host', 'localhost'),
            'message': event.get('message', ''),
            'raw': event.get('raw', '')
        }
        
        # Extract IPs and ports if available
        if 'src_ip' in event:
            normalized['src_ip'] = event['src_ip']
        if 'dst_ip' in event:
            normalized['dst_ip'] = event['dst_ip']
        if 'src_port' in event:
            normalized['src_port'] = event['src_port']
        if 'dst_port' in event:
            normalized['dst_port'] = event['dst_port']
        
        # Extract user and process info
        if 'user' in event:
            normalized['user'] = event['user']
        if 'process' in event:
            normalized['process'] = event['process']
        if 'pid' in event:
            normalized['pid'] = event['pid']
        if 'command' in event:
            normalized['message'] = event['command']
        
        # Map event types
        event_type_map = {
            'ssh_failed_login': 'auth_failed',
            'ssh_successful_login': 'auth_success',
            'sudo_command': 'privilege_escalation'
        }
        
        if event.get('event_type') in event_type_map:
            normalized['event_type'] = event_type_map[event['event_type']]
            normalized['tags'] = ['authentication']
        
        return normalized
    
    def _normalize_syslog(self, event: Dict) -> Dict[str, Any]:
        """Normalize Syslog collector events"""
        normalized = {
            'event_type': event.get('event_type', 'syslog'),
            'host': event.get('host', event.get('source_ip', 'unknown')),
            'message': event.get('message', ''),
            'raw': event.get('raw', '')
        }
        
        # Add network info
        if 'source_ip' in event:
            normalized['src_ip'] = event['source_ip']
        
        # Add process info
        if 'process' in event:
            normalized['process'] = event['process']
        if 'pid' in event:
            normalized['pid'] = event['pid']
        
        # Add severity based on syslog priority
        if 'severity' in event:
            severity_map = {
                0: 'critical',  # Emergency
                1: 'critical',  # Alert
                2: 'critical',  # Critical
                3: 'high',      # Error
                4: 'medium',    # Warning
                5: 'low',       # Notice
                6: 'low',       # Info
                7: 'low'        # Debug
            }
            normalized['severity'] = severity_map.get(event['severity'], 'low')
        
        # Add tags based on content
        tags = []
        if 'firewall_event' in str(event.get('event_type', '')):
            tags.append('firewall')
        if 'kernel_event' in str(event.get('event_type', '')):
            tags.append('kernel')
        if 'service_event' in str(event.get('event_type', '')):
            tags.append('service')
        
        if tags:
            normalized['tags'] = tags
        
        return normalized
    
    def _normalize_suricata(self, event: Dict) -> Dict[str, Any]:
        """Normalize Suricata collector events"""
        normalized = {
            'event_type': event.get('event_type', 'ids_alert'),
            'message': event.get('signature', event.get('message', '')),
            'raw': event.get('raw', '')
        }
        
        # Network fields
        if 'src_ip' in event:
            normalized['src_ip'] = event['src_ip']
        if 'dst_ip' in event:
            normalized['dst_ip'] = event['dst_ip']
        if 'src_port' in event:
            normalized['src_port'] = event['src_port']
        if 'dst_port' in event:
            normalized['dst_port'] = event['dst_port']
        if 'proto' in event:
            normalized['proto'] = event['proto']
        
        # Severity
        if 'severity' in event:
            normalized['severity'] = event['severity']
        
        # Tags
        tags = ['ids', 'suricata']
        if 'category' in event:
            tags.append(event['category'].lower().replace(' ', '_'))
        if 'tags' in event:
            tags.extend(event['tags'])
        normalized['tags'] = tags
        
        # Additional Suricata-specific fields in metadata
        normalized['_meta'] = {
            'signature_id': event.get('signature_id'),
            'category': event.get('category'),
            'flow_id': event.get('flow_id')
        }
        
        return normalized
    
    def _normalize_netflow(self, event: Dict) -> Dict[str, Any]:
        """Normalize NetFlow collector events"""
        normalized = {
            'event_type': 'network_flow',
            'message': f"Flow: {event.get('packets', 0)} packets, {event.get('bytes', 0)} bytes",
            'raw': str(event)
        }
        
        # Network fields
        if 'src_ip' in event:
            normalized['src_ip'] = event['src_ip']
        if 'dst_ip' in event:
            normalized['dst_ip'] = event['dst_ip']
        if 'src_port' in event:
            normalized['src_port'] = event['src_port']
        if 'dst_port' in event:
            normalized['dst_port'] = event['dst_port']
        
        # Protocol
        proto_map = {
            6: 'TCP',
            17: 'UDP',
            1: 'ICMP'
        }
        if 'proto' in event:
            normalized['proto'] = proto_map.get(event['proto'], str(event['proto']))
        
        # Tags
        tags = ['netflow']
        if 'tags' in event:
            tags.extend(event['tags'])
        normalized['tags'] = tags
        
        # Severity based on anomalies
        if 'severity' in event:
            normalized['severity'] = event['severity']
        elif 'large_transfer' in tags or 'potential_exfiltration' in tags:
            normalized['severity'] = 'high'
        elif 'suspicious_port' in tags:
            normalized['severity'] = 'medium'
        else:
            normalized['severity'] = 'low'
        
        # Metadata
        normalized['_meta'] = {
            'packets': event.get('packets'),
            'bytes': event.get('bytes'),
            'start_time': event.get('start_time'),
            'end_time': event.get('end_time'),
            'tcp_flags': event.get('tcp_flags')
        }
        
        return normalized
    
    def _normalize_scapy(self, event: Dict) -> Dict[str, Any]:
        """Normalize Scapy collector events"""
        normalized = {
            'event_type': event.get('event_type', 'packet'),
            'message': f"Packet captured: {event.get('proto', 'Unknown')}",
            'raw': str(event)
        }
        
        # Network fields
        if 'src_ip' in event:
            normalized['src_ip'] = event['src_ip']
        if 'dst_ip' in event:
            normalized['dst_ip'] = event['dst_ip']
        if 'src_port' in event:
            normalized['src_port'] = event['src_port']
        if 'dst_port' in event:
            normalized['dst_port'] = event['dst_port']
        if 'proto' in event:
            normalized['proto'] = event['proto']
        
        # Tags
        tags = ['packet_capture']
        if 'tags' in event:
            tags.extend(event['tags'])
        normalized['tags'] = tags
        
        # Severity based on threat score
        threat_score = event.get('threat_score', 0)
        if threat_score >= 80:
            normalized['severity'] = 'critical'
        elif threat_score >= 60:
            normalized['severity'] = 'high'
        elif threat_score >= 40:
            normalized['severity'] = 'medium'
        else:
            normalized['severity'] = 'low'
        
        # Metadata
        normalized['_meta'] = {
            'packet_size': event.get('packet_size'),
            'threat_score': threat_score,
            'tcp_flags': event.get('tcp_flags'),
            'dns_query': event.get('dns_query'),
            'dns_response': event.get('dns_response')
        }
        
        return normalized
    
    def _normalize_generic(self, event: Dict) -> Dict[str, Any]:
        """Generic normalization for unknown sources"""
        normalized = {
            'event_type': 'generic',
            'message': str(event),
            'raw': str(event)
        }
        
        # Try to extract common fields
        for field in ['src_ip', 'dst_ip', 'src_port', 'dst_port', 'proto', 
                     'user', 'host', 'process', 'pid', 'severity', 'tags']:
            if field in event:
                normalized[field] = event[field]
        
        return normalized
    
    def _add_common_fields(self, normalized: Dict, raw_event: Dict) -> Dict:
        """Add common fields to normalized event"""
        # Generate unique ID
        id_source = f"{normalized.get('ts', '')}{normalized.get('src_ip', '')}" \
                   f"{normalized.get('dst_ip', '')}{normalized.get('event_type', '')}"
        normalized['id'] = hashlib.sha256(id_source.encode()).hexdigest()[:16]
        
        # Timestamp
        if 'ts' not in normalized:
            normalized['ts'] = raw_event.get('_collected_at', 
                                            datetime.utcnow().isoformat())
        
        # Default values
        normalized.setdefault('tags', [])
        normalized.setdefault('severity', 'low')
        normalized.setdefault('_meta', {})
        
        # Add collector info to metadata
        normalized['_meta']['collector'] = raw_event.get('_collector', 'unknown')
        normalized['_meta']['event_id'] = raw_event.get('_event_id', '')
        
        return normalized
    
    def _validate_and_enrich(self, event: Dict) -> Dict:
        """Validate and enrich normalized event"""
        # Validate IP addresses
        for field in ['src_ip', 'dst_ip']:
            if field in event:
                try:
                    ip = ipaddress.ip_address(event[field])
                    # Add IP type tags
                    if ip.is_private:
                        event['tags'].append(f'{field}_private')
                    if ip.is_multicast:
                        event['tags'].append(f'{field}_multicast')
                    if ip.is_loopback:
                        event['tags'].append(f'{field}_loopback')
                except ValueError:
                    self.logger.debug(f"Invalid IP address: {event[field]}")
                    event[field] = None
        
        # Validate ports
        for field in ['src_port', 'dst_port']:
            if field in event:
                try:
                    port = int(event[field])
                    if not 0 <= port <= 65535:
                        event[field] = None
                except (ValueError, TypeError):
                    event[field] = None
        
        # Enrich with port service names
        if 'dst_port' in event and event['dst_port']:
            service = self._get_service_name(event['dst_port'])
            if service:
                event['_meta']['service'] = service
        
        # Ensure required fields exist
        event.setdefault('event_type', 'unknown')
        event.setdefault('message', '')
        
        return event
    
    def _get_service_name(self, port: int) -> Optional[str]:
        """Get service name for common ports"""
        services = {
            21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp',
            53: 'dns', 80: 'http', 110: 'pop3', 143: 'imap',
            443: 'https', 445: 'smb', 3306: 'mysql', 3389: 'rdp',
            5432: 'postgresql', 5900: 'vnc', 6379: 'redis',
            8080: 'http-alt', 8443: 'https-alt'
        }
        return services.get(port)

