"""
Suricata Collector - Ingest Suricata EVE JSON logs
"""

import asyncio
import json
import aiofiles
from typing import Dict, Any, Optional
from datetime import datetime
from pathlib import Path

from .base import BaseCollector


class SuricataCollector(BaseCollector):
    """
    Collector for Suricata IDS EVE JSON logs
    Parses alerts, flows, DNS, HTTP, and other Suricata events
    """
    
    def __init__(self, config: Dict[str, Any], event_queue: asyncio.Queue):
        super().__init__(config, event_queue)
        self.eve_path = config.get('eve_path', '/var/log/suricata/eve.json')
        self.file_position = 0
        self.check_interval = config.get('check_interval', 0.5)
        self.event_types = config.get('event_types', ['alert', 'flow', 'dns', 'http', 'tls'])
    
    async def start(self) -> None:
        """Start monitoring Suricata EVE log"""
        await super().start()
        
        # Get initial file position (start from end)
        if Path(self.eve_path).exists():
            self.file_position = Path(self.eve_path).stat().st_size
            self.logger.info(f"Monitoring Suricata EVE log: {self.eve_path}")
        else:
            self.logger.warning(f"Suricata EVE log not found: {self.eve_path}")
        
        # Start collection task
        asyncio.create_task(self.collect())
    
    async def stop(self) -> None:
        """Stop monitoring"""
        await super().stop()
    
    async def collect(self) -> None:
        """Tail Suricata EVE JSON log"""
        while self.running:
            try:
                if not Path(self.eve_path).exists():
                    await asyncio.sleep(self.check_interval)
                    continue
                
                # Check for new data
                current_size = Path(self.eve_path).stat().st_size
                
                if current_size < self.file_position:
                    # File was rotated
                    self.logger.info("Suricata EVE log rotation detected")
                    self.file_position = 0
                
                if current_size > self.file_position:
                    # Read new lines
                    async with aiofiles.open(self.eve_path, 'r') as f:
                        await f.seek(self.file_position)
                        
                        async for line in f:
                            line = line.strip()
                            if line:
                                event = self._parse_eve_json(line)
                                if event:
                                    await self.emit(event)
                        
                        self.file_position = await f.tell()
                
                await asyncio.sleep(self.check_interval)
                
            except Exception as e:
                self.logger.error(f"Error in Suricata collect: {e}")
                self.stats['errors'] += 1
                await asyncio.sleep(self.check_interval)
    
    def _parse_eve_json(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse Suricata EVE JSON line"""
        try:
            eve_data = json.loads(line)
            
            # Filter by event type
            event_type = eve_data.get('event_type', '')
            if event_type not in self.event_types:
                return None
            
            # Create normalized event
            event = {
                'source': 'suricata',
                'event_type': f'suricata_{event_type}',
                'timestamp': eve_data.get('timestamp', datetime.utcnow().isoformat()),
                'raw': line
            }
            
            # Parse based on event type
            if event_type == 'alert':
                event.update(self._parse_alert(eve_data))
            elif event_type == 'flow':
                event.update(self._parse_flow(eve_data))
            elif event_type == 'dns':
                event.update(self._parse_dns(eve_data))
            elif event_type == 'http':
                event.update(self._parse_http(eve_data))
            elif event_type == 'tls':
                event.update(self._parse_tls(eve_data))
            elif event_type == 'stats':
                event.update(self._parse_stats(eve_data))
            
            # Common fields
            if 'src_ip' in eve_data:
                event['src_ip'] = eve_data['src_ip']
            if 'src_port' in eve_data:
                event['src_port'] = eve_data['src_port']
            if 'dest_ip' in eve_data:
                event['dst_ip'] = eve_data['dest_ip']
            if 'dest_port' in eve_data:
                event['dst_port'] = eve_data['dest_port']
            if 'proto' in eve_data:
                event['proto'] = eve_data['proto']
            
            return event
            
        except json.JSONDecodeError as e:
            self.logger.debug(f"Invalid JSON in EVE log: {e}")
            return None
        except Exception as e:
            self.logger.error(f"Error parsing EVE JSON: {e}")
            return None
    
    def _parse_alert(self, data: Dict) -> Dict[str, Any]:
        """Parse Suricata alert event"""
        parsed = {
            'severity': 'high',  # Suricata alerts are high priority
            'suricata_severity': data.get('alert', {}).get('severity', 3)
        }
        
        alert = data.get('alert', {})
        if alert:
            parsed['signature'] = alert.get('signature', '')
            parsed['signature_id'] = alert.get('signature_id', 0)
            parsed['category'] = alert.get('category', '')
            parsed['action'] = alert.get('action', '')
            
            # Extract severity level
            severity = alert.get('severity', 3)
            if severity == 1:
                parsed['severity'] = 'critical'
            elif severity == 2:
                parsed['severity'] = 'high'
            elif severity == 3:
                parsed['severity'] = 'medium'
            else:
                parsed['severity'] = 'low'
        
        # Add flow information
        if 'flow' in data:
            flow = data['flow']
            parsed['flow_id'] = flow.get('flow_id')
            parsed['flow_start'] = flow.get('start')
            parsed['flow_bytes'] = flow.get('bytes_toserver', 0) + flow.get('bytes_toclient', 0)
            parsed['flow_packets'] = flow.get('pkts_toserver', 0) + flow.get('pkts_toclient', 0)
        
        return parsed
    
    def _parse_flow(self, data: Dict) -> Dict[str, Any]:
        """Parse Suricata flow event"""
        flow = data.get('flow', {})
        
        parsed = {
            'flow_id': flow.get('flow_id'),
            'flow_start': flow.get('start'),
            'flow_end': flow.get('end'),
            'flow_age': flow.get('age', 0),
            'flow_state': flow.get('state'),
            'flow_reason': flow.get('reason'),
            'bytes_toserver': flow.get('bytes_toserver', 0),
            'bytes_toclient': flow.get('bytes_toclient', 0),
            'packets_toserver': flow.get('pkts_toserver', 0),
            'packets_toclient': flow.get('pkts_toclient', 0)
        }
        
        # Calculate total bytes/packets
        parsed['total_bytes'] = parsed['bytes_toserver'] + parsed['bytes_toclient']
        parsed['total_packets'] = parsed['packets_toserver'] + parsed['packets_toclient']
        
        # Detect potential data exfiltration
        if parsed['bytes_toserver'] > 10000000:  # > 10MB uploaded
            parsed['tags'] = ['potential_data_exfiltration']
        
        return parsed
    
    def _parse_dns(self, data: Dict) -> Dict[str, Any]:
        """Parse Suricata DNS event"""
        dns = data.get('dns', {})
        
        parsed = {
            'dns_type': dns.get('type', ''),
            'dns_query': dns.get('rrname', ''),
            'dns_rcode': dns.get('rcode', ''),
            'dns_answers': []
        }
        
        # Parse answers
        if 'answers' in dns:
            for answer in dns['answers']:
                parsed['dns_answers'].append({
                    'rrname': answer.get('rrname'),
                    'rrtype': answer.get('rrtype'),
                    'rdata': answer.get('rdata'),
                    'ttl': answer.get('ttl')
                })
        
        # Detect suspicious domains
        query = parsed['dns_query'].lower()
        if any(tld in query for tld in ['.tk', '.ml', '.ga', '.cf']):
            parsed['tags'] = ['suspicious_domain']
        
        return parsed
    
    def _parse_http(self, data: Dict) -> Dict[str, Any]:
        """Parse Suricata HTTP event"""
        http = data.get('http', {})
        
        parsed = {
            'http_method': http.get('http_method', ''),
            'http_hostname': http.get('hostname', ''),
            'http_url': http.get('url', ''),
            'http_status': http.get('status', 0),
            'http_user_agent': http.get('http_user_agent', ''),
            'http_content_type': http.get('http_content_type', ''),
            'http_length': http.get('length', 0)
        }
        
        # Detect suspicious patterns
        tags = []
        
        # Check for SQL injection attempts
        if any(sql in parsed['http_url'].lower() for sql in ['union', 'select', 'drop', 'insert']):
            tags.append('potential_sqli')
        
        # Check for suspicious user agents
        ua = parsed['http_user_agent'].lower()
        if any(scanner in ua for scanner in ['nikto', 'nmap', 'sqlmap', 'burp']):
            tags.append('scanner_detected')
        
        if tags:
            parsed['tags'] = tags
        
        return parsed
    
    def _parse_tls(self, data: Dict) -> Dict[str, Any]:
        """Parse Suricata TLS event"""
        tls = data.get('tls', {})
        
        parsed = {
            'tls_sni': tls.get('sni', ''),
            'tls_version': tls.get('version', ''),
            'tls_subject': tls.get('subject', ''),
            'tls_issuer': tls.get('issuerdn', ''),
            'tls_fingerprint': tls.get('fingerprint', '')
        }
        
        # Check for self-signed or suspicious certificates
        if parsed['tls_issuer'] == parsed['tls_subject']:
            parsed['tags'] = ['self_signed_cert']
        
        return parsed
    
    def _parse_stats(self, data: Dict) -> Dict[str, Any]:
        """Parse Suricata stats event"""
        stats = data.get('stats', {})
        
        parsed = {
            'capture_kernel_packets': stats.get('capture', {}).get('kernel_packets', 0),
            'capture_kernel_drops': stats.get('capture', {}).get('kernel_drops', 0),
            'decoder_pkts': stats.get('decoder', {}).get('pkts', 0),
            'decoder_invalid': stats.get('decoder', {}).get('invalid', 0),
            'flow_memuse': stats.get('flow', {}).get('memuse', 0)
        }
        
        return parsed

