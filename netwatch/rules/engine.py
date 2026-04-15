"""
Rule Engine - YAML/Sigma-style detection rules
"""

import re
import yaml
import logging
import asyncio
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from collections import defaultdict
import operator


class RuleEngine:
    """
    Rule engine for event detection and alerting
    Supports single-event matching and multi-event correlation
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger('netwatch.rules')
        self.rules: List[Dict] = []
        self.rules_path = Path(config.get('path', '/etc/netwatch/rules/'))
        
        # Event buffer for correlation rules
        self.event_buffer = defaultdict(list)
        self.buffer_ttl = config.get('buffer_ttl', 3600)  # 1 hour
        
        # Statistics
        self.stats = {
            'rules_loaded': 0,
            'events_evaluated': 0,
            'matches': 0
        }
    
    async def load_rules(self) -> None:
        """Load rules from YAML files"""
        self.rules = []
        
        if not self.rules_path.exists():
            self.logger.warning(f"Rules directory not found: {self.rules_path}")
            self.rules_path.mkdir(parents=True, exist_ok=True)
            return
        
        # Load all YAML files
        for rule_file in self.rules_path.glob('*.yaml'):
            try:
                with open(rule_file, 'r') as f:
                    rule = yaml.safe_load(f)
                    if rule:
                        rule['_file'] = str(rule_file)
                        self.rules.append(rule)
                        self.logger.info(f"Loaded rule: {rule.get('name', rule_file.name)}")
            except Exception as e:
                self.logger.error(f"Error loading rule {rule_file}: {e}")
        
        self.stats['rules_loaded'] = len(self.rules)
        self.logger.info(f"Loaded {len(self.rules)} rules")
    
    async def reload_rules(self) -> None:
        """Reload rules from disk"""
        self.logger.info("Reloading rules...")
        await self.load_rules()
    
    async def evaluate(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Evaluate an event against all rules
        
        Args:
            event: Normalized event
            
        Returns:
            List of rule matches/alerts
        """
        matches = []
        self.stats['events_evaluated'] += 1
        
        # Clean old events from buffer
        self._clean_event_buffer()
        
        # Add event to buffer for correlation
        event_type = event.get('event_type', 'unknown')
        self.event_buffer[event_type].append({
            'event': event,
            'timestamp': datetime.fromisoformat(event.get('ts', datetime.utcnow().isoformat()))
        })
        
        # Evaluate each rule
        for rule in self.rules:
            try:
                if rule.get('enabled', True):
                    match = await self._evaluate_rule(rule, event)
                    if match:
                        matches.append(match)
                        self.stats['matches'] += 1
            except Exception as e:
                self.logger.error(f"Error evaluating rule {rule.get('name')}: {e}")
        
        return matches
    
    async def _evaluate_rule(self, rule: Dict, event: Dict) -> Optional[Dict[str, Any]]:
        """Evaluate a single rule against an event"""
        rule_type = rule.get('type', 'simple')
        
        if rule_type == 'simple':
            return self._evaluate_simple_rule(rule, event)
        elif rule_type == 'correlation':
            return await self._evaluate_correlation_rule(rule, event)
        elif rule_type == 'aggregation':
            return self._evaluate_aggregation_rule(rule, event)
        else:
            self.logger.warning(f"Unknown rule type: {rule_type}")
            return None
    
    def _evaluate_simple_rule(self, rule: Dict, event: Dict) -> Optional[Dict[str, Any]]:
        """Evaluate simple single-event rule"""
        detection = rule.get('detection', {})
        
        # Check field matches
        if 'fields' in detection:
            if not self._match_fields(detection['fields'], event):
                return None
        
        # Check regex patterns
        if 'regex' in detection:
            if not self._match_regex(detection['regex'], event):
                return None
        
        # Check conditions
        if 'condition' in detection:
            if not self._evaluate_condition(detection['condition'], event):
                return None
        
        # Rule matched - create alert
        return self._create_alert(rule, [event])
    
    async def _evaluate_correlation_rule(self, rule: Dict, event: Dict) -> Optional[Dict[str, Any]]:
        """Evaluate correlation rule (multiple events)"""
        correlation = rule.get('correlation', {})
        
        # Get events to correlate
        event_types = correlation.get('event_types', [])
        timeframe = correlation.get('timeframe', 300)  # 5 minutes default
        
        # Collect relevant events from buffer
        relevant_events = []
        cutoff_time = datetime.utcnow() - timedelta(seconds=timeframe)
        
        for event_type in event_types:
            for buffered in self.event_buffer.get(event_type, []):
                if buffered['timestamp'] >= cutoff_time:
                    relevant_events.append(buffered['event'])
        
        # Check correlation conditions
        conditions = correlation.get('conditions', [])
        for condition in conditions:
            if not self._evaluate_correlation_condition(condition, relevant_events):
                return None
        
        # Correlation matched
        if relevant_events:
            return self._create_alert(rule, relevant_events)
        
        return None
    
    def _evaluate_aggregation_rule(self, rule: Dict, event: Dict) -> Optional[Dict[str, Any]]:
        """Evaluate aggregation rule (threshold-based)"""
        aggregation = rule.get('aggregation', {})
        
        # Get aggregation parameters
        field = aggregation.get('field', 'event_type')
        threshold = aggregation.get('threshold', 5)
        timeframe = aggregation.get('timeframe', 60)  # 1 minute default
        group_by = aggregation.get('group_by', [])
        
        # Get matching events from buffer
        cutoff_time = datetime.utcnow() - timedelta(seconds=timeframe)
        field_value = event.get(field)
        
        matching_events = []
        for buffered in self.event_buffer.get(event.get('event_type', ''), []):
            if (buffered['timestamp'] >= cutoff_time and 
                buffered['event'].get(field) == field_value):
                
                # Check group_by fields
                if group_by:
                    match = True
                    for group_field in group_by:
                        if buffered['event'].get(group_field) != event.get(group_field):
                            match = False
                            break
                    if not match:
                        continue
                
                matching_events.append(buffered['event'])
        
        # Check threshold
        if len(matching_events) >= threshold:
            return self._create_alert(rule, matching_events)
        
        return None
    
    def _match_fields(self, fields: Dict, event: Dict) -> bool:
        """Check if event fields match rule fields"""
        for field, value in fields.items():
            event_value = self._get_nested_field(event, field)
            
            if isinstance(value, list):
                # Match any value in list
                if event_value not in value:
                    return False
            elif isinstance(value, dict):
                # Complex matching (e.g., {'$gte': 100})
                if not self._match_complex_value(value, event_value):
                    return False
            else:
                # Exact match
                if event_value != value:
                    return False
        
        return True
    
    def _match_regex(self, patterns: Dict, event: Dict) -> bool:
        """Check if event matches regex patterns"""
        for field, pattern in patterns.items():
            event_value = str(self._get_nested_field(event, field) or '')
            
            try:
                if not re.search(pattern, event_value, re.IGNORECASE):
                    return False
            except re.error as e:
                self.logger.error(f"Invalid regex pattern: {pattern}: {e}")
                return False
        
        return True
    
    def _evaluate_condition(self, condition: str, event: Dict) -> bool:
        """Evaluate condition expression"""
        try:
            # Simple condition evaluation
            # In production, use a safe expression evaluator
            
            # Replace field references with values
            for field in re.findall(r'\$(\w+)', condition):
                value = event.get(field)
                if isinstance(value, str):
                    condition = condition.replace(f'${field}', f'"{value}"')
                else:
                    condition = condition.replace(f'${field}', str(value))
            
            # Evaluate (UNSAFE - use ast.literal_eval or similar in production)
            return eval(condition, {"__builtins__": {}}, {})
        except Exception as e:
            self.logger.error(f"Error evaluating condition: {condition}: {e}")
            return False
    
    def _evaluate_correlation_condition(self, condition: Dict, events: List[Dict]) -> bool:
        """Evaluate correlation condition"""
        cond_type = condition.get('type')
        
        if cond_type == 'sequence':
            # Check event sequence
            sequence = condition.get('sequence', [])
            return self._check_event_sequence(events, sequence)
        
        elif cond_type == 'field_match':
            # Check if field values match across events
            field = condition.get('field')
            values = set()
            for event in events:
                values.add(event.get(field))
            return len(values) == 1  # All same value
        
        elif cond_type == 'count':
            # Check event count
            op = condition.get('operator', '>=')
            count = condition.get('count', 1)
            return self._compare(len(events), op, count)
        
        return False
    
    def _check_event_sequence(self, events: List[Dict], sequence: List[str]) -> bool:
        """Check if events match expected sequence"""
        event_types = [e.get('event_type') for e in sorted(
            events, key=lambda x: x.get('ts', '')
        )]
        
        # Simple sequence matching
        seq_index = 0
        for event_type in event_types:
            if seq_index < len(sequence) and event_type == sequence[seq_index]:
                seq_index += 1
        
        return seq_index == len(sequence)
    
    def _match_complex_value(self, condition: Dict, value: Any) -> bool:
        """Match complex value conditions"""
        for op, expected in condition.items():
            if op == '$gte':
                if not (value >= expected):
                    return False
            elif op == '$gt':
                if not (value > expected):
                    return False
            elif op == '$lte':
                if not (value <= expected):
                    return False
            elif op == '$lt':
                if not (value < expected):
                    return False
            elif op == '$ne':
                if not (value != expected):
                    return False
            elif op == '$in':
                if value not in expected:
                    return False
            elif op == '$nin':
                if value in expected:
                    return False
            elif op == '$regex':
                if not re.search(expected, str(value), re.IGNORECASE):
                    return False
        
        return True
    
    def _compare(self, a: Any, op: str, b: Any) -> bool:
        """Compare values with operator"""
        ops = {
            '==': operator.eq,
            '!=': operator.ne,
            '>': operator.gt,
            '>=': operator.ge,
            '<': operator.lt,
            '<=': operator.le
        }
        return ops.get(op, operator.eq)(a, b)
    
    def _get_nested_field(self, obj: Dict, field: str) -> Any:
        """Get nested field value (supports dot notation)"""
        parts = field.split('.')
        value = obj
        
        for part in parts:
            if isinstance(value, dict):
                value = value.get(part)
            else:
                return None
        
        return value
    
    def _create_alert(self, rule: Dict, events: List[Dict]) -> Dict[str, Any]:
        """Create alert from rule match"""
        alert = {
            'alert_id': f"alert-{datetime.utcnow().timestamp()}",
            'ts': datetime.utcnow().isoformat(),
            'title': rule.get('name', 'Unknown Rule'),
            'description': rule.get('description', ''),
            'severity': rule.get('severity', 'medium'),
            'score': self._calculate_score(rule, events),
            'rule': {
                'name': rule.get('name'),
                'id': rule.get('id'),
                'file': rule.get('_file')
            },
            'evidence': events,
            'tags': rule.get('tags', []),
            'playbook': rule.get('response', {}).get('playbook', [])
        }
        
        return alert
    
    def _calculate_score(self, rule: Dict, events: List[Dict]) -> int:
        """Calculate alert score"""
        base_score = {
            'critical': 100,
            'high': 75,
            'medium': 50,
            'low': 25
        }.get(rule.get('severity', 'medium'), 50)
        
        # Adjust based on evidence count
        evidence_multiplier = min(len(events) / 10, 2.0)
        
        return int(base_score * evidence_multiplier)
    
    def _clean_event_buffer(self) -> None:
        """Remove old events from buffer"""
        cutoff_time = datetime.utcnow() - timedelta(seconds=self.buffer_ttl)
        
        for event_type in list(self.event_buffer.keys()):
            self.event_buffer[event_type] = [
                e for e in self.event_buffer[event_type]
                if e['timestamp'] >= cutoff_time
            ]
            
            if not self.event_buffer[event_type]:
                del self.event_buffer[event_type]

