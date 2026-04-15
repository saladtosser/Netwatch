"""
SQLAlchemy models for NetWatch storage
"""

from sqlalchemy import Column, Integer, String, DateTime, Text, Boolean, JSON, Float, Index
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.dialects.postgresql import UUID
import datetime
import uuid

Base = declarative_base()


class Event(Base):
    """Normalized event storage"""
    __tablename__ = "events"
    
    id = Column(Integer, primary_key=True)
    event_id = Column(String(64), unique=True, index=True, nullable=False)
    ts = Column(DateTime, default=datetime.datetime.utcnow, index=True)
    
    # Network fields
    src_ip = Column(String(45), index=True)  # IPv6 compatible
    dst_ip = Column(String(45), index=True)
    src_port = Column(Integer)
    dst_port = Column(Integer)
    proto = Column(String(16), index=True)
    
    # System fields
    user = Column(String(128), index=True)
    host = Column(String(256), index=True)
    process = Column(String(256))
    pid = Column(Integer)
    
    # Event classification
    event_type = Column(String(128), index=True)
    severity = Column(String(32), index=True)
    tags = Column(JSON)
    message = Column(Text)
    
    # Raw data and metadata
    raw = Column(Text)
    meta = Column(JSON)
    
    # Collector info
    collector = Column(String(64), index=True)
    collected_at = Column(DateTime, default=datetime.datetime.utcnow)
    
    # Indexes for common queries
    __table_args__ = (
        Index('idx_events_src_ip_ts', 'src_ip', 'ts'),
        Index('idx_events_dst_ip_ts', 'dst_ip', 'ts'),
        Index('idx_events_type_ts', 'event_type', 'ts'),
        Index('idx_events_severity_ts', 'severity', 'ts'),
    )


class Alert(Base):
    """Alert storage"""
    __tablename__ = "alerts"
    
    id = Column(Integer, primary_key=True)
    alert_id = Column(String(64), unique=True, index=True, nullable=False)
    ts = Column(DateTime, default=datetime.datetime.utcnow, index=True)
    
    # Alert details
    title = Column(String(256), nullable=False)
    description = Column(Text)
    severity = Column(String(32), index=True, nullable=False)
    score = Column(Integer, default=0, index=True)
    
    # Rule information
    rule_name = Column(String(128), index=True)
    rule_id = Column(String(64), index=True)
    rule_file = Column(String(256))
    
    # Evidence and context
    evidence = Column(JSON)  # List of related events
    context = Column(JSON)   # Additional context data
    
    # Response information
    playbook = Column(JSON)  # Playbook actions
    response_executed = Column(Boolean, default=False)
    response_success = Column(Boolean)
    response_error = Column(Text)
    
    # Status tracking
    acknowledged = Column(Boolean, default=False, index=True)
    acknowledged_by = Column(String(128))
    acknowledged_at = Column(DateTime)
    resolved = Column(Boolean, default=False, index=True)
    resolved_at = Column(DateTime)
    
    # Raw alert data
    raw = Column(Text)
    
    # Indexes
    __table_args__ = (
        Index('idx_alerts_severity_ts', 'severity', 'ts'),
        Index('idx_alerts_acknowledged_ts', 'acknowledged', 'ts'),
        Index('idx_alerts_resolved_ts', 'resolved', 'ts'),
    )


class SystemMetrics(Base):
    """System performance metrics"""
    __tablename__ = "system_metrics"
    
    id = Column(Integer, primary_key=True)
    ts = Column(DateTime, default=datetime.datetime.utcnow, index=True)
    
    # Performance metrics
    cpu_percent = Column(Float)
    memory_percent = Column(Float)
    disk_percent = Column(Float)
    network_bytes_sent = Column(Integer)
    network_bytes_recv = Column(Integer)
    
    # NetWatch specific metrics
    events_per_second = Column(Float)
    alerts_per_second = Column(Float)
    queue_depth = Column(Integer)
    active_collectors = Column(Integer)
    active_rules = Column(Integer)
    
    # Collector statistics
    collector_stats = Column(JSON)  # Per-collector stats
    
    # Index for time-series queries
    __table_args__ = (
        Index('idx_metrics_ts', 'ts'),
    )


class ThreatIntelligence(Base):
    """Threat intelligence feeds"""
    __tablename__ = "threat_intel"
    
    id = Column(Integer, primary_key=True)
    indicator = Column(String(256), unique=True, index=True, nullable=False)
    indicator_type = Column(String(32), index=True)  # ip, domain, hash, etc.
    
    # Threat data
    threat_type = Column(String(128), index=True)
    severity = Column(String(32), index=True)
    confidence = Column(Float)
    description = Column(Text)
    
    # Source information
    source = Column(String(128), index=True)
    source_url = Column(String(512))
    first_seen = Column(DateTime, default=datetime.datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.datetime.utcnow)
    
    # Metadata
    tags = Column(JSON)
    metadata = Column(JSON)
    
    # Indexes
    __table_args__ = (
        Index('idx_threat_intel_type_severity', 'indicator_type', 'severity'),
        Index('idx_threat_intel_source', 'source'),
    )


class ResponseAudit(Base):
    """Audit trail for response actions"""
    __tablename__ = "response_audit"
    
    id = Column(Integer, primary_key=True)
    ts = Column(DateTime, default=datetime.datetime.utcnow, index=True)
    
    # Action details
    action = Column(String(128), nullable=False, index=True)
    playbook = Column(String(128), index=True)
    alert_id = Column(String(64), index=True)
    
    # Execution context
    triggered_by = Column(String(128))  # rule, manual, api
    user = Column(String(128))
    source_ip = Column(String(45))
    
    # Action parameters
    parameters = Column(JSON)
    success = Column(Boolean, index=True)
    error_message = Column(Text)
    execution_time = Column(Float)  # seconds
    
    # Result data
    result = Column(JSON)
    
    # Indexes
    __table_args__ = (
        Index('idx_audit_action_ts', 'action', 'ts'),
        Index('idx_audit_alert_ts', 'alert_id', 'ts'),
        Index('idx_audit_success_ts', 'success', 'ts'),
    )


class RuleExecution(Base):
    """Rule execution statistics"""
    __tablename__ = "rule_execution"
    
    id = Column(Integer, primary_key=True)
    ts = Column(DateTime, default=datetime.datetime.utcnow, index=True)
    
    # Rule information
    rule_name = Column(String(128), index=True, nullable=False)
    rule_id = Column(String(64), index=True)
    rule_type = Column(String(32), index=True)  # simple, correlation, aggregation
    
    # Execution details
    events_evaluated = Column(Integer, default=0)
    matches_found = Column(Integer, default=0)
    execution_time = Column(Float)  # milliseconds
    memory_used = Column(Integer)   # bytes
    
    # Performance metrics
    events_per_second = Column(Float)
    match_rate = Column(Float)  # matches / events_evaluated
    
    # Indexes
    __table_args__ = (
        Index('idx_rule_exec_rule_ts', 'rule_name', 'ts'),
        Index('idx_rule_exec_type_ts', 'rule_type', 'ts'),
    )
