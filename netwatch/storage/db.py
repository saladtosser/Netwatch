"""
Database management and storage operations
"""

import os
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.exc import SQLAlchemyError
from contextlib import asynccontextmanager

from .models import Base, Event, Alert, SystemMetrics, ThreatIntelligence, ResponseAudit, RuleExecution


class StorageManager:
    """
    Database storage manager with async operations
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger('netwatch.storage')
        
        # Database configuration
        db_type = config.get('type', 'sqlite')
        if db_type == 'sqlite':
            db_path = config.get('path', './netwatch.db')
            self.db_url = f"sqlite:///{db_path}"
        elif db_type == 'postgresql':
            host = config.get('host', 'localhost')
            port = config.get('port', 5432)
            database = config.get('database', 'netwatch')
            username = config.get('username', 'netwatch')
            password = config.get('password', '')
            self.db_url = f"postgresql://{username}:{password}@{host}:{port}/{database}"
        else:
            raise ValueError(f"Unsupported database type: {db_type}")
        
        # Create engine and session
        self.engine = create_engine(
            self.db_url,
            connect_args={"check_same_thread": False} if "sqlite" in self.db_url else {},
            pool_pre_ping=True,
            pool_recycle=3600
        )
        self.SessionLocal = sessionmaker(bind=self.engine, autoflush=False, autocommit=False)
        
        # Statistics
        self.stats = {
            'events_stored': 0,
            'alerts_stored': 0,
            'errors': 0,
            'last_cleanup': None
        }
    
    async def initialize(self):
        """Initialize database and create tables"""
        try:
            # Create all tables
            Base.metadata.create_all(bind=self.engine)
            self.logger.info("Database initialized successfully")
            
            # Create indexes for better performance
            await self._create_indexes()
            
            # Schedule cleanup task
            asyncio.create_task(self._cleanup_old_data())
            
        except Exception as e:
            self.logger.error(f"Error initializing database: {e}")
            raise
    
    async def _create_indexes(self):
        """Create additional indexes for performance"""
        try:
            with self.engine.connect() as conn:
                # Create composite indexes for common queries
                indexes = [
                    "CREATE INDEX IF NOT EXISTS idx_events_src_ip_ts ON events(src_ip, ts)",
                    "CREATE INDEX IF NOT EXISTS idx_events_dst_ip_ts ON events(dst_ip, ts)",
                    "CREATE INDEX IF NOT EXISTS idx_events_type_ts ON events(event_type, ts)",
                    "CREATE INDEX IF NOT EXISTS idx_alerts_severity_ts ON alerts(severity, ts)",
                    "CREATE INDEX IF NOT EXISTS idx_alerts_acknowledged_ts ON alerts(acknowledged, ts)"
                ]
                
                for index_sql in indexes:
                    try:
                        conn.execute(text(index_sql))
                    except Exception as e:
                        self.logger.debug(f"Index creation skipped (may already exist): {e}")
                
                conn.commit()
                
        except Exception as e:
            self.logger.warning(f"Error creating indexes: {e}")
    
    async def store_event(self, event: Dict[str, Any]) -> bool:
        """Store normalized event"""
        try:
            with self.SessionLocal() as session:
                db_event = Event(
                    event_id=event.get('id'),
                    ts=datetime.fromisoformat(event.get('ts', datetime.utcnow().isoformat())),
                    src_ip=event.get('src_ip'),
                    dst_ip=event.get('dst_ip'),
                    src_port=event.get('src_port'),
                    dst_port=event.get('dst_port'),
                    proto=event.get('proto'),
                    user=event.get('user'),
                    host=event.get('host'),
                    process=event.get('process'),
                    pid=event.get('pid'),
                    event_type=event.get('event_type'),
                    severity=event.get('severity'),
                    tags=event.get('tags', []),
                    message=event.get('message'),
                    raw=event.get('raw'),
                    meta=event.get('_meta', {}),
                    collector=event.get('_meta', {}).get('collector', 'unknown')
                )
                
                session.add(db_event)
                session.commit()
                
                self.stats['events_stored'] += 1
                return True
                
        except SQLAlchemyError as e:
            self.logger.error(f"Error storing event: {e}")
            self.stats['errors'] += 1
            return False
    
    async def store_alert(self, alert: Dict[str, Any]) -> bool:
        """Store alert"""
        try:
            with self.SessionLocal() as session:
                db_alert = Alert(
                    alert_id=alert.get('alert_id'),
                    ts=datetime.fromisoformat(alert.get('ts', datetime.utcnow().isoformat())),
                    title=alert.get('title'),
                    description=alert.get('description'),
                    severity=alert.get('severity'),
                    score=alert.get('score', 0),
                    rule_name=alert.get('rule', {}).get('name'),
                    rule_id=alert.get('rule', {}).get('id'),
                    rule_file=alert.get('rule', {}).get('file'),
                    evidence=alert.get('evidence', []),
                    context=alert.get('context', {}),
                    playbook=alert.get('playbook', []),
                    raw=str(alert)
                )
                
                session.add(db_alert)
                session.commit()
                
                self.stats['alerts_stored'] += 1
                return True
                
        except SQLAlchemyError as e:
            self.logger.error(f"Error storing alert: {e}")
            self.stats['errors'] += 1
            return False
    
    async def store_system_metrics(self, metrics: Dict[str, Any]) -> bool:
        """Store system performance metrics"""
        try:
            with self.SessionLocal() as session:
                db_metrics = SystemMetrics(
                    ts=datetime.utcnow(),
                    cpu_percent=metrics.get('cpu_percent'),
                    memory_percent=metrics.get('memory_percent'),
                    disk_percent=metrics.get('disk_percent'),
                    network_bytes_sent=metrics.get('network_bytes_sent'),
                    network_bytes_recv=metrics.get('network_bytes_recv'),
                    events_per_second=metrics.get('events_per_second'),
                    alerts_per_second=metrics.get('alerts_per_second'),
                    queue_depth=metrics.get('queue_depth'),
                    active_collectors=metrics.get('active_collectors'),
                    active_rules=metrics.get('active_rules'),
                    collector_stats=metrics.get('collector_stats', {})
                )
                
                session.add(db_metrics)
                session.commit()
                return True
                
        except SQLAlchemyError as e:
            self.logger.error(f"Error storing metrics: {e}")
            return False
    
    async def get_recent_events(self, limit: int = 100, event_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get recent events"""
        try:
            with self.SessionLocal() as session:
                query = session.query(Event).order_by(Event.ts.desc())
                
                if event_type:
                    query = query.filter(Event.event_type == event_type)
                
                events = query.limit(limit).all()
                
                return [self._event_to_dict(event) for event in events]
                
        except SQLAlchemyError as e:
            self.logger.error(f"Error getting events: {e}")
            return []
    
    async def get_recent_alerts(self, limit: int = 100, severity: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get recent alerts"""
        try:
            with self.SessionLocal() as session:
                query = session.query(Alert).order_by(Alert.ts.desc())
                
                if severity:
                    query = query.filter(Alert.severity == severity)
                
                alerts = query.limit(limit).all()
                
                return [self._alert_to_dict(alert) for alert in alerts]
                
        except SQLAlchemyError as e:
            self.logger.error(f"Error getting alerts: {e}")
            return []
    
    async def acknowledge_alert(self, alert_id: str, user: str) -> bool:
        """Acknowledge an alert"""
        try:
            with self.SessionLocal() as session:
                alert = session.query(Alert).filter(Alert.alert_id == alert_id).first()
                if alert:
                    alert.acknowledged = True
                    alert.acknowledged_by = user
                    alert.acknowledged_at = datetime.utcnow()
                    session.commit()
                    return True
                return False
                
        except SQLAlchemyError as e:
            self.logger.error(f"Error acknowledging alert: {e}")
            return False
    
    async def resolve_alert(self, alert_id: str) -> bool:
        """Resolve an alert"""
        try:
            with self.SessionLocal() as session:
                alert = session.query(Alert).filter(Alert.alert_id == alert_id).first()
                if alert:
                    alert.resolved = True
                    alert.resolved_at = datetime.utcnow()
                    session.commit()
                    return True
                return False
                
        except SQLAlchemyError as e:
            self.logger.error(f"Error resolving alert: {e}")
            return False
    
    async def get_alert_stats(self, hours: int = 24) -> Dict[str, Any]:
        """Get alert statistics"""
        try:
            cutoff_time = datetime.utcnow() - timedelta(hours=hours)
            
            with self.SessionLocal() as session:
                # Total alerts
                total_alerts = session.query(Alert).filter(Alert.ts >= cutoff_time).count()
                
                # By severity
                severity_counts = {}
                for severity in ['critical', 'high', 'medium', 'low']:
                    count = session.query(Alert).filter(
                        Alert.ts >= cutoff_time,
                        Alert.severity == severity
                    ).count()
                    severity_counts[severity] = count
                
                # Acknowledged vs unacknowledged
                acknowledged = session.query(Alert).filter(
                    Alert.ts >= cutoff_time,
                    Alert.acknowledged == True
                ).count()
                
                # Resolved vs unresolved
                resolved = session.query(Alert).filter(
                    Alert.ts >= cutoff_time,
                    Alert.resolved == True
                ).count()
                
                return {
                    'total_alerts': total_alerts,
                    'severity_breakdown': severity_counts,
                    'acknowledged': acknowledged,
                    'unacknowledged': total_alerts - acknowledged,
                    'resolved': resolved,
                    'unresolved': total_alerts - resolved,
                    'timeframe_hours': hours
                }
                
        except SQLAlchemyError as e:
            self.logger.error(f"Error getting alert stats: {e}")
            return {}
    
    async def _cleanup_old_data(self):
        """Clean up old data to prevent database bloat"""
        while True:
            try:
                # Clean up events older than 30 days
                cutoff_time = datetime.utcnow() - timedelta(days=30)
                
                with self.SessionLocal() as session:
                    # Delete old events
                    deleted_events = session.query(Event).filter(
                        Event.ts < cutoff_time
                    ).delete()
                    
                    # Delete old metrics (keep 7 days)
                    metrics_cutoff = datetime.utcnow() - timedelta(days=7)
                    deleted_metrics = session.query(SystemMetrics).filter(
                        SystemMetrics.ts < metrics_cutoff
                    ).delete()
                    
                    session.commit()
                    
                    if deleted_events > 0 or deleted_metrics > 0:
                        self.logger.info(f"Cleaned up {deleted_events} events and {deleted_metrics} metrics")
                
                self.stats['last_cleanup'] = datetime.utcnow()
                
                # Run cleanup every 6 hours
                await asyncio.sleep(6 * 3600)
                
            except Exception as e:
                self.logger.error(f"Error in cleanup task: {e}")
                await asyncio.sleep(3600)  # Retry in 1 hour
    
    def _event_to_dict(self, event: Event) -> Dict[str, Any]:
        """Convert Event model to dictionary"""
        return {
            'id': event.event_id,
            'ts': event.ts.isoformat(),
            'src_ip': event.src_ip,
            'dst_ip': event.dst_ip,
            'src_port': event.src_port,
            'dst_port': event.dst_port,
            'proto': event.proto,
            'user': event.user,
            'host': event.host,
            'process': event.process,
            'pid': event.pid,
            'event_type': event.event_type,
            'severity': event.severity,
            'tags': event.tags or [],
            'message': event.message,
            'collector': event.collector
        }
    
    def _alert_to_dict(self, alert: Alert) -> Dict[str, Any]:
        """Convert Alert model to dictionary"""
        return {
            'alert_id': alert.alert_id,
            'ts': alert.ts.isoformat(),
            'title': alert.title,
            'description': alert.description,
            'severity': alert.severity,
            'score': alert.score,
            'rule_name': alert.rule_name,
            'evidence': alert.evidence or [],
            'acknowledged': alert.acknowledged,
            'resolved': alert.resolved,
            'response_executed': alert.response_executed
        }
    
    async def close(self):
        """Close database connections"""
        try:
            self.engine.dispose()
            self.logger.info("Database connections closed")
        except Exception as e:
            self.logger.error(f"Error closing database: {e}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get storage statistics"""
        return self.stats.copy()


def init_db(db_url: Optional[str] = None) -> None:
    """Initialize database (standalone function)"""
    if db_url:
        engine = create_engine(db_url)
    else:
        engine = create_engine("sqlite:///./netwatch.db")
    
    Base.metadata.create_all(bind=engine)
    engine.dispose()
