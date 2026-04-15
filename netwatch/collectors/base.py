"""
Base collector interface for all data collection plugins
"""

import asyncio
import logging
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from datetime import datetime
import uuid


class BaseCollector(ABC):
    """
    Abstract base class for all collectors
    Defines the interface that all collectors must implement
    """
    
    def __init__(self, config: Dict[str, Any], event_queue: asyncio.Queue):
        """
        Initialize collector
        
        Args:
            config: Collector-specific configuration
            event_queue: Async queue to emit events to
        """
        self.config = config
        self.event_queue = event_queue
        self.logger = logging.getLogger(f'netwatch.collector.{self.__class__.__name__}')
        self.running = False
        self.stats = {
            'events_collected': 0,
            'events_dropped': 0,
            'errors': 0,
            'start_time': None
        }
    
    async def emit(self, event: Dict[str, Any]) -> bool:
        """
        Emit an event to the processing pipeline
        
        Args:
            event: Raw event data
            
        Returns:
            bool: True if event was emitted, False if dropped
        """
        try:
            # Add collector metadata
            event['_collector'] = self.__class__.__name__
            event['_collected_at'] = datetime.utcnow().isoformat()
            event['_event_id'] = str(uuid.uuid4())
            
            # Try to put event in queue (non-blocking)
            try:
                self.event_queue.put_nowait(event)
                self.stats['events_collected'] += 1
                return True
            except asyncio.QueueFull:
                self.logger.warning("Event queue full, dropping event")
                self.stats['events_dropped'] += 1
                return False
                
        except Exception as e:
            self.logger.error(f"Error emitting event: {e}")
            self.stats['errors'] += 1
            return False
    
    @abstractmethod
    async def start(self) -> None:
        """
        Start the collector
        Must be implemented by subclasses
        """
        self.running = True
        self.stats['start_time'] = datetime.utcnow()
        self.logger.info(f"{self.__class__.__name__} started")
    
    @abstractmethod
    async def stop(self) -> None:
        """
        Stop the collector
        Must be implemented by subclasses
        """
        self.running = False
        self.logger.info(
            f"{self.__class__.__name__} stopped. "
            f"Stats: {self.stats['events_collected']} collected, "
            f"{self.stats['events_dropped']} dropped, "
            f"{self.stats['errors']} errors"
        )
    
    @abstractmethod
    async def collect(self) -> None:
        """
        Main collection loop
        Must be implemented by subclasses
        """
        pass
    
    def get_stats(self) -> Dict[str, Any]:
        """Get collector statistics"""
        return self.stats.copy()

