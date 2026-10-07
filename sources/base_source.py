"""
Abstract Base Source Plugin for Modular Ingestion.
Every telemetry adapter (WinEvt, FIM, Honeypot, Cowrie, Syslog, Replay) implements this class.
"""

from abc import ABC, abstractmethod
import asyncio
from typing import Optional
from engine.models import Alert


class BaseSource(ABC):
    def __init__(self, name: str, event_queue: Optional["UnifiedEventQueue"] = None):
        self.name = name
        self.event_queue = event_queue
        self._running = False
        self._task: Optional[asyncio.Task] = None

    def set_queue(self, event_queue: "UnifiedEventQueue") -> None:
        self.event_queue = event_queue

    async def emit(self, alert: Alert) -> None:
        """Pushes an alert to the unified event queue."""
        if self.event_queue is not None:
            await self.event_queue.put(alert)
        else:
            raise RuntimeError(f"Source {self.name} has no event_queue attached to emit alerts.")

    @abstractmethod
    async def start(self) -> None:
        """Starts collecting/streaming telemetry."""
        pass

    @abstractmethod
    async def stop(self) -> None:
        """Stops collecting telemetry."""
        pass

    @property
    def is_running(self) -> bool:
        return self._running

