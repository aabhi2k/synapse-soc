"""
Unified Event Queue for Async Telemetry Ingestion.
Provides non-blocking event consumption, thread-safe injection, and observer broadcast.
"""

import asyncio
from typing import Callable, List, Optional, Any
from engine.models import Alert


class UnifiedEventQueue:
    def __init__(self, maxsize: int = 100000):
        self._queue: asyncio.Queue[Alert] = asyncio.Queue(maxsize=maxsize)
        self._subscribers: List[Callable[[Alert], Any]] = []
        self._total_ingested = 0
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    def set_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop

    async def put(self, alert: Alert) -> None:
        """Pushes an alert into the async queue and increments counters."""
        await self._queue.put(alert)
        self._total_ingested += 1
        for sub in self._subscribers:
            try:
                res = sub(alert)
                if asyncio.iscoroutine(res):
                    asyncio.create_task(res)
            except Exception:
                pass

    def put_threadsafe(self, alert: Alert) -> None:
        """Thread-safe injection from synchronous background workers (Win32, Watchdog)."""
        self._total_ingested += 1
        for sub in self._subscribers:
            try:
                res = sub(alert)
                if asyncio.iscoroutine(res):
                    if self._loop and self._loop.is_running():
                        asyncio.run_coroutine_threadsafe(res, self._loop)
            except Exception:
                pass
        try:
            if self._loop and self._loop.is_running():
                asyncio.run_coroutine_threadsafe(self._queue.put(alert), self._loop)
            else:
                self._queue.put_nowait(alert)
        except Exception:
            try:
                self._queue.put_nowait(alert)
            except Exception:
                pass

    async def get(self) -> Alert:
        """Pulls the next alert from the queue."""
        return await self._queue.get()

    def task_done(self) -> None:
        self._queue.task_done()

    def subscribe(self, callback: Callable[[Alert], Any]) -> None:
        """Registers a callback hook invoked on every incoming alert."""
        self._subscribers.append(callback)

    @property
    def qsize(self) -> int:
        return self._queue.qsize()

    @property
    def total_ingested(self) -> int:
        return self._total_ingested

    @property
    def empty(self) -> bool:
        return self._queue.empty()
