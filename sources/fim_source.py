"""
File Integrity Monitor (FIM) Source Plugin.
Uses watchdog to monitor protected assets directory for ransomware-style mass modifications,
file encryptions, and suspicious extension renames.
"""

import os
import re
import time
import uuid
import threading
from collections import deque
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, List, Deque, Tuple, Dict, Any

from sources.base_source import BaseSource
from sources.event_queue import UnifiedEventQueue
from engine.models import Alert, Severity, AssetTier

# Suspicious ransomware file extensions
SUSPICIOUS_EXTENSIONS = re.compile(
    r"\.(locked|encrypted|crypto|crypted|ransom|wannacry|vault|lockbit|blackcat|phobos|stop|djvu|mallox)$",
    re.IGNORECASE
)


class FIMHandler:
    """Watchdog event handler / fallback poller that detects suspicious file events."""
    def __init__(self, source: "FIMSource"):
        self.source = source
        self.recent_events: Deque[Tuple[float, str, str]] = deque()  # (timestamp, event_type, path)
        self.lock = threading.Lock()

    def handle_file_event(self, event_type: str, file_path: str) -> None:
        now = time.time()
        ext = os.path.splitext(file_path)[1].lower()

        with self.lock:
            self.recent_events.append((now, event_type, file_path))
            # Prune events older than 10 seconds
            while self.recent_events and (now - self.recent_events[0][0]) > 10.0:
                self.recent_events.popleft()

            event_count_10s = len(self.recent_events)

        is_suspicious_ext = bool(SUSPICIOUS_EXTENSIONS.search(file_path))

        if is_suspicious_ext:
            self.source.emit_fim_alert(
                rule_name=f"CRITICAL: Suspicious Ransomware Extension Observed ({ext})" if event_count_10s >= 20 else f"HIGH: Suspicious Ransomware Extension Observed ({ext})",
                event_type="SUSPICIOUS_FILE_ENCRYPTION",
                severity=Severity.CRITICAL if event_count_10s >= 20 else Severity.HIGH,
                file_path=file_path,
                tactic="Impact",
                tech_id="T1486",
                tech_name="Data Encrypted for Impact",
                ext=ext
            )

        # Check for mass file modifications / renames (>20 files in 10s window)
        if event_count_10s >= 20:
            self.source.emit_fim_alert(
                rule_name=f"CRITICAL: Ransomware Mass File Modification Detected ({event_count_10s} files/10s)",
                event_type="MASS_FILE_CHANGE",
                severity=Severity.CRITICAL,
                file_path=file_path,
                tactic="Impact",
                tech_id="T1486",
                tech_name="Data Encrypted for Impact",
                ext=ext
            )
        elif not is_suspicious_ext:
            # Single normal file modification
            self.source.emit_fim_alert(
                rule_name=f"FIM: File Modified ({os.path.basename(file_path)})",
                event_type="FILE_MODIFIED",
                severity=Severity.INFORMATIONAL,
                file_path=file_path,
                tactic="Collection",
                tech_id="T1005",
                tech_name="Data from Local System",
                ext=ext
            )


class FIMSource(BaseSource):
    def __init__(
        self,
        watch_dir: str = "protected_assets",
        event_queue: Optional[UnifiedEventQueue] = None
    ):
        super().__init__(name="FileIntegrityMonitor", event_queue=event_queue)
        self.watch_dir = Path(watch_dir).resolve()
        self.handler = FIMHandler(self)
        self.observer = None
        self._watchdog_available = False
        self._check_watchdog()

    def _check_watchdog(self) -> None:
        try:
            import watchdog
            self._watchdog_available = True
        except ImportError:
            self._watchdog_available = False

    def emit_fim_alert(
        self,
        rule_name: str,
        event_type: str,
        severity: Severity,
        file_path: str,
        tactic: str,
        tech_id: str,
        tech_name: str,
        ext: str
    ) -> None:
        host = os.environ.get("COMPUTERNAME", "WIN-FILESERVER-01")
        alert = Alert(
            alert_id=f"FIM-{uuid.uuid4().hex[:8].upper()}",
            timestamp=datetime.now(timezone.utc),
            rule_name=rule_name,
            severity=severity,
            source="fim",
            type=event_type,
            host=host,
            user="SYSTEM",
            src_ip="127.0.0.1",
            hostname=host,
            username="SYSTEM",
            file_path=file_path,
            file_extension=ext,
            mitre_tactic=tactic,
            mitre_technique_id=tech_id,
            mitre_technique_name=tech_name,
            asset_tier=AssetTier.TIER_1,  # File servers / protected assets are Tier 1
            asset_criticality_score=8.5,
            business_unit="Core Operations & Storage"
        )
        if self.event_queue:
            self.event_queue.put_threadsafe(alert)

    async def start(self) -> None:
        self._running = True
        self.watch_dir.mkdir(parents=True, exist_ok=True)

        if self._watchdog_available:
            try:
                from watchdog.observers import Observer
                from watchdog.events import FileSystemEventHandler

                class WatchdogBridge(FileSystemEventHandler):
                    def __init__(self, handler: FIMHandler):
                        self.handler = handler

                    def on_modified(self, event):
                        if not event.is_directory:
                            self.handler.handle_file_event("modified", event.src_path)

                    def on_created(self, event):
                        if not event.is_directory:
                            self.handler.handle_file_event("created", event.src_path)

                    def on_moved(self, event):
                        if not event.is_directory:
                            self.handler.handle_file_event("renamed", event.dest_path)

                self.observer = Observer()
                self.observer.schedule(WatchdogBridge(self.handler), str(self.watch_dir), recursive=True)
                self.observer.start()
            except Exception:
                pass

    def get_status(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "running": self._running,
            "degraded": not self._watchdog_available,
            "reason": f"Active Watchdog monitoring on {self.watch_dir}" if self._watchdog_available else "watchdog library missing",
            "watch_dir": str(self.watch_dir)
        }

    async def stop(self) -> None:
        self._running = False
        if self.observer:
            try:
                self.observer.stop()
                self.observer.join(timeout=1.0)
            except Exception:
                pass

