"""
Async Telemetry Forwarder (Syslog / UDP / TCP / WebSocket Receiver).
Receives forwarded syslog or json events from cloud VM honeypots/sensors
and feeds them directly into the local Unified Event Queue.
"""

import asyncio
import json
import uuid
from datetime import datetime, timezone
from typing import Optional

from sources.base_source import BaseSource
from sources.event_queue import UnifiedEventQueue
from engine.models import Alert, Severity, AssetTier


class HoneypotForwarder(BaseSource):
    def __init__(
        self,
        listen_host: str = "0.0.0.0",
        listen_port: int = 5140,
        event_queue: Optional[UnifiedEventQueue] = None
    ):
        super().__init__(name="HoneypotForwarder", event_queue=event_queue)
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.server: Optional[asyncio.Server] = None

    async def _handle_stream(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            while self._running:
                line = await reader.readline()
                if not line:
                    break
                text = line.decode("utf-8", errors="replace").strip()
                if not text:
                    continue

                try:
                    payload = json.loads(text)
                except Exception:
                    payload = {"raw_syslog": text}

                alert = Alert(
                    alert_id=f"FWD-{uuid.uuid4().hex[:8].upper()}",
                    timestamp=datetime.now(timezone.utc),
                    rule_name=payload.get("rule_name", "Remote Sensor Deception Event"),
                    severity=Severity.HIGH,
                    source="remote_sensor",
                    type="REMOTE_DECEPTION",
                    host=payload.get("host", "REMOTE-VM-HONEYPOT"),
                    user=payload.get("user", "root"),
                    src_ip=payload.get("src_ip", "198.51.100.44"),
                    hostname=payload.get("host", "REMOTE-VM-HONEYPOT"),
                    username=payload.get("user", "root"),
                    source_ip=payload.get("src_ip", "198.51.100.44"),
                    mitre_tactic="Reconnaissance",
                    mitre_technique_id="T1046",
                    mitre_technique_name="Network Service Discovery",
                    asset_tier=AssetTier.TIER_3,
                    asset_criticality_score=2.0,
                    raw_payload=payload
                )

                if self.event_queue:
                    await self.event_queue.put(alert)
        except Exception:
            pass
        finally:
            writer.close()

    async def start(self) -> None:
        self._running = True
        try:
            self.server = await asyncio.start_server(self._handle_stream, self.listen_host, self.listen_port)
        except Exception:
            self._running = False

    async def stop(self) -> None:
        self._running = False
        if self.server:
            self.server.close()
            await self.server.wait_closed()

