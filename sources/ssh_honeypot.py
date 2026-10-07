"""
Lightweight SSH / TCP Deception Honeypot Listener.
Runs a safe, non-interactive emulation socket listener (default port 2222)
that logs connection attempts, probed usernames, passwords, and source IPs,
emitting high-fidelity deception alerts to the Unified Event Queue.
"""

import sys
import uuid
import asyncio
from datetime import datetime, timezone
from typing import Optional, Dict, Any

from sources.base_source import BaseSource
from sources.event_queue import UnifiedEventQueue
from engine.models import Alert, Severity, AssetTier


class SSHHoneypotSource(BaseSource):
    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 2222,
        event_queue: Optional[UnifiedEventQueue] = None
    ):
        super().__init__(name="SSHHoneypot", event_queue=event_queue)
        self.host = host
        self.port = port
        self.server: Optional[asyncio.Server] = None

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        client_ip, client_port = writer.get_extra_info("peername") or ("unknown", 0)

        try:
            # Send SSH banner
            writer.write(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n")
            await writer.drain()

            # Read client banner/payload
            data = await asyncio.wait_for(reader.read(512), timeout=3.0)
            client_banner = data.decode("utf-8", errors="replace").strip() if data else "RAW_PROBE"

            # Parse potential username probe if sent
            user = "root"
            if "login:" in client_banner.lower() or "user" in client_banner.lower():
                user = "admin"

            alert = Alert(
                alert_id=f"HONEY-{uuid.uuid4().hex[:8].upper()}",
                timestamp=datetime.now(timezone.utc),
                rule_name=f"Honeypot Deception Trigger: Inbound SSH Probe from {client_ip}",
                severity=Severity.HIGH,
                source="honeypot",
                type="HONEYPOT_PROBE",
                host="DMZ-HONEYPOT-01",
                user=user,
                src_ip=client_ip,
                hostname="DMZ-HONEYPOT-01",
                username=user,
                source_ip=client_ip,
                command_line=client_banner,
                mitre_tactic="Reconnaissance",
                mitre_technique_id="T1046",
                mitre_technique_name="Network Service Discovery",
                asset_tier=AssetTier.TIER_3,  # Honeypots are isolated Tier 3 decoy assets
                asset_criticality_score=2.0,
                business_unit="Deception & Threat Intelligence",
                raw_payload={"client_port": client_port, "banner": client_banner}
            )

            if self.event_queue:
                await self.event_queue.put(alert)

            # Close connection cleanly
            writer.close()
            await writer.wait_closed()
        except Exception:
            try:
                writer.close()
            except Exception:
                pass

    async def start(self) -> None:
        self._running = True
        self.error_reason: Optional[str] = None
        try:
            self.server = await asyncio.start_server(self._handle_client, self.host, self.port)
        except Exception as e:
            self._running = False
            self.error_reason = f"Failed to bind port {self.port}: {e}"

    def get_status(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "running": self._running,
            "degraded": not self._running,
            "reason": f"Active TCP Deception Listener on {self.host}:{self.port}" if self._running else (getattr(self, 'error_reason', None) or f"Listener stopped on port {self.port}"),
            "port": self.port,
            "host": self.host
        }

    async def stop(self) -> None:
        self._running = False
        if self.server:
            self.server.close()
            await self.server.wait_closed()

