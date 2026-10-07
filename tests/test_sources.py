"""
Unit Tests for Telemetry Sources & Schema Normalization.
"""

import unittest
import sys
import asyncio
from pathlib import Path
from datetime import datetime, timezone

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from engine.models import Alert, Severity, AssetTier
from sources.event_queue import UnifiedEventQueue
from sources.windows_events import WindowsEventSource
from sources.fim_source import FIMSource
from sources.ssh_honeypot import SSHHoneypotSource
from engine.ip_enrichment import IPEnrichmentEngine


class TestTelemetrySources(unittest.TestCase):

    def test_common_alert_schema_synchronization(self):
        """Verify that standard fields (source, type, host, user, src_ip) auto-sync with legacy aliases."""
        alert = Alert(
            alert_id="TEST-001",
            timestamp=datetime.now(timezone.utc),
            source="winevt",
            type="AUTH_FAILED",
            host="DC-CORP-01",
            user="jdoe",
            src_ip="192.168.1.50",
            rule_name="Failed Logon"
        )
        self.assertEqual(alert.hostname, "DC-CORP-01")
        self.assertEqual(alert.username, "jdoe")
        self.assertEqual(alert.source_ip, "192.168.1.50")
        self.assertEqual(alert.type, "AUTH_FAILED")
        self.assertEqual(alert.asset_tier.badge, "T2")

    def test_unified_event_queue_async_and_threadsafe(self):
        """Verify async and threadsafe queue ingestion."""
        async def run_queue_test():
            q = UnifiedEventQueue()
            a = Alert(
                alert_id="Q-001",
                timestamp=datetime.now(timezone.utc),
                rule_name="Test Queue",
                host="HOST-A"
            )
            await q.put(a)
            self.assertEqual(q.total_ingested, 1)
            fetched = await q.get()
            self.assertEqual(fetched.alert_id, "Q-001")
            q.task_done()

        asyncio.run(run_queue_test())

    def test_windows_event_schema_normalization(self):
        """Test raw WinEvt XML/dict parsing into Common Alert Schema."""
        source = WindowsEventSource()
        raw_dict = {
            "TargetUserName": "Administrator",
            "WorkstationName": "DC-PRIMARY",
            "IpAddress": "185.220.101.5",
            "timestamp": "2026-10-06T21:00:00Z"
        }
        alert_4625 = source.normalize_event_data(4625, raw_dict)
        self.assertIsNotNone(alert_4625)
        self.assertEqual(alert_4625.user, "Administrator")
        self.assertEqual(alert_4625.host, "DC-PRIMARY")
        self.assertEqual(alert_4625.src_ip, "185.220.101.5")
        self.assertEqual(alert_4625.type, "AUTH_FAILED")
        self.assertEqual(alert_4625.asset_tier, AssetTier.TIER_0)
        self.assertEqual(alert_4625.asset_tier.badge, "T0")

    def test_ip_enrichment_engine(self):
        """Test IP threat score and geolocation resolution."""
        async def run_ip_test():
            engine = IPEnrichmentEngine()
            # Internal IP
            geo, score = await engine.enrich_ip("10.0.0.1")
            self.assertEqual(score, 0)
            self.assertIn("Internal", geo)

            # External IP
            geo_ext, score_ext = await engine.enrich_ip("185.220.101.5")
            self.assertGreater(score_ext, 50)
            self.assertTrue(len(geo_ext) > 0)

        asyncio.run(run_ip_test())

    def test_sources_status_and_graceful_degradation(self):
        """Test that telemetry sources report diagnostics and degrade gracefully."""
        win_src = WindowsEventSource()
        status_win = win_src.get_status()
        self.assertIn("name", status_win)
        self.assertIn("degraded", status_win)
        self.assertIn("reason", status_win)

        fim_src = FIMSource()
        status_fim = fim_src.get_status()
        self.assertIn("name", status_fim)
        self.assertIn("watch_dir", status_fim)

        honey_src = SSHHoneypotSource()
        status_honey = honey_src.get_status()
        self.assertEqual(status_honey["port"], 2222)


if __name__ == "__main__":
    unittest.main()

