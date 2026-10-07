"""
Unit Tests for Streaming Correlator & 5 Core Detection Rules.
"""

import unittest
import sys
from pathlib import Path
from datetime import datetime, timezone, timedelta

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from engine.models import Alert, Incident, Severity, AssetTier
from engine.streaming_correlator import StreamingCorrelator
from engine.detection_rules import DetectionRuleEngine


class TestStreamingCorrelator(unittest.TestCase):

    def setUp(self):
        self.correlator = StreamingCorrelator(time_window_minutes=15.0)

    def test_brute_force_rule_detection(self):
        """Rule 1: >= 5 failed logins within 5 mins triggers Brute Force rule."""
        now = datetime.now(timezone.utc)
        for i in range(5):
            alert = Alert(
                alert_id=f"TEST-BF-{i+1}",
                timestamp=now + timedelta(seconds=i * 10),
                source="winevt",
                type="AUTH_FAILED",
                host="DC-CORP-01",
                user="admin",
                src_ip="198.51.100.99",
                rule_name="Windows Security: Failed Logon Attempt (Event 4625)",
                severity=Severity.LOW,
                asset_tier=AssetTier.TIER_0
            )
            inc = self.correlator.on_new_alert(alert)

        self.assertEqual(inc.alert_count, 5)
        self.assertIn("Credential Access", inc.mitre_tactics)
        self.assertEqual(inc.highest_asset_tier, AssetTier.TIER_0)
        self.assertEqual(inc.tier_badge, "T0")

    def test_post_brute_login_escalation(self):
        """Rule 2: Successful login following brute force escalates incident to Critical."""
        now = datetime.now(timezone.utc)
        # 3 failed logins
        for i in range(3):
            self.correlator.on_new_alert(Alert(
                alert_id=f"TEST-FAIL-{i}",
                timestamp=now + timedelta(seconds=i * 10),
                source="winevt",
                type="AUTH_FAILED",
                host="DC-CORP-01",
                user="admin",
                src_ip="198.51.100.99",
                rule_name="Failed Logon",
                asset_tier=AssetTier.TIER_0
            ))

        # Successful login
        success_alert = Alert(
            alert_id="TEST-SUCC-1",
            timestamp=now + timedelta(seconds=40),
            source="winevt",
            type="AUTH_SUCCESS",
            host="DC-CORP-01",
            user="admin",
            src_ip="198.51.100.99",
            rule_name="Successful Logon",
            asset_tier=AssetTier.TIER_0
        )
        inc = self.correlator.on_new_alert(success_alert)

        self.assertEqual(inc.highest_alert_severity, Severity.CRITICAL)
        self.assertIn("Initial Access", inc.mitre_tactics)
        self.assertGreaterEqual(inc.risk_score, 70.0)

    def test_spawn_after_login_rule(self):
        """Rule 3: Process spawn following login is correlated."""
        now = datetime.now(timezone.utc)
        # Login
        self.correlator.on_new_alert(Alert(
            alert_id="TEST-LOGON",
            timestamp=now,
            source="winevt",
            type="AUTH_SUCCESS",
            host="DC-CORP-01",
            user="admin",
            src_ip="198.51.100.99",
            rule_name="Successful Logon",
            asset_tier=AssetTier.TIER_0
        ))
        # Spawn PowerShell
        proc_alert = Alert(
            alert_id="TEST-PROC",
            timestamp=now + timedelta(seconds=30),
            source="winevt",
            type="PROCESS_SPAWN",
            host="DC-CORP-01",
            user="admin",
            src_ip="198.51.100.99",
            process_name="powershell.exe",
            command_line="powershell.exe -enc AAAA",
            rule_name="Process Created",
            severity=Severity.HIGH,
            asset_tier=AssetTier.TIER_0
        )
        inc = self.correlator.on_new_alert(proc_alert)

        self.assertIn("Execution", inc.mitre_tactics)
        self.assertEqual(inc.alert_count, 2)

    def test_mass_file_change_rule(self):
        """Rule 4: Mass file change in FIM triggers Impact ransomware rule."""
        now = datetime.now(timezone.utc)
        fim_alert = Alert(
            alert_id="TEST-FIM-1",
            timestamp=now,
            source="fim",
            type="MASS_FILE_CHANGE",
            host="FS-PROD-01",
            user="SYSTEM",
            file_path="C:\\Shares\\Data.xlsx.locked",
            rule_name="CRITICAL: Ransomware Mass File Modification Detected",
            severity=Severity.CRITICAL,
            asset_tier=AssetTier.TIER_1
        )
        inc = self.correlator.on_new_alert(fim_alert)

        self.assertIn("Impact", inc.mitre_tactics)
        self.assertEqual(inc.highest_alert_severity, Severity.CRITICAL)

    def test_honeypot_hit_rule(self):
        """Rule 5: Honeypot hit generates high-fidelity reconnaissance alert."""
        now = datetime.now(timezone.utc)
        honey_alert = Alert(
            alert_id="TEST-HONEY-1",
            timestamp=now,
            source="honeypot",
            type="HONEYPOT_PROBE",
            host="DMZ-HONEYPOT-01",
            user="root",
            src_ip="198.51.100.77",
            rule_name="SSH Honeypot Connection Probe",
            severity=Severity.HIGH,
            asset_tier=AssetTier.TIER_3
        )
        inc = self.correlator.on_new_alert(honey_alert)

        self.assertIn("Reconnaissance", inc.mitre_tactics)
        self.assertEqual(inc.primary_hostname, "DMZ-HONEYPOT-01")


if __name__ == "__main__":
    unittest.main()
