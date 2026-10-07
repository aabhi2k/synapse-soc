"""
Comprehensive Test Suite for Security Alert Summarizer Pipeline.
"""

import unittest
import sys
import json
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from fastapi.testclient import TestClient
from engine.models import Alert, Incident, Severity, AssetTier, TriageStatus
from engine.correlator import AlertCorrelator
from engine.risk_scorer import RiskScorer
from engine.mitre_mapper import analyze_kill_chain_progression
from engine.summarizer import ShiftBriefSummarizer
from engine.metrics import TriageMetricsCalculator
from web.app import app


class TestSecurityAlertSummarizer(unittest.TestCase):

    def test_dataset_generation_and_integrity(self):
        data_file = Path("data/alerts_3000.json")
        self.assertTrue(data_file.exists(), "Alert dataset file must exist")
        with open(data_file, "r", encoding="utf-8") as f:
            alerts = json.load(f)
        self.assertEqual(len(alerts), 3000, f"Expected 3000 alerts, got {len(alerts)}")
        
        # Check required fields
        sample = alerts[0]
        for key in ["alert_id", "timestamp", "rule_name", "severity", "asset_tier", "asset_criticality_score"]:
            self.assertIn(key, sample, f"Missing key {key} in alert")

    def test_correlator_reduces_noise(self):
        data_file = Path("data/alerts_3000.json")
        with open(data_file, "r", encoding="utf-8") as f:
            raw_alerts = json.load(f)

        correlator = AlertCorrelator(time_window_hours=6.0)
        incidents = correlator.correlate_alerts(raw_alerts)

        self.assertLess(len(incidents), 20, f"Expected < 20 incidents from 3000 alerts, got {len(incidents)}")
        self.assertEqual(sum(inc.alert_count for inc in incidents), 3000, "All 3000 alerts must be accounted for")

    def test_asset_criticality_prioritization(self):
        """Verify that a 40-alert attack on a Domain Controller outranks 1,100 alerts on a DMZ scanner."""
        data_file = Path("data/alerts_3000.json")
        with open(data_file, "r", encoding="utf-8") as f:
            raw_alerts = json.load(f)

        correlator = AlertCorrelator()
        incidents = correlator.correlate_alerts(raw_alerts)

        scorer = RiskScorer()
        ranked = scorer.score_and_rank_incidents(incidents)

        # Top incident must be the Domain Controller takeover (Tier 0)
        top_incident = ranked[0]
        self.assertEqual(top_incident.highest_asset_tier, AssetTier.TIER_0, f"Rank 1 incident should be Tier 0, was {top_incident.highest_asset_tier}")
        self.assertGreaterEqual(top_incident.risk_score, 85.0, f"Top threat risk score should be >= 85.0, was {top_incident.risk_score}")

        # Find the port scan noise cluster (1000+ alerts)
        scanner_inc = next((inc for inc in ranked if inc.alert_count > 500), None)
        self.assertIsNotNone(scanner_inc)
        self.assertLess(scanner_inc.risk_score, 25.0, f"Scanner noise must have low risk score despite high alert count, was {scanner_inc.risk_score}")
        self.assertGreater(scanner_inc.risk_rank, top_incident.risk_rank, "High-volume scanner must rank lower than DC compromise")

    def test_mitre_kill_chain_progression(self):
        tactics = ["Initial Access", "Execution", "Credential Access", "Lateral Movement", "Command and Control"]
        stages, bonus, ordered = analyze_kill_chain_progression(tactics)
        self.assertEqual(stages, 5)
        self.assertGreaterEqual(bonus, 30.0, f"Multi-stage breach must have high bonus, got {bonus}")
        self.assertEqual(ordered[0], "Initial Access")
        self.assertEqual(ordered[-1], "Command and Control")

    def test_mttt_reduction_calculation(self):
        calc = TriageMetricsCalculator(avg_manual_triage_minutes_per_alert=4.0)
        data_file = Path("data/alerts_3000.json")
        with open(data_file, "r", encoding="utf-8") as f:
            raw_alerts = json.load(f)

        correlator = AlertCorrelator()
        incidents = correlator.correlate_alerts(raw_alerts)
        scorer = RiskScorer()
        ranked = scorer.score_and_rank_incidents(incidents)

        benchmark = calc.calculate_benchmark(ranked, len(raw_alerts))
        self.assertEqual(benchmark["baseline_manual_hours"], 200.0)
        self.assertGreaterEqual(benchmark["mttt_reduction_percent"], 95.0, f"Expected MTTT reduction >= 95%, got {benchmark['mttt_reduction_percent']}%")
        self.assertGreaterEqual(benchmark["analyst_speedup_factor"], 100.0, "Expected at least 100x speedup")

    def test_fastapi_endpoints(self):
        from web.app import load_or_init_data
        load_or_init_data()
        with TestClient(app) as client:
            # 0. Health API
            res_health = client.get("/api/health")
            self.assertEqual(res_health.status_code, 200)
            self.assertEqual(res_health.json()["status"], "healthy")
            self.assertIn("sources", res_health.json())

            # 1. Benchmark API
            res = client.get("/api/benchmark")
            self.assertEqual(res.status_code, 200)
            data = res.json()
            self.assertIn("mttt_reduction_percent", data)

            # 2. Incidents List API
            res = client.get("/api/incidents")
            self.assertEqual(res.status_code, 200)
            incidents = res.json()["incidents"]
            self.assertGreater(len(incidents), 0)
            first_id = incidents[0]["incident_id"]

            # 3. Incident Detail API
            res = client.get(f"/api/incidents/{first_id}")
            self.assertEqual(res.status_code, 200)
            self.assertEqual(res.json()["incident_id"], first_id)

            # 4. Human-in-the-Loop Triage Decision update
            res = client.post(f"/api/incidents/{first_id}/triage", json={
                "status": "Confirmed Incident (Escalate)",
                "analyst_notes": "Tier-1 analyst verified Mimikatz memory dump on DC.",
                "risk_score_override": 99.0
            })
            self.assertEqual(res.status_code, 200)
            self.assertEqual(res.json()["incident"]["status"], "Confirmed Incident (Escalate)")
            self.assertEqual(res.json()["incident"]["risk_score"], 99.0)

            # 5. Playbook Containment Action
            res = client.post(f"/api/incidents/{first_id}/contain", json={
                "action_type": "ISOLATE_HOST",
                "target": "DC-CORP-01"
            })
            self.assertEqual(res.status_code, 200)
            self.assertIn("EDR Host Isolation", res.json()["message"])


if __name__ == "__main__":
    unittest.main()
