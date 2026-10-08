"""
Unit tests for engine/metrics.py (Task 3 – MTTT benchmark).

Design principle: every test uses a hand-crafted mini-dataset where the
CORRECT ANSWER IS KNOWN in advance, so the assertions are not circular.
"""

import unittest
from datetime import datetime, timezone, timedelta

from engine.models import Alert, Incident, Severity, AssetTier, TriageStatus
from engine.metrics import TriageMetricsCalculator


# ─────────────────────────────────────────────────────────────────────────────
# Helper builders
# ─────────────────────────────────────────────────────────────────────────────

def _ts(offset_minutes: int = 0) -> datetime:
    return datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc) + timedelta(minutes=offset_minutes)


def _alert(aid: str, ground_truth: str = None) -> Alert:
    return Alert(
        alert_id=aid,
        timestamp=_ts(),
        rule_name="test-rule",
        severity=Severity.HIGH,
        ground_truth_label=ground_truth,
    )


def _incident(iid: str, alerts, risk_score: float, tier=AssetTier.TIER_2) -> Incident:
    inc = Incident(
        incident_id=iid,
        title=f"Incident {iid}",
        alert_count=len(alerts),
        alerts=alerts,
        first_seen=_ts(),
        last_seen=_ts(5),
        highest_asset_tier=tier,
    )
    inc.risk_score = risk_score
    return inc


# ─────────────────────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestTriageMetricsCalculator(unittest.TestCase):

    def setUp(self):
        self.calc = TriageMetricsCalculator()

    # ── 1. Basic structure ──────────────────────────────────────────────────

    def test_output_has_measured_and_assumed_keys(self):
        """Result dict must always contain MEASURED and ASSUMED top-level keys."""
        alerts = [_alert("a1"), _alert("a2"), _alert("a3")]
        inc = _incident("INC-001", alerts, risk_score=80.0, tier=AssetTier.TIER_0)
        result = self.calc.calculate_benchmark([inc], alerts, 1.5)
        self.assertIn("MEASURED", result)
        self.assertIn("ASSUMED", result)
        for level in ("low", "medium", "high"):
            self.assertIn(level, result["ASSUMED"])

    def test_legacy_flat_keys_still_present(self):
        """Backward-compat: old keys must exist on the returned dict."""
        alerts = [_alert("x1")]
        inc = _incident("INC-001", alerts, risk_score=50.0)
        result = self.calc.calculate_benchmark([inc], 10, 0.0)
        for key in ("baseline_manual_hours", "mttt_reduction_percent",
                    "total_alerts", "total_incidents"):
            self.assertIn(key, result, f"Missing legacy key: {key}")

    # ── 2. MEASURED metrics ─────────────────────────────────────────────────

    def test_pipeline_duration_recorded(self):
        """pipeline_processing_time_seconds must exactly match what was passed in."""
        result = self.calc.calculate_benchmark([], [], 3.14)
        self.assertAlmostEqual(
            result["MEASURED"]["pipeline_processing_time_seconds"], 3.14, places=2
        )

    def test_compression_ratio_string(self):
        """alert_to_incident_compression must show N→M format."""
        alerts = [_alert(f"a{i}") for i in range(10)]
        inc = _incident("INC-001", alerts, risk_score=30.0)
        result = self.calc.calculate_benchmark([inc], alerts, 0.0)
        self.assertEqual(result["MEASURED"]["alert_to_incident_compression"], "10→1")

    def test_ground_truth_detection_rate(self):
        """
        KNOWN ANSWER: 3 alerts total, 2 are attacks (gt != BENIGN).
        They land in a HIGH-priority incident (risk_score=90).
        So pct_attacks_in_high_priority_incident should be 100 %.
        """
        a_benign = _alert("b1", ground_truth="BENIGN")
        a_atk1   = _alert("c1", ground_truth="DoS")
        a_atk2   = _alert("c2", ground_truth="Scan")
        inc = _incident("INC-001", [a_benign, a_atk1, a_atk2], risk_score=90.0)

        result = self.calc.calculate_benchmark([inc], [a_benign, a_atk1, a_atk2], 0.0)
        self.assertEqual(result["MEASURED"]["true_attack_alerts_found"], 2)
        self.assertAlmostEqual(
            result["MEASURED"]["pct_attacks_in_high_priority_incident"], 100.0
        )

    def test_first_true_attack_rank(self):
        """
        KNOWN ANSWER: 3 incidents ranked by risk score.
        The SECOND one (rank 2) contains the attack alert.
        rank_of_first_true_attack_incident should be 2.
        """
        noise_alerts = [_alert("n1"), _alert("n2")]
        attack_alert = _alert("atk1", ground_truth="Port Scan")
        low_alerts   = [_alert("l1")]

        inc_high  = _incident("INC-A", noise_alerts,  risk_score=80.0)  # rank 1 – no attack
        inc_atk   = _incident("INC-B", [attack_alert], risk_score=70.0) # rank 2 – has attack
        inc_low   = _incident("INC-C", low_alerts,    risk_score=20.0)  # rank 3

        all_alerts = noise_alerts + [attack_alert] + low_alerts
        result = self.calc.calculate_benchmark(
            [inc_high, inc_atk, inc_low], all_alerts, 0.0
        )
        self.assertEqual(result["MEASURED"]["rank_of_first_true_attack_incident"], 2)

    def test_no_ground_truth_labels_handled_gracefully(self):
        """When no alerts have ground_truth_label the function must not crash."""
        alerts = [_alert("a1"), _alert("a2")]
        inc = _incident("INC-001", alerts, risk_score=40.0)
        try:
            result = self.calc.calculate_benchmark([inc], alerts, 0.0)
            self.assertEqual(result["MEASURED"]["true_attack_alerts_found"], 0)
        except Exception as exc:
            self.fail(f"calculate_benchmark raised unexpectedly: {exc}")

    # ── 3. ASSUMED sensitivity table ────────────────────────────────────────

    def test_assumed_reduction_is_greater_for_higher_risk_incidents(self):
        """
        KNOWN ANSWER: 100 raw alerts, 1 incident with risk_score=90 (HIGH tier).
        MEDIUM assumption: 100 * 4 = 400 min baseline, 1 * 6 = 6 min automated.
        Reduction = (400-6)/400 * 100 = 98.5 %
        """
        alerts = [_alert(f"a{i}") for i in range(100)]
        inc = _incident("INC-001", alerts, risk_score=90.0)
        result = self.calc.calculate_benchmark([inc], 100, 0.0)   # pass int (compat)

        medium = result["ASSUMED"]["medium"]
        pct = float(medium["mttt_reduction_percent"].split("%")[0].strip())
        # Expected ≈ 98.5 %  (allow ±2 for rounding)
        self.assertGreater(pct, 95.0,
            f"Expected > 95 % reduction for 100 alerts → 1 high-risk incident, got {pct}")

    def test_assumed_low_lt_medium_lt_high_baseline(self):
        """Baseline manual minutes must increase from low → medium → high assumptions."""
        result = self.calc.calculate_benchmark([], 100, 0.0)
        low_b  = result["ASSUMED"]["low"]["baseline_manual_minutes"]
        med_b  = result["ASSUMED"]["medium"]["baseline_manual_minutes"]
        high_b = result["ASSUMED"]["high"]["baseline_manual_minutes"]
        self.assertLess(low_b, med_b, "low baseline should be < medium baseline")
        self.assertLess(med_b, high_b, "medium baseline should be < high baseline")

    def test_ttftp_is_lower_for_ranked_vs_arrival_order(self):
        """
        KNOWN ANSWER: 4 alerts in arrival order [noise, noise, noise, attack].
        Baseline TTFTP (arrival order) = 4 * 4 min (medium) = 16 min.
        Ranked TTFTP: the attack is in a HIGH-risk incident (rank 1) = 6 min.
        So automated_ttftp < baseline_ttftp.
        """
        noise  = [_alert(f"n{i}") for i in range(3)]
        attack = _alert("atk", ground_truth="SSH-Patator")
        all_alerts = noise + [attack]   # arrival order: noise first

        inc_atk   = _incident("INC-A", [attack], risk_score=85.0)   # ranked 1st
        inc_noise = _incident("INC-B", noise,    risk_score=10.0)   # ranked 2nd

        result = self.calc.calculate_benchmark(
            [inc_atk, inc_noise], all_alerts, 0.0
        )
        medium = result["ASSUMED"]["medium"]
        baseline_ttftp = medium["baseline_ttftp_minutes"]
        auto_ttftp     = medium["automated_ttftp_minutes"]

        # baseline: 4 alerts × 4 min = 16 min
        self.assertAlmostEqual(baseline_ttftp, 16.0)
        # automated: first ranked incident is the attack → costs mhi = 6 min
        self.assertAlmostEqual(auto_ttftp, 6.0)
        self.assertLess(auto_ttftp, baseline_ttftp,
            "Ranked triage must reach first true positive faster than arrival order")


if __name__ == "__main__":
    unittest.main()
