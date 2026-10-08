"""
Mean-Time-To-Triage (MTTT) Reduction & SOC Benchmark Calculator.

DESIGN PRINCIPLE – MEASURED vs ASSUMED separation:
  MEASURED: things the pipeline can empirically record (wall-clock time, alert→incident
            compression ratio, fraction of true-attack alerts surfaced in high-priority
            incidents, rank of the first true-attack incident).
  ASSUMED:  analyst minutes per alert / incident.  These vary by team, tool-set and
            alert fidelity.  They come from a config file with cited sources, and are
            reported as a LOW / MEDIUM / HIGH sensitivity table, never as one magic number.

Sources for assumption defaults (config/triage_assumptions.yaml):
  - IBM "Cost of a Data Breach 2023" – mean alert triage time
  - SANS SOC Survey 2022 – average Tier-1 review times per alert and per incident
"""

import os
import time
from typing import List, Dict, Any, Optional

import yaml

from engine.models import Incident, AssetTier, Severity


# ─────────────────────────────────────────────────────────────────────────────
# Default assumptions (used when config file is missing)
# ─────────────────────────────────────────────────────────────────────────────
_DEFAULT_ASSUMPTIONS = {
    "low":    {"minutes_per_raw_alert": 2.0,  "minutes_per_high_incident": 3.0,  "minutes_per_medium_incident": 1.5, "minutes_per_low_incident": 0.25},
    "medium": {"minutes_per_raw_alert": 4.0,  "minutes_per_high_incident": 6.0,  "minutes_per_medium_incident": 3.0, "minutes_per_low_incident": 0.5},
    "high":   {"minutes_per_raw_alert": 10.0, "minutes_per_high_incident": 15.0, "minutes_per_medium_incident": 5.0, "minutes_per_low_incident": 1.0},
}

_CONFIG_PATH = os.path.join(os.path.dirname(__file__), "..", "config", "triage_assumptions.yaml")


class TriageMetricsCalculator:
    """
    Separates MEASURED pipeline metrics from ASSUMED analyst-time estimates.

    Usage:
        calc = TriageMetricsCalculator()
        result = calc.calculate_benchmark(incidents, raw_alerts, pipeline_duration_seconds)

    Backward-compat note:
        The old signature was calculate_benchmark(incidents, total_alerts_int).
        If raw_alerts is an int it is treated as a count (no ground-truth evaluation).
    """

    def __init__(self, config_path: Optional[str] = None):
        cfg_path = config_path or _CONFIG_PATH
        try:
            with open(cfg_path, "r") as f:
                loaded = yaml.safe_load(f) or {}
            self.assumptions = loaded.get("assumptions", _DEFAULT_ASSUMPTIONS)
        except FileNotFoundError:
            self.assumptions = _DEFAULT_ASSUMPTIONS

    # ─────────────────────────────────────────────────────────────────────────
    # Public API
    # ─────────────────────────────────────────────────────────────────────────

    def calculate_benchmark(
        self,
        incidents: List[Incident],
        raw_alerts,                              # List[Alert] or int (back-compat)
        pipeline_duration_seconds: float = 0.0,
    ) -> Dict[str, Any]:
        """
        Main entry point.  Returns a dict with two top-level keys:
          "MEASURED" – empirical numbers from this run
          "ASSUMED"  – sensitivity table keyed by assumption level
        """
        # Back-compat: old callers pass total_raw_alerts as an int
        if isinstance(raw_alerts, int):
            total_alerts = raw_alerts
            alert_list = []
        else:
            alert_list = list(raw_alerts)
            total_alerts = len(alert_list)

        measured = self._compute_measured(incidents, alert_list,
                                          total_alerts, pipeline_duration_seconds)
        assumed  = self._compute_assumed(incidents, alert_list, total_alerts)

        # ── Legacy flat keys so old code that reads benchmark["mttt_reduction_percent"]
        #    still works without crashing (uses the MEDIUM scenario). ──────────────────
        medium = assumed.get("medium", {})
        legacy = {
            "total_alerts":                  total_alerts,
            "total_incidents":               len(incidents),
            "baseline_manual_hours":         round(medium.get("baseline_manual_minutes", 0) / 60, 1),
            "automated_triage_minutes":      round(medium.get("automated_triage_minutes", 0), 1),
            "mttt_reduction_percent":        _extract_pct(medium.get("mttt_reduction_percent", "0%")),
            "analyst_speedup_factor":        _speedup(medium),
            "noise_reduction_ratio_percent": round(
                (1 - len(incidents) / max(1, total_alerts)) * 100, 2),
            "critical_incidents_prioritized": sum(
                1 for i in incidents if i.risk_score >= 75),
            "crown_jewel_threats_isolated":  sum(
                1 for i in incidents if i.highest_asset_tier == AssetTier.TIER_0),
            "top_threat_campaigns_caught":   measured.get("top_threat_campaigns_caught", []),
        }

        return {**legacy, "MEASURED": measured, "ASSUMED": assumed}

    # ─────────────────────────────────────────────────────────────────────────
    # Private helpers
    # ─────────────────────────────────────────────────────────────────────────

    def _compute_measured(self, incidents, alert_list, total_alerts, duration_s):
        """Empirical numbers – no analyst-time assumptions here."""
        # Build quick lookup
        true_attack_ids = {
            a.alert_id for a in alert_list
            if getattr(a, "ground_truth_label", None)
            and a.ground_truth_label != "BENIGN"
        }

        # Rank incidents by risk score (descending)
        ranked = sorted(incidents, key=lambda i: i.risk_score, reverse=True)

        first_true_rank = None
        attacks_in_high = set()
        campaigns = set()

        for rank, inc in enumerate(ranked, start=1):
            inc_has_attack = False
            for a in inc.alerts:
                if a.alert_id in true_attack_ids:
                    inc_has_attack = True
                    if inc.risk_score >= 75.0:
                        attacks_in_high.add(a.alert_id)
                lbl = getattr(a, "ground_truth_label", None)
                if lbl and str(lbl).startswith("CAMPAIGN_"):
                    campaigns.add(lbl)

            if inc_has_attack and first_true_rank is None:
                first_true_rank = rank

        pct_in_high = (len(attacks_in_high) / max(1, len(true_attack_ids))) * 100.0

        return {
            "pipeline_processing_time_seconds": round(duration_s, 3),
            "total_alerts":                     total_alerts,
            "total_incidents":                  len(incidents),
            "alert_to_incident_compression":    f"{total_alerts}→{len(incidents)}",
            "true_attack_alerts_found":         len(true_attack_ids),
            "pct_attacks_in_high_priority_incident": round(pct_in_high, 1),
            "rank_of_first_true_attack_incident": first_true_rank,
            "top_threat_campaigns_caught":      sorted(campaigns),
        }

    def _compute_assumed(self, incidents, alert_list, total_alerts):
        """Sensitivity table over LOW / MEDIUM / HIGH analyst-time assumptions."""
        ranked = sorted(incidents, key=lambda i: i.risk_score, reverse=True)

        # Index of first true-attack alert in raw arrival order (for TTFTP baseline)
        true_attack_ids = {
            a.alert_id for a in alert_list
            if getattr(a, "ground_truth_label", None)
            and a.ground_truth_label != "BENIGN"
        }
        first_attack_arrival_idx = None
        for idx, a in enumerate(alert_list):
            if a.alert_id in true_attack_ids:
                first_attack_arrival_idx = idx
                break

        scenarios = {}
        for level, params in self.assumptions.items():
            mpr  = params["minutes_per_raw_alert"]
            mhi  = params["minutes_per_high_incident"]
            mmi  = params["minutes_per_medium_incident"]
            mli  = params["minutes_per_low_incident"]

            baseline_mins = total_alerts * mpr

            auto_mins = 0.0
            ttftp_auto = None
            for inc in ranked:
                if inc.risk_score >= 75.0:
                    inc_mins = mhi
                elif inc.risk_score >= 45.0:
                    inc_mins = mmi
                else:
                    inc_mins = mli
                auto_mins += inc_mins
                if ttftp_auto is None and any(a.alert_id in true_attack_ids for a in inc.alerts):
                    ttftp_auto = auto_mins

            saved = baseline_mins - auto_mins
            pct   = (saved / baseline_mins * 100) if baseline_mins > 0 else 0.0

            baseline_ttftp = (
                (first_attack_arrival_idx + 1) * mpr
                if first_attack_arrival_idx is not None else None
            )

            scenarios[level] = {
                "assumption_source": (
                    f"{mpr} min/alert (IBM/SANS), "
                    f"{mhi}/{mmi}/{mli} min per H/M/L incident"
                ),
                "baseline_manual_minutes": round(baseline_mins, 1),
                "automated_triage_minutes": round(auto_mins, 1),
                "mttt_reduction_percent": (
                    f"{round(pct, 1)}%  "
                    f"[assuming {mpr}m/raw-alert vs {mhi}/{mmi}/{mli}m/H/M/L-incident]"
                ),
                "baseline_ttftp_minutes": baseline_ttftp,
                "automated_ttftp_minutes": round(ttftp_auto, 2) if ttftp_auto else None,
                "speedup_factor": round(baseline_mins / max(1.0, auto_mins), 1),
            }

        return scenarios


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _extract_pct(s) -> float:
    """Pull the numeric percentage from the annotated string the new code produces."""
    if isinstance(s, (int, float)):
        return float(s)
    try:
        return float(str(s).split("%")[0].strip())
    except (ValueError, IndexError):
        return 0.0


def _speedup(scenario: dict) -> float:
    base = scenario.get("baseline_manual_minutes", 1.0)
    auto = scenario.get("automated_triage_minutes", 1.0)
    return round(base / max(1.0, auto), 1)
