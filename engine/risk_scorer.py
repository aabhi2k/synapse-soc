"""
Enterprise Risk & Asset-Criticality Scoring Engine.
Prioritizes incidents based on target asset value, cyber kill-chain progression,
and anomaly indicators rather than naive alert counts.
"""

import math
from typing import List
from engine.models import Incident, Severity, AssetTier
from engine.mitre_mapper import analyze_kill_chain_progression


class RiskScorer:
    def __init__(self):
        self.severity_weights = {
            Severity.CRITICAL: 25.0,
            Severity.HIGH: 18.0,
            Severity.MEDIUM: 10.0,
            Severity.LOW: 4.0,
            Severity.INFORMATIONAL: 1.0
        }

    def score_and_rank_incidents(self, incidents: List[Incident]) -> List[Incident]:
        """
        Calculates composite risk score for each incident and assigns ordinal ranks (1 = highest risk).
        """
        for inc in incidents:
            score, factors = self._calculate_incident_risk(inc)
            inc.risk_score = round(score, 1)
            inc.risk_factors = factors

        # Sort descending by risk score, breaking ties by asset criticality then severity
        incidents.sort(
            key=lambda x: (x.risk_score, x.max_asset_criticality, x.alert_count),
            reverse=True
        )

        # Assign ordinal risk ranks
        for rank, inc in enumerate(incidents, start=1):
            inc.risk_rank = rank

        return incidents

    def _calculate_incident_risk(self, inc: Incident) -> (float, List[str]):
        factors = []

        # 1. Asset Criticality Factor (Up to 40 points)
        # Scaled strictly by CMDB asset criticality score (1.0 - 10.0)
        asset_score = inc.max_asset_criticality * 4.0
        factors.append(f"Asset Impact [{inc.highest_asset_tier.value}]: +{asset_score:.1f} pts (Score: {inc.max_asset_criticality}/10)")

        # 2. Maximum Alert Severity (Up to 25 points)
        sev_score = self.severity_weights.get(inc.highest_alert_severity, 2.0)
        factors.append(f"Peak Severity [{inc.highest_alert_severity.value}]: +{sev_score:.1f} pts")

        # 3. MITRE ATT&CK Kill-Chain Progression (Up to 35 points)
        stage_count, progression_bonus, ordered_tactics = analyze_kill_chain_progression(inc.mitre_tactics)
        if progression_bonus > 0:
            tactics_str = " -> ".join(ordered_tactics[:4]) + ("..." if len(ordered_tactics) > 4 else "")
            factors.append(f"Kill-Chain Advancement ({stage_count} stages: {tactics_str}): +{progression_bonus:.1f} pts")

        # 4. Multi-Entity Lateral Velocity (Up to 10 points)
        velocity_points = 0.0
        host_count = len(inc.entities.get("hosts", []))
        if host_count >= 2:
            velocity_points += 5.0
            factors.append(f"Multi-Host Pivot ({host_count} endpoints traversed): +5.0 pts")

        # Alert volume factor uses log2 to prevent thousands of scanner pings from dominating
        if inc.alert_count > 1:
            log_vol = min(5.0, math.log2(inc.alert_count))
            velocity_points += log_vol

        # 5. Noise & False Positive Mitigation Discounts
        discount = 0.0

        # Pattern A: Authorized SCCM / IT automation
        is_sccm = any("SCCM" in f or "svc_sccm_deploy" in inc.entities.get("users", []) for f in [inc.title])
        if is_sccm:
            discount += 35.0
            factors.append("Authorized IT Management Signature (Whitelisted Admin Service): -35.0 pts")

        # Pattern B: 100% External Port Scanning on Perimeter without internal ingress
        is_perimeter_scan = (
            inc.highest_asset_tier == AssetTier.TIER_3 and
            inc.mitre_tactics == ["Reconnaissance"] and
            inc.highest_alert_severity in [Severity.LOW, Severity.INFORMATIONAL]
        )
        if is_perimeter_scan:
            discount += 28.0
            factors.append("Uncorrelated Edge Perimeter Scan (Zero Internal Penetration): -28.0 pts")

        # Pattern C: External Password Spraying (Repeated failed attempts, no successful logins)
        is_failed_spray = (
            "Password Spraying" in inc.title or
            (len(inc.mitre_tactics) == 1 and inc.mitre_tactics[0] == "Credential Access" and inc.highest_alert_severity == Severity.LOW)
        )
        if is_failed_spray:
            discount += 22.0
            factors.append("Perimeter Password Spraying (Generic External Lockouts): -22.0 pts")

        # Pattern D: Dev / Lab container testing
        is_dev_test = inc.highest_asset_tier == AssetTier.TIER_3 and any("DEV-" in h for h in inc.entities.get("hosts", []))
        if is_dev_test:
            discount += 18.0
            factors.append("Isolated Sandbox / Dev Environment Activity: -18.0 pts")

        # Pattern E: Common AV / Browser Cookie False Positives
        is_av_fp = all(a.rule_name.startswith("Heuristic Detection") for a in inc.alerts)
        if is_av_fp:
            discount += 15.0
            factors.append("Low-Fidelity AV Heuristic Signature (Tracking Cookie / PUA): -15.0 pts")

        raw_total = asset_score + sev_score + progression_bonus + velocity_points - discount
        final_score = max(5.0, min(100.0, raw_total))

        return final_score, factors
