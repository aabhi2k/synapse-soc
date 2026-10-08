"""
Stateful Live Streaming Correlator.
Processes real-time alerts one-by-one via on_new_alert(alert), maintaining an entity graph
and dynamic sliding time windows to correlate alerts into cohesive live incidents.
"""

from typing import List, Dict, Optional, Set, Any
from datetime import datetime, timezone, timedelta
import networkx as nx
import uuid

from engine.models import Alert, Incident, Severity, AssetTier, TriageStatus
from engine.detection_rules import DetectionRuleEngine
from engine.risk_scorer import RiskScorer
from engine.mitre_mapper import analyze_kill_chain_progression


class StreamingCorrelator:
    def __init__(self, time_window_minutes: float = 15.0):
        self.time_window = timedelta(minutes=time_window_minutes)
        self.active_incidents: Dict[str, Incident] = {}
        self.rule_engine = DetectionRuleEngine(time_window_minutes=time_window_minutes)
        self.scorer = RiskScorer()
        self._incident_seq = 1

    def on_new_alert(self, alert: Alert) -> Incident:
        """
        Processes a single incoming alert in real time:
        1. Evaluates stateful detection rules.
        2. Identifies or creates candidate Incident based on Entity Pivots & Sliding Window.
        3. Dynamically updates kill-chain stages & recalculates CADR risk score.
        4. Re-ranks active incidents.
        """
        # Step 1: Evaluate stateful detection rules
        rule_findings = self.rule_engine.evaluate(alert)
        sev_rank = {Severity.INFORMATIONAL: 1, Severity.LOW: 2, Severity.MEDIUM: 3, Severity.HIGH: 4, Severity.CRITICAL: 5}
        if rule_findings:
            for title, rtype, sev, tactic, tech_id, tech_name in rule_findings:
                # Update alert metadata with highest severity finding
                if sev_rank.get(sev, 1) > sev_rank.get(alert.severity, 1):
                    alert.severity = sev
                if not alert.mitre_tactic or alert.mitre_tactic == "Reconnaissance":
                    alert.mitre_tactic = tactic
                    alert.mitre_technique_id = tech_id
                    alert.mitre_technique_name = tech_name

        # Step 2: Match alert to active incidents
        matched_inc: Optional[Incident] = None
        alert_host = (alert.hostname or alert.host or "").upper()
        alert_user = (alert.username or alert.user or "").lower()
        alert_ip = alert.source_ip or alert.src_ip

        for inc_id, inc in self.active_incidents.items():
            # Check temporal window
            time_diff = abs((alert.timestamp - inc.last_seen).total_seconds())
            if time_diff > self.time_window.total_seconds():
                continue

            # Check entity intersections
            hosts = [h.upper() for h in inc.entities.get("hosts", [])]
            users = [u.lower() for u in inc.entities.get("users", []) if u.lower() not in ["system", "nt authority\\system"]]
            ips = inc.entities.get("ips", [])

            host_match = alert_host and alert_host in hosts
            user_match = alert_user and alert_user in users and alert_user != "system"
            ip_match = alert_ip and alert_ip in ips and not alert_ip.startswith("10.") and not alert_ip.startswith("127.")

            if host_match or user_match or ip_match:
                matched_inc = inc
                break

        # Step 3: Append to existing incident or initialize a new incident
        if matched_inc is not None:
            matched_inc.alerts.append(alert)
            matched_inc.alert_count = len(matched_inc.alerts)
            if alert.timestamp > matched_inc.last_seen:
                matched_inc.last_seen = alert.timestamp
            if alert.timestamp < matched_inc.first_seen:
                matched_inc.first_seen = alert.timestamp

            matched_inc.duration_minutes = round(
                max(0.0, (matched_inc.last_seen - matched_inc.first_seen).total_seconds() / 60.0), 1
            )
            self._update_incident_entities_and_mitre(matched_inc, alert)
            target_incident = matched_inc
        else:
            inc_id = f"INC-{self._incident_seq:04d}"
            self._incident_seq += 1

            new_inc = Incident(
                incident_id=inc_id,
                title=f"Incident: {alert.rule_name} on {alert_host or 'Unknown Host'}",
                alert_count=1,
                alerts=[alert],
                created_at=datetime.now(timezone.utc),
                first_seen=alert.timestamp,
                last_seen=alert.timestamp,
                duration_minutes=0.0,
                primary_hostname=alert_host or "Unknown Host",
                primary_username=alert_user or "SYSTEM",
                entities={
                    "hosts": [alert_host] if alert_host else [],
                    "users": [alert_user] if alert_user else [],
                    "ips": [alert_ip] if alert_ip else [],
                    "processes": [alert.process_name] if alert.process_name else []
                },
                highest_asset_tier=alert.asset_tier,
                max_asset_criticality=alert.asset_criticality_score,
                highest_alert_severity=alert.severity,
                mitre_tactics=[alert.mitre_tactic] if alert.mitre_tactic else ["Reconnaissance"],
                mitre_techniques=[{"id": alert.mitre_technique_id, "name": alert.mitre_technique_name}] if alert.mitre_technique_id else [],
                kill_chain_stages_covered=1 if alert.mitre_tactic else 0,
                current_kill_chain_stage=alert.mitre_tactic or "Reconnaissance",
                status=TriageStatus.PENDING_TRIAGE
            )
            self.active_incidents[inc_id] = new_inc
            target_incident = new_inc

        # Step 4: Re-calculate CADR risk scores across active incidents
        all_incs = list(self.active_incidents.values())
        self.scorer.score_and_rank_incidents(all_incs)

        return target_incident

    def _update_incident_entities_and_mitre(self, inc: Incident, a: Alert) -> None:
        """Dynamically updates entity sets, MITRE tactics, and highest asset tier."""
        if a.hostname and a.hostname not in inc.entities.setdefault("hosts", []):
            inc.entities["hosts"].append(a.hostname)
        if a.username and a.username not in inc.entities.setdefault("users", []):
            inc.entities["users"].append(a.username)
        if a.source_ip and a.source_ip not in inc.entities.setdefault("ips", []):
            inc.entities["ips"].append(a.source_ip)
        if a.process_name and a.process_name not in inc.entities.setdefault("processes", []):
            inc.entities["processes"].append(a.process_name)

        if a.mitre_tactic and a.mitre_tactic not in inc.mitre_tactics:
            inc.mitre_tactics.append(a.mitre_tactic)
            inc.current_kill_chain_stage = a.mitre_tactic

        if a.mitre_technique_id and a.mitre_technique_name:
            if not any(t["id"] == a.mitre_technique_id for t in inc.mitre_techniques):
                inc.mitre_techniques.append({"id": a.mitre_technique_id, "name": a.mitre_technique_name})

        inc.kill_chain_stages_covered = len(inc.mitre_tactics)

        # Update highest tier / severity
        tier_order = {AssetTier.TIER_0: 4, AssetTier.TIER_1: 3, AssetTier.TIER_2: 2, AssetTier.TIER_3: 1}
        if tier_order.get(a.asset_tier, 1) > tier_order.get(inc.highest_asset_tier, 1):
            inc.highest_asset_tier = a.asset_tier

        if a.asset_criticality_score > inc.max_asset_criticality:
            inc.max_asset_criticality = a.asset_criticality_score

        sev_order = {Severity.INFORMATIONAL: 1, Severity.LOW: 2, Severity.MEDIUM: 3, Severity.HIGH: 4, Severity.CRITICAL: 5}
        if sev_order.get(a.severity, 1) > sev_order.get(inc.highest_alert_severity, 1):
            inc.highest_alert_severity = a.severity

        # Refine title if high severity attack pattern emerges
        tactics_set = set(inc.mitre_tactics)
        if "Lateral Movement" in tactics_set and "Credential Access" in tactics_set:
            inc.title = f"CRITICAL: Active Domain Compromise & Lateral Movement ({inc.primary_hostname})"
        elif "Impact" in tactics_set or any("MASS_FILE_CHANGE" in al.type for al in inc.alerts if al.type):
            inc.title = f"CRITICAL: Active Ransomware File Encryption Attack ({inc.primary_hostname})"
        elif "Execution" in tactics_set and "Initial Access" in tactics_set:
            inc.title = f"HIGH: Post-Exploitation Execution & Compromise ({inc.primary_hostname})"

    def get_ranked_incidents(self) -> List[Incident]:
        incs = list(self.active_incidents.values())
        return self.scorer.score_and_rank_incidents(incs)
