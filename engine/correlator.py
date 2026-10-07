"""
Graph-Based Incident Correlation Engine.
Transforms thousands of unlinked alerts into cohesive, entity-linked security incidents
using NetworkX bipartite/entity clustering and temporal sliding windows.
"""

from typing import List, Dict, Any, Set
from datetime import datetime, timezone, timedelta
from collections import defaultdict
import networkx as nx

from engine.models import Alert, Incident, Severity, AssetTier, TriageStatus


class AlertCorrelator:
    def __init__(self, time_window_hours: float = 6.0):
        self.time_window = timedelta(hours=time_window_hours)

    def correlate_alerts(self, alerts_data: List[Dict[str, Any]]) -> List[Incident]:
        """
        Main pipeline:
        1. Ingests raw alert dicts and parses into Alert models.
        2. Aggregates repetitive low-level noise signatures (e.g., external port scans, spray).
        3. Constructs an Entity Graph across remaining alerts (Host, User, Source IP, Dest IP, C2).
        4. Extracts connected components as candidate Incidents.
        5. Builds rich Incident objects with metadata, timeline, and entity maps.
        """
        # Parse into typed Alert objects
        alerts: List[Alert] = []
        for raw in alerts_data:
            ts = datetime.fromisoformat(raw["timestamp"])
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)

            alert = Alert(
                alert_id=raw["alert_id"],
                timestamp=ts,
                rule_name=raw["rule_name"],
                severity=Severity(raw["severity"]),
                source_ip=raw.get("source_ip"),
                destination_ip=raw.get("destination_ip"),
                hostname=raw.get("hostname"),
                username=raw.get("username"),
                process_name=raw.get("process_name"),
                command_line=raw.get("command_line"),
                parent_process=raw.get("parent_process"),
                mitre_tactic=raw.get("mitre_tactic"),
                mitre_technique_id=raw.get("mitre_technique_id"),
                mitre_technique_name=raw.get("mitre_technique_name"),
                asset_tier=AssetTier(raw.get("asset_tier", "Tier 2 (Internal Business)")),
                asset_criticality_score=float(raw.get("asset_criticality_score", 5.0)),
                business_unit=raw.get("business_unit"),
                ground_truth_label=raw.get("ground_truth_label"),
                raw_payload=raw
            )
            alerts.append(alert)

        # Sort chronologically
        alerts.sort(key=lambda a: a.timestamp)

        # Step 1: Pre-cluster massive noise buckets (e.g. Scanners, Spraying, SCCM)
        # to prevent giant hairball graphs and preserve analytical clarity
        clustered_groups: List[List[Alert]] = []
        noise_keyed_groups: Dict[str, List[Alert]] = defaultdict(list)
        investigative_alerts: List[Alert] = []

        for a in alerts:
            # Check if this alert belongs to high-volume generic noise profiles
            is_generic_scan = (a.rule_name.startswith("Inbound TCP Port Scan") and a.hostname == "DMZ-EDGE-FW")
            is_generic_spray = (a.rule_name.startswith("VPN Authentication Failure") and a.hostname == "DMZ-EDGE-FW")
            is_sccm_admin = (a.username == "CORP\\svc_sccm_deploy" and a.parent_process == "CcmExec.exe")
            is_dev_docker = (a.hostname == "DEV-KUBE-NODE-03" and a.process_name == "dockerd")

            if is_generic_scan:
                noise_keyed_groups["NOISE_PERIMETER_SCAN"].append(a)
            elif is_generic_spray:
                noise_keyed_groups["NOISE_VPN_PASSWORD_SPRAY"].append(a)
            elif is_sccm_admin:
                noise_keyed_groups["NOISE_SCCM_PATCH_JOB"].append(a)
            elif is_dev_docker:
                noise_keyed_groups["NOISE_DEV_CONTAINER_TEST"].append(a)
            else:
                investigative_alerts.append(a)

        # Add noise clusters as their own discrete grouped incidents
        for group in noise_keyed_groups.values():
            if group:
                clustered_groups.append(group)

        # Step 2: Build Entity Graph for investigative alerts
        # Nodes: Alert IDs and Entity identifiers (HOST:<name>, USER:<name>, IP:<ip>)
        G = nx.Graph()
        alert_map: Dict[str, Alert] = {a.alert_id: a for a in investigative_alerts}

        for a in investigative_alerts:
            G.add_node(a.alert_id, node_type="alert")

            # Entity pivots
            if a.hostname:
                host_node = f"HOST:{a.hostname.upper()}"
                G.add_node(host_node, node_type="host")
                G.add_edge(a.alert_id, host_node)

            if a.username and a.username not in ["NT AUTHORITY\\SYSTEM", "SYSTEM"]:
                user_node = f"USER:{a.username.lower()}"
                G.add_node(user_node, node_type="user")
                G.add_edge(a.alert_id, user_node)

            if a.source_ip and not a.source_ip.startswith("10.") and not a.source_ip.startswith("172."):
                ip_node = f"EXT_IP:{a.source_ip}"
                G.add_node(ip_node, node_type="external_ip")
                G.add_edge(a.alert_id, ip_node)

            if a.destination_ip and not a.destination_ip.startswith("10.") and not a.destination_ip.startswith("172."):
                ip_node = f"EXT_IP:{a.destination_ip}"
                G.add_node(ip_node, node_type="external_ip")
                G.add_edge(a.alert_id, ip_node)

        # Step 3: Extract Connected Components from Entity Graph
        connected_subgraphs = list(nx.connected_components(G))
        for comp in connected_subgraphs:
            comp_alerts = [alert_map[node_id] for node_id in comp if node_id in alert_map]
            if not comp_alerts:
                continue

            # Check temporal window: if alerts within component span > time_window, split if discontinuous
            comp_alerts.sort(key=lambda a: a.timestamp)
            current_batch = [comp_alerts[0]]

            for next_alert in comp_alerts[1:]:
                if (next_alert.timestamp - current_batch[-1].timestamp) <= self.time_window:
                    current_batch.append(next_alert)
                else:
                    clustered_groups.append(current_batch)
                    current_batch = [next_alert]
            if current_batch:
                clustered_groups.append(current_batch)

        # Step 4: Convert alert clusters into structured Incidents
        incidents: List[Incident] = []
        for idx, group_alerts in enumerate(clustered_groups, start=1):
            incident = self._build_incident_object(f"INC-{idx:04d}", group_alerts)
            incidents.append(incident)

        return incidents

    def _build_incident_object(self, incident_id: str, alerts: List[Alert]) -> Incident:
        alerts.sort(key=lambda a: a.timestamp)
        first_seen = alerts[0].timestamp
        last_seen = alerts[-1].timestamp
        duration = max(0.0, (last_seen - first_seen).total_seconds() / 60.0)

        # Aggregate entities
        hosts: Set[str] = set()
        users: Set[str] = set()
        ips: Set[str] = set()
        processes: Set[str] = set()
        mitre_tactics_set: Set[str] = set()
        mitre_techniques_map: Dict[str, str] = {}

        max_crit = 1.0
        tier_hierarchy = {
            AssetTier.TIER_0: 4,
            AssetTier.TIER_1: 3,
            AssetTier.TIER_2: 2,
            AssetTier.TIER_3: 1
        }
        highest_tier = AssetTier.TIER_3
        current_tier_rank = 0

        severity_rank = {
            Severity.INFORMATIONAL: 1,
            Severity.LOW: 2,
            Severity.MEDIUM: 3,
            Severity.HIGH: 4,
            Severity.CRITICAL: 5
        }
        highest_sev = Severity.INFORMATIONAL

        for a in alerts:
            if a.hostname:
                hosts.add(a.hostname)
            if a.username:
                users.add(a.username)
            if a.source_ip:
                ips.add(a.source_ip)
            if a.destination_ip:
                ips.add(a.destination_ip)
            if a.process_name:
                processes.add(a.process_name)

            if a.mitre_tactic:
                mitre_tactics_set.add(a.mitre_tactic)
            if a.mitre_technique_id and a.mitre_technique_name:
                mitre_techniques_map[a.mitre_technique_id] = a.mitre_technique_name

            if a.asset_criticality_score > max_crit:
                max_crit = a.asset_criticality_score

            rank = tier_hierarchy.get(a.asset_tier, 1)
            if rank > current_tier_rank:
                current_tier_rank = rank
                highest_tier = a.asset_tier

            if severity_rank.get(a.severity, 1) > severity_rank.get(highest_sev, 1):
                highest_sev = a.severity

        # Generate descriptive incident title
        primary_host = next(iter(hosts)) if hosts else "Unknown Host"
        primary_user = next(iter(users)) if users else "System/Unknown"

        # Check for characteristic attack patterns
        tactics_list = list(mitre_tactics_set)
        if "Lateral Movement" in mitre_tactics_set and "Credential Access" in mitre_tactics_set:
            title = f"CRITICAL: Active Domain Compromise & Lateral Movement targeting {primary_host}"
        elif "Exploit Public-Facing Application" in [t for t in mitre_techniques_map.values()]:
            title = f"HIGH: External Web Application Exploitation & Exfiltration ({primary_host})"
        elif "Exfiltration Over Physical Medium: USB" in [t for t in mitre_techniques_map.values()]:
            title = f"MED: Insider Threat Data Exfiltration via Removable Media ({primary_user})"
        elif any("Port Scan" in a.rule_name for a in alerts):
            title = f"INFO: Aggregated Perimeter Reconnaissance & Port Scanning ({len(alerts)} alerts)"
        elif any("Password Spray" in a.rule_name for a in alerts):
            title = f"LOW: Edge VPN Password Spraying Activity ({len(alerts)} attempts)"
        elif any("SCCM" in a.rule_name for a in alerts):
            title = f"INFO: Authorized Central Patch Management (SCCM Automation)"
        elif any("Container" in a.rule_name for a in alerts):
            title = f"LOW: Routine Containerized CI/CD Build Activity ({primary_host})"
        else:
            title = f"Security Event Cluster: {alerts[0].rule_name} on {primary_host}"

        techniques_formatted = [{"id": k, "name": v} for k, v in mitre_techniques_map.items()]

        return Incident(
            incident_id=incident_id,
            title=title,
            alert_count=len(alerts),
            alerts=alerts,
            created_at=datetime.now(timezone.utc),
            first_seen=first_seen,
            last_seen=last_seen,
            duration_minutes=round(duration, 1),
            primary_hostname=primary_host,
            primary_username=primary_user,
            entities={
                "hosts": sorted(list(hosts)),
                "users": sorted(list(users)),
                "ips": sorted(list(ips)),
                "processes": sorted(list(processes))
            },
            highest_asset_tier=highest_tier,
            max_asset_criticality=round(max_crit, 1),
            highest_alert_severity=highest_sev,
            mitre_tactics=sorted(tactics_list),
            mitre_techniques=techniques_formatted,
            kill_chain_stages_covered=len(mitre_tactics_set),
            status=TriageStatus.PENDING_TRIAGE
        )
