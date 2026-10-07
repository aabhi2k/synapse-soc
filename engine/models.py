"""
Data models for the Security Alert Summarizer & Incident Correlation Engine.
Implements the Common Alert Schema (source, type, host, user, src_ip, timestamp, severity)
and CADR Enterprise Risk Models.
"""

from enum import Enum
from typing import List, Dict, Optional, Any
from datetime import datetime, timezone
from pydantic import BaseModel, Field, model_validator


class Severity(str, Enum):
    INFORMATIONAL = "Informational"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class AssetTier(str, Enum):
    TIER_0 = "Tier 0 (Crown Jewel)"
    TIER_1 = "Tier 1 (Mission Critical)"
    TIER_2 = "Tier 2 (Internal Business)"
    TIER_3 = "Tier 3 (Dev / Guest / Lab)"

    @property
    def badge(self) -> str:
        """Returns short badge code e.g. T0, T1, T2, T3"""
        if "Tier 0" in self.value:
            return "T0"
        elif "Tier 1" in self.value:
            return "T1"
        elif "Tier 2" in self.value:
            return "T2"
        elif "Tier 3" in self.value:
            return "T3"
        return "T2"

    @property
    def multiplier(self) -> float:
        """CADR Asset Multiplier"""
        if "Tier 0" in self.value:
            return 3.0
        elif "Tier 1" in self.value:
            return 2.0
        elif "Tier 2" in self.value:
            return 1.0
        elif "Tier 3" in self.value:
            return 0.5
        return 1.0


class TriageStatus(str, Enum):
    PENDING_TRIAGE = "Pending Review"
    CONFIRMED_INCIDENT = "Confirmed Incident (Escalate)"
    FALSE_POSITIVE = "False Positive (Suppressed)"
    BENIGN_AUTHORIZED = "Benign Authorized Activity"
    CONTAINED = "Contained & Resolved"


class Alert(BaseModel):
    """
    Common Alert Schema:
    Primary standardized fields: source, type, host, user, src_ip, timestamp, severity.
    Includes backward-compatible aliases for hostname, username, source_ip, rule_name.
    """
    alert_id: str
    timestamp: datetime
    rule_name: str
    severity: Severity = Severity.MEDIUM
    
    # Common standard schema fields
    source: str = "internal"           # e.g., "winevt", "fim", "honeypot", "network", "synthetic"
    type: Optional[str] = None         # normalized attack/event type, e.g. "AUTH_FAILED", "PROCESS_SPAWN", "MASS_FILE_CHANGE"
    host: Optional[str] = None         # standard hostname
    user: Optional[str] = None         # standard username
    src_ip: Optional[str] = None       # standard source IP

    # Extended telemetry fields
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    hostname: Optional[str] = None
    username: Optional[str] = None
    process_name: Optional[str] = None
    command_line: Optional[str] = None
    parent_process: Optional[str] = None
    file_path: Optional[str] = None
    file_extension: Optional[str] = None
    event_id: Optional[int] = None

    # Threat Intelligence & MITRE Context
    mitre_tactic: Optional[str] = None
    mitre_technique_id: Optional[str] = None
    mitre_technique_name: Optional[str] = None
    asset_tier: AssetTier = AssetTier.TIER_2
    asset_criticality_score: float = 5.0  # 1.0 to 10.0 scale
    business_unit: Optional[str] = None
    ground_truth_label: Optional[str] = None
    raw_payload: Optional[Dict[str, Any]] = None

    # IP threat enrichment
    geo_location: Optional[str] = None
    abuse_score: Optional[int] = None

    @model_validator(mode="before")
    @classmethod
    def sync_common_fields(cls, data: Any) -> Any:
        if isinstance(data, dict):
            # Sync host / hostname
            if "host" in data and "hostname" not in data:
                data["hostname"] = data["host"]
            elif "hostname" in data and "host" not in data:
                data["host"] = data["hostname"]

            # Sync user / username
            if "user" in data and "username" not in data:
                data["username"] = data["user"]
            elif "username" in data and "user" not in data:
                data["user"] = data["username"]

            # Sync src_ip / source_ip
            if "src_ip" in data and "source_ip" not in data:
                data["source_ip"] = data["src_ip"]
            elif "source_ip" in data and "src_ip" not in data:
                data["src_ip"] = data["source_ip"]

            # Sync rule_name / type
            if "type" in data and "rule_name" not in data:
                data["rule_name"] = data["type"]
            elif "rule_name" in data and "type" not in data:
                data["type"] = data["rule_name"]

            # Auto-align asset criticality score if default 5.0 and tier is specified
            tier_val = data.get("asset_tier")
            if "asset_criticality_score" not in data or data["asset_criticality_score"] == 5.0:
                if tier_val in [AssetTier.TIER_0, "Tier 0 (Crown Jewel)"]:
                    data["asset_criticality_score"] = 10.0
                elif tier_val in [AssetTier.TIER_1, "Tier 1 (Mission Critical)"]:
                    data["asset_criticality_score"] = 8.0
                elif tier_val in [AssetTier.TIER_3, "Tier 3 (Dev / Guest / Lab)"]:
                    data["asset_criticality_score"] = 2.0

            # Normalize timestamp to UTC datetime if string
            if "timestamp" in data and isinstance(data["timestamp"], str):
                try:
                    ts = datetime.fromisoformat(data["timestamp"].replace("Z", "+00:00"))
                    if ts.tzinfo is None:
                        ts = ts.replace(tzinfo=timezone.utc)
                    data["timestamp"] = ts
                except Exception:
                    data["timestamp"] = datetime.now(timezone.utc)
            elif "timestamp" not in data:
                data["timestamp"] = datetime.now(timezone.utc)
        return data


class IncidentBrief(BaseModel):
    headline: str
    executive_summary: str
    attack_narrative: str
    key_iocs: List[str] = Field(default_factory=list)
    impact_assessment: str
    recommended_actions: List[str] = Field(default_factory=list)
    cited_alert_ids: List[str] = Field(default_factory=list)
    generated_by: str = "Deterministic Security Expert Engine"


class Incident(BaseModel):
    incident_id: str
    title: str
    alert_count: int
    alerts: List[Alert] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    first_seen: datetime
    last_seen: datetime
    duration_minutes: float = 0.0

    primary_hostname: Optional[str] = None
    primary_username: Optional[str] = None
    entities: Dict[str, List[str]] = Field(default_factory=dict)

    highest_asset_tier: AssetTier = AssetTier.TIER_2
    max_asset_criticality: float = 5.0
    highest_alert_severity: Severity = Severity.LOW

    mitre_tactics: List[str] = Field(default_factory=list)
    mitre_techniques: List[Dict[str, str]] = Field(default_factory=list)
    kill_chain_stages_covered: int = 0
    current_kill_chain_stage: str = "Reconnaissance"

    risk_score: float = 0.0  # Normalized 0 - 100
    risk_rank: int = 0
    risk_factors: List[str] = Field(default_factory=list)

    status: TriageStatus = TriageStatus.PENDING_TRIAGE
    analyst_verdict: Optional[str] = None
    analyst_notes: Optional[str] = None
    triage_timestamp: Optional[datetime] = None

    ai_brief: Optional[IncidentBrief] = None

    @property
    def tier_badge(self) -> str:
        return self.highest_asset_tier.badge


class TriageBenchmark(BaseModel):
    total_alerts_ingested: int
    total_incidents_created: int
    suppression_ratio_percent: float
    baseline_manual_hours: float
    automated_triage_minutes: float
    mttt_reduction_percent: float
    crown_jewel_incidents_prioritized: int
    top_5_percent_risk_incidents: int
