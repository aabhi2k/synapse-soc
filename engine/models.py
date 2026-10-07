"""
Data models for the Security Alert Summarizer & Incident Correlation Engine.
"""

from enum import Enum
from typing import List, Dict, Optional, Any
from datetime import datetime
from pydantic import BaseModel, Field


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


class TriageStatus(str, Enum):
    PENDING_TRIAGE = "Pending Review"
    CONFIRMED_INCIDENT = "Confirmed Incident (Escalate)"
    FALSE_POSITIVE = "False Positive (Suppressed)"
    BENIGN_AUTHORIZED = "Benign Authorized Activity"
    CONTAINED = "Contained & Resolved"


class Alert(BaseModel):
    alert_id: str
    timestamp: datetime
    rule_name: str
    severity: Severity
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    hostname: Optional[str] = None
    username: Optional[str] = None
    process_name: Optional[str] = None
    command_line: Optional[str] = None
    parent_process: Optional[str] = None
    mitre_tactic: Optional[str] = None
    mitre_technique_id: Optional[str] = None
    mitre_technique_name: Optional[str] = None
    asset_tier: AssetTier = AssetTier.TIER_2
    asset_criticality_score: float = 5.0  # 1.0 to 10.0 scale
    business_unit: Optional[str] = None
    ground_truth_label: Optional[str] = None  # Benchmark / ground truth campaign name
    raw_payload: Optional[Dict[str, Any]] = None


class IncidentBrief(BaseModel):
    headline: str
    executive_summary: str
    attack_narrative: str
    key_iocs: List[str] = Field(default_factory=list)
    impact_assessment: str
    recommended_actions: List[str] = Field(default_factory=list)
    generated_by: str = "Deterministic Security Expert Engine"


class Incident(BaseModel):
    incident_id: str
    title: str
    alert_count: int
    alerts: List[Alert] = Field(default_factory=list)
    created_at: datetime
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

    risk_score: float = 0.0  # Normalized 0 - 100
    risk_rank: int = 0
    risk_factors: List[str] = Field(default_factory=list)

    status: TriageStatus = TriageStatus.PENDING_TRIAGE
    analyst_verdict: Optional[str] = None
    analyst_notes: Optional[str] = None
    triage_timestamp: Optional[datetime] = None

    ai_brief: Optional[IncidentBrief] = None


class TriageBenchmark(BaseModel):
    total_alerts_ingested: int
    total_incidents_created: int
    suppression_ratio_percent: float
    baseline_manual_hours: float
    automated_triage_minutes: float
    mttt_reduction_percent: float
    crown_jewel_incidents_prioritized: int
    top_5_percent_risk_incidents: int
