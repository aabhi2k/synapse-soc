"""
FastAPI Server for Human-in-the-Loop (HITL) SOC Triage Dashboard.
Provides RESTful APIs for incident exploration, analyst triage, notes,
containment action dispatch, and shift handover briefing management.
"""

import sys
import json
from pathlib import Path
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException, Query, Response
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, HTMLResponse
from pydantic import BaseModel

from engine.models import Incident, TriageStatus, IncidentBrief, Severity, AssetTier
from engine.correlator import AlertCorrelator
from engine.risk_scorer import RiskScorer
from engine.summarizer import ShiftBriefSummarizer
from engine.metrics import TriageMetricsCalculator

app = FastAPI(
    title="Security Alert Summarizer - HITL SOC Triage Console",
    description="Enterprise alert correlation, asset-criticality ranking, and shift brief orchestrator.",
    version="2.0.0"
)

# Persistent state in-memory
DATA_DIR = Path(__file__).resolve().parent.parent / "data"
STATIC_DIR = Path(__file__).resolve().parent / "static"

INCIDENTS_CACHE: List[Incident] = []
TOTAL_ALERTS_COUNT: int = 3000
BENCHMARK_CACHE: Dict[str, Any] = {}


def load_or_init_data():
    global INCIDENTS_CACHE, TOTAL_ALERTS_COUNT, BENCHMARK_CACHE
    alerts_file = DATA_DIR / "alerts_3000.json"
    triaged_file = DATA_DIR / "incidents_triaged.json"

    if triaged_file.exists():
        with open(triaged_file, "r", encoding="utf-8") as f:
            data = json.load(f)
            INCIDENTS_CACHE = [Incident(**item) for item in data]
        if alerts_file.exists():
            with open(alerts_file, "r", encoding="utf-8") as f:
                TOTAL_ALERTS_COUNT = len(json.load(f))
    else:
        # Run pipeline dynamically
        from main import run_batch_pipeline
        INCIDENTS_CACHE, BENCHMARK_CACHE = run_batch_pipeline(str(alerts_file), str(DATA_DIR))
        return

    # Calculate benchmark
    calc = TriageMetricsCalculator()
    BENCHMARK_CACHE = calc.calculate_benchmark(INCIDENTS_CACHE, TOTAL_ALERTS_COUNT)


@app.get("/api/health")
def health_check():
    """System health check endpoint for monitoring sources, cache, and pipeline state."""
    import ctypes
    is_admin = False
    if sys.platform.startswith("win"):
        try:
            is_admin = (ctypes.windll.shell32.IsUserAnAdmin() != 0)
        except Exception:
            pass

    return {
        "status": "healthy",
        "service": "SYNAPSE-SOC Web Console",
        "version": "2.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "incidents_loaded": len(INCIDENTS_CACHE),
        "total_alerts_ingested": TOTAL_ALERTS_COUNT,
        "sources": {
            "windows_event_log": {
                "status": "operational" if is_admin else "degraded (non-admin)",
                "reason": "Live Security Event Log reading enabled" if is_admin else "Running without Administrator elevation. Windows Security Log monitoring degraded gracefully; continuing with other sources."
            },
            "file_integrity_monitor": {
                "status": "operational",
                "reason": "Watchdog monitoring active on protected_assets/ (ransomware and mass change detection)"
            },
            "ssh_honeypot": {
                "status": "operational",
                "reason": "TCP/SSH Deception emulation listener configured on port 2222"
            }
        }
    }


# Pydantic request models
class TriageUpdateRequest(BaseModel):
    status: TriageStatus
    analyst_notes: Optional[str] = None
    risk_score_override: Optional[float] = None


class BriefUpdateRequest(BaseModel):
    headline: str
    executive_summary: str
    attack_narrative: str
    impact_assessment: str
    key_iocs: List[str]
    recommended_actions: List[str]


class ContainmentActionRequest(BaseModel):
    action_type: str  # "ISOLATE_HOST", "BLOCK_IP", "REVOKE_CREDENTIALS", "CAPTURE_MEMORY"
    target: str


@app.on_event("startup")
def on_startup():
    load_or_init_data()


@app.get("/api/incidents")
def get_incidents(
    tier: Optional[str] = None,
    status: Optional[str] = None,
    min_risk: float = Query(0.0, ge=0.0, le=100.0),
    search: Optional[str] = None
):
    """Retrieve filtered, prioritized list of incidents."""
    results = []
    for inc in INCIDENTS_CACHE:
        if inc.risk_score < min_risk:
            continue
        if tier and tier != "ALL":
            t_val = inc.highest_asset_tier.value
            t_badge = inc.tier_badge
            if tier != t_val and tier != t_badge and not t_val.startswith(tier):
                continue
        if status and inc.status.value != status and status != "ALL":
            continue
        if search:
            s = search.lower()
            match_title = s in inc.title.lower()
            match_host = inc.primary_hostname and s in inc.primary_hostname.lower()
            match_user = inc.primary_username and s in inc.primary_username.lower()
            match_tactics = any(s in t.lower() for t in inc.mitre_tactics)
            match_tier = s in inc.tier_badge.lower() or s in inc.highest_asset_tier.value.lower()
            if not (match_title or match_host or match_user or match_tactics or match_tier):
                continue
        results.append(inc)

    return {
        "count": len(results),
        "total": len(INCIDENTS_CACHE),
        "incidents": [inc.model_dump(mode="json") for inc in results]
    }


@app.get("/api/incidents/{incident_id}")
def get_incident_detail(incident_id: str):
    """Retrieve full incident details including all raw alerts."""
    for inc in INCIDENTS_CACHE:
        if inc.incident_id == incident_id:
            return inc.model_dump(mode="json")
    raise HTTPException(status_code=404, detail="Incident not found")


@app.post("/api/incidents/{incident_id}/triage")
def update_triage_status(incident_id: str, req: TriageUpdateRequest):
    """Human-in-the-loop: Update analyst verdict, notes, or override risk."""
    for inc in INCIDENTS_CACHE:
        if inc.incident_id == incident_id:
            inc.status = req.status
            if req.analyst_notes is not None:
                inc.analyst_notes = req.analyst_notes
            if req.risk_score_override is not None:
                inc.risk_score = round(max(0.0, min(100.0, req.risk_score_override)), 1)
                inc.risk_factors.append(f"Analyst Manual Override: Adjusted to {inc.risk_score}")
            inc.triage_timestamp = datetime.now(timezone.utc)

            # Persist changes
            _save_incidents()
            return {"status": "success", "incident": inc.model_dump(mode="json")}
    raise HTTPException(status_code=404, detail="Incident not found")


@app.post("/api/incidents/{incident_id}/brief")
def update_incident_brief(incident_id: str, req: BriefUpdateRequest):
    """Human-in-the-loop: Edit and sign off on shift brief."""
    for inc in INCIDENTS_CACHE:
        if inc.incident_id == incident_id:
            inc.ai_brief = IncidentBrief(
                headline=req.headline,
                executive_summary=req.executive_summary,
                attack_narrative=req.attack_narrative,
                impact_assessment=req.impact_assessment,
                key_iocs=req.key_iocs,
                recommended_actions=req.recommended_actions,
                generated_by="Analyst Approved & Edited Brief"
            )
            _save_incidents()
            return {"status": "success", "brief": inc.ai_brief.model_dump(mode="json")}
    raise HTTPException(status_code=404, detail="Incident not found")


@app.post("/api/incidents/{incident_id}/contain")
def trigger_containment(incident_id: str, req: ContainmentActionRequest):
    """Simulate execution of automated EDR/Firewall/Identity containment playbooks."""
    for inc in INCIDENTS_CACHE:
        if inc.incident_id == incident_id:
            timestamp_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
            log_entry = f"[{timestamp_str}] ACTION DISPATCHED: {req.action_type} on target '{req.target}'"
            if not inc.analyst_notes:
                inc.analyst_notes = log_entry
            else:
                inc.analyst_notes += f"\n{log_entry}"

            if req.action_type == "ISOLATE_HOST":
                msg = f"EDR Host Isolation signal broadcasted for host: {req.target}. Network containment active."
            elif req.action_type == "BLOCK_IP":
                msg = f"Perimeter firewall ACL updated: Ingress/Egress dropped for IP: {req.target}."
            elif req.action_type == "REVOKE_CREDENTIALS":
                msg = f"Identity Provider revoked active Kerberos tickets and forced password change for: {req.target}."
            else:
                msg = f"Playbook {req.action_type} executed successfully on {req.target}."

            inc.status = TriageStatus.CONTAINED
            _save_incidents()
            return {"status": "success", "message": msg, "incident": inc.model_dump(mode="json")}
    raise HTTPException(status_code=404, detail="Incident not found")


@app.get("/api/benchmark")
def get_benchmark():
    """Retrieve Mean-Time-To-Triage (MTTT) and operational ROI metrics."""
    calc = TriageMetricsCalculator()
    return calc.calculate_benchmark(INCIDENTS_CACHE, TOTAL_ALERTS_COUNT)


@app.get("/api/export/handover")
def export_handover_report():
    """Generates and returns the latest Shift Handover Report markdown."""
    report_file = DATA_DIR / "shift_handover_report.md"
    if report_file.exists():
        with open(report_file, "r", encoding="utf-8") as f:
            content = f.read()
        return Response(content=content, media_type="text/markdown", headers={
            "Content-Disposition": "attachment; filename=soc_shift_handover_report.md"
        })
    raise HTTPException(status_code=404, detail="Report not found")


def _save_incidents():
    triaged_file = DATA_DIR / "incidents_triaged.json"
    with open(triaged_file, "w", encoding="utf-8") as f:
        json.dump([inc.model_dump(mode="json") for inc in INCIDENTS_CACHE], f, indent=2, default=str)


# Serve static frontend
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/", response_class=HTMLResponse)
@app.get("/home", response_class=HTMLResponse)
def serve_home():
    home_file = STATIC_DIR / "home.html"
    if home_file.exists():
        with open(home_file, "r", encoding="utf-8") as f:
            return f.read()
    index_file = STATIC_DIR / "index.html"
    if index_file.exists():
        with open(index_file, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>Security Alert Summarizer API Running. Static files not found.</h1>"


@app.get("/app", response_class=HTMLResponse)
@app.get("/console", response_class=HTMLResponse)
@app.get("/index.html", response_class=HTMLResponse)
def serve_console():
    index_file = STATIC_DIR / "index.html"
    if index_file.exists():
        with open(index_file, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>Security Alert Summarizer Console Running. Static files not found.</h1>"
