"""
3-Minute End-to-End Live Attack Simulation Script.
Demonstrates the complete SYNAPSE-SOC event-driven detection lifecycle:
  Stage 1: Inbound SSH Honeypot Recon Probe (T1046)
  Stage 2: Credential Brute Force on Domain Controller DC-CORP-01 (T1110)
  Stage 3: Successful Post-Brute Logon (T1078)
  Stage 4: Privileged Process Spawn & LSASS Credential Dump (T1059, T1003)
  Stage 5: Ransomware Velocity Encryption on Protected Share (T1486)
  Stage 6: Real-time Escalation with Grounded AI Brief
  Stage 7: Human-in-the-loop Containment Action ([Block IP] & [Isolate Host])
"""

import sys
import time
import asyncio
from pathlib import Path
from datetime import datetime, timezone

if sys.platform.startswith("win"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from engine.models import Alert, Severity, AssetTier
from engine.streaming_correlator import StreamingCorrelator
from sources.event_queue import UnifiedEventQueue
from live_dashboard import TerminalDashboard
from notifications.telegram_bot import TelegramResponseBot
from notifications.notifier import IncidentNotifier


async def run_attack_demo():
    print("=================================================================")
    print("  SYNAPSE-SOC: LIVE MULTI-STAGE ATTACK SIMULATION DEMO          ")
    print("=================================================================\n")

    event_queue = UnifiedEventQueue()
    correlator = StreamingCorrelator(time_window_minutes=15.0)
    bot = TelegramResponseBot()
    notifier = IncidentNotifier(bot=bot)

    def status_line(stage: str, desc: str):
        print(f"\n[>>> {stage.upper()} <<<] {desc}")

    # STAGE 1: Recon Probe
    status_line("Stage 1", "Attacker probing edge SSH honeypot from external IP 185.220.101.5")
    a1 = Alert(
        alert_id="HONEY-001",
        timestamp=datetime.now(timezone.utc),
        source="honeypot",
        type="HONEYPOT_PROBE",
        host="DMZ-HONEYPOT-01",
        user="root",
        src_ip="185.220.101.5",
        rule_name="SSH Honeypot Connection Probe from 185.220.101.5",
        severity=Severity.HIGH,
        mitre_tactic="Reconnaissance",
        mitre_technique_id="T1046",
        mitre_technique_name="Network Service Discovery",
        asset_tier=AssetTier.TIER_3,
        asset_criticality_score=2.0
    )
    inc = correlator.on_new_alert(a1)
    print(f"  -> Correlated Incident: {inc.incident_id} | Tier: {inc.tier_badge} | CADR Score: {inc.risk_score} | Stage: {inc.current_kill_chain_stage}")
    await asyncio.sleep(1.0)

    # STAGE 2: Password Brute Force
    status_line("Stage 2", "Adversary launching credential brute-force attack against Domain Controller DC-CORP-01")
    for i in range(5):
        a_bf = Alert(
            alert_id=f"WIN-BF-{i+1:03d}",
            timestamp=datetime.now(timezone.utc),
            source="winevt",
            type="AUTH_FAILED",
            host="DC-CORP-01",
            user="CORP\\Administrator",
            src_ip="185.220.101.5",
            rule_name="Windows Security: Failed Logon Attempt (Event 4625)",
            severity=Severity.MEDIUM,
            mitre_tactic="Credential Access",
            mitre_technique_id="T1110.001",
            mitre_technique_name="Password Guessing",
            asset_tier=AssetTier.TIER_0,
            asset_criticality_score=10.0
        )
        inc = correlator.on_new_alert(a_bf)
        print(f"  [Failed Login #{i+1}] Incident {inc.incident_id} -> CADR Score: {inc.risk_score} [{inc.tier_badge}]")
        await asyncio.sleep(0.4)

    # STAGE 3: Successful Logon
    status_line("Stage 3", "Post-Brute Valid Account Login Succeeded (Event 4624)")
    a_logon = Alert(
        alert_id="WIN-LOGIN-001",
        timestamp=datetime.now(timezone.utc),
        source="winevt",
        type="AUTH_SUCCESS",
        host="DC-CORP-01",
        user="CORP\\Administrator",
        src_ip="185.220.101.5",
        rule_name="Windows Security: Successful Logon (Event 4624)",
        severity=Severity.CRITICAL,
        mitre_tactic="Initial Access",
        mitre_technique_id="T1078",
        mitre_technique_name="Valid Accounts",
        asset_tier=AssetTier.TIER_0,
        asset_criticality_score=10.0
    )
    inc = correlator.on_new_alert(a_logon)
    print(f"  -> Incident {inc.incident_id} Escalated! Tier: {inc.tier_badge} | CADR Score: {inc.risk_score} | Kill-Chain: {', '.join(inc.mitre_tactics)}")
    await notifier.maybe_notify(inc)
    await asyncio.sleep(1.0)

    # STAGE 4: Process Spawn & Credential Dump
    status_line("Stage 4", "PowerShell Execution & LSASS Credential Dumping (mimikatz.exe)")
    a_proc = Alert(
        alert_id="WIN-PROC-001",
        timestamp=datetime.now(timezone.utc),
        source="winevt",
        type="PROCESS_SPAWN",
        host="DC-CORP-01",
        user="CORP\\Administrator",
        src_ip="185.220.101.5",
        process_name="mimikatz.exe",
        command_line="mimikatz.exe privilege::debug sekurlsa::logonpasswords exit",
        parent_process="powershell.exe",
        rule_name="Suspicious Command Execution Detected: mimikatz.exe",
        severity=Severity.CRITICAL,
        mitre_tactic="Credential Access",
        mitre_technique_id="T1003.001",
        mitre_technique_name="OS Credential Dumping",
        asset_tier=AssetTier.TIER_0,
        asset_criticality_score=10.0
    )
    inc = correlator.on_new_alert(a_proc)
    print(f"  -> Incident {inc.incident_id} CADR Score: {inc.risk_score} / 100 (Peak Severity: {inc.highest_alert_severity.value})")
    await asyncio.sleep(1.0)

    # STAGE 5: Mass File Changes (FIM Ransomware)
    status_line("Stage 5", "FIM Watchdog triggers on mass file encryption (.locked extension)")
    a_fim = Alert(
        alert_id="FIM-RANSOM-001",
        timestamp=datetime.now(timezone.utc),
        source="fim",
        type="MASS_FILE_CHANGE",
        host="DC-CORP-01",
        user="SYSTEM",
        src_ip="185.220.101.5",
        file_path="C:\\ProtectedShares\\NTDS.dit.locked",
        file_extension=".locked",
        rule_name="CRITICAL: Ransomware Mass File Modification Detected (25 files/10s)",
        severity=Severity.CRITICAL,
        mitre_tactic="Impact",
        mitre_technique_id="T1486",
        mitre_technique_name="Data Encrypted for Impact",
        asset_tier=AssetTier.TIER_0,
        asset_criticality_score=10.0
    )
    inc = correlator.on_new_alert(a_fim)
    print(f"  -> Incident {inc.incident_id} Hit IMPACT Stage! Final CADR Score: {inc.risk_score} / 100")
    await notifier.maybe_notify(inc)
    await asyncio.sleep(1.0)

    # STAGE 6: Mobile Escalation Summary
    status_line("Stage 6", "Dispatching Grounded AI Handover Brief & Mobile Escalation")
    brief_msg = bot.format_incident_message(inc)
    print("-----------------------------------------------------------------")
    print(brief_msg)
    print("-----------------------------------------------------------------")
    await asyncio.sleep(1.0)

    # STAGE 7: Human-in-the-Loop Containment Execution
    status_line("Stage 7", "Human Analyst Approval Simulation: Authorizing [Block IP] and [Isolate Host]")
    res_block = bot.execute_human_approved_action("BLOCK_IP", "185.220.101.5", inc.incident_id, confirmed=True)
    res_isolate = bot.execute_human_approved_action("ISOLATE_HOST", inc.primary_hostname, inc.incident_id, confirmed=True)

    print(f"  [+] {res_block['message']}")
    print(f"  [+] {res_isolate['message']}")
    print("\n=================================================================")
    print("  DEMO COMPLETED SUCCESSFULLY: FULL ATTACK CHAIN MITIGATED!      ")
    print("=================================================================\n")


if __name__ == "__main__":
    asyncio.run(run_attack_demo())
