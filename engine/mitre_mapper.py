"""
MITRE ATT&CK Mapping, Kill-Chain Taxonomy & Progression Analyzer.
"""

from typing import List, Dict, Tuple, Optional

# Canonical MITRE Enterprise ATT&CK tactics ordered by cyber kill-chain progression
MITRE_TACTIC_ORDER = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact"
]

TACTIC_WEIGHTS = {
    "Reconnaissance": 1.0,
    "Resource Development": 1.0,
    "Initial Access": 2.5,
    "Execution": 3.0,
    "Persistence": 3.5,
    "Privilege Escalation": 4.0,
    "Defense Evasion": 4.0,
    "Credential Access": 5.0,
    "Discovery": 2.0,
    "Lateral Movement": 5.5,
    "Collection": 3.5,
    "Command and Control": 4.5,
    "Exfiltration": 5.5,
    "Impact": 6.0
}

# Known MITRE Techniques reference database
TECHNIQUE_CATALOG = {
    "T1566.001": {"tactic": "Initial Access", "name": "Spearphishing Attachment", "crit": "High"},
    "T1190": {"tactic": "Initial Access", "name": "Exploit Public-Facing Application", "crit": "High"},
    "T1059.001": {"tactic": "Execution", "name": "PowerShell Execution", "crit": "Medium"},
    "T1059.004": {"tactic": "Execution", "name": "Unix Shell Scripting", "crit": "Medium"},
    "T1547.001": {"tactic": "Persistence", "name": "Registry Run Keys / Startup Folder", "crit": "Medium"},
    "T1068": {"tactic": "Privilege Escalation", "name": "Exploitation for Privilege Escalation", "crit": "High"},
    "T1562.001": {"tactic": "Defense Evasion", "name": "Impair Defenses: Disable Tools", "crit": "Critical"},
    "T1564.004": {"tactic": "Defense Evasion", "name": "Hide Artifacts: NTFS File Attributes", "crit": "Low"},
    "T1003.001": {"tactic": "Credential Access", "name": "OS Credential Dumping: LSASS Memory", "crit": "Critical"},
    "T1110.003": {"tactic": "Credential Access", "name": "Brute Force: Password Spraying", "crit": "Low"},
    "T1046": {"tactic": "Discovery", "name": "Network Service Discovery", "crit": "Low"},
    "T1021.002": {"tactic": "Lateral Movement", "name": "SMB/Windows Admin Shares (PsExec)", "crit": "Critical"},
    "T1047": {"tactic": "Execution", "name": "Windows Management Instrumentation (WMI)", "crit": "High"},
    "T1005": {"tactic": "Collection", "name": "Data from Local System", "crit": "Medium"},
    "T1039": {"tactic": "Collection", "name": "Data from Network Shared Drive", "crit": "Medium"},
    "T1071.001": {"tactic": "Command and Control", "name": "Application Layer Protocol: Web", "crit": "Critical"},
    "T1048.003": {"tactic": "Exfiltration", "name": "Exfiltration to Cloud Storage", "crit": "Critical"},
    "T1052.001": {"tactic": "Exfiltration", "name": "Exfiltration Over Physical Medium (USB)", "crit": "High"},
    "T1486": {"tactic": "Impact", "name": "Data Encrypted for Impact (Ransomware)", "crit": "Critical"}
}


def get_tactic_stage_index(tactic_name: str) -> int:
    """Returns the zero-indexed chronological stage of the tactic in the kill chain."""
    try:
        return MITRE_TACTIC_ORDER.index(tactic_name)
    except ValueError:
        return 0


def analyze_kill_chain_progression(tactics: List[str]) -> Tuple[int, float, List[str]]:
    """
    Evaluates how far an attacker has advanced along the MITRE ATT&CK kill-chain.
    Returns:
      - unique_stages_count: number of distinct kill-chain phases reached
      - progression_bonus: numeric score multiplier (up to 30 points)
      - stage_sequence: ordered list of tactics observed
    """
    if not tactics:
        return 0, 0.0, []

    # Filter and sort unique tactics by kill chain order
    unique_tactics = set(tactics)
    ordered_observed = [t for t in MITRE_TACTIC_ORDER if t in unique_tactics]
    stage_count = len(ordered_observed)

    # Multi-stage detection: An attack that hits Initial Access -> Lateral Movement -> C2
    # represents a dangerous advanced multi-stage breach.
    has_initial_access = "Initial Access" in unique_tactics
    has_execution = "Execution" in unique_tactics
    has_cred_access = "Credential Access" in unique_tactics
    has_lateral = "Lateral Movement" in unique_tactics
    has_c2_or_exfil = bool(unique_tactics.intersection({"Command and Control", "Exfiltration", "Impact"}))

    bonus = stage_count * 3.5  # Base coverage points

    # Critical progression milestones
    if has_cred_access and has_initial_access:
        bonus += 10.0  # Post-brute login / active credential compromise
    if has_cred_access and has_lateral:
        bonus += 12.0  # High confidence active breach
    if has_lateral and has_c2_or_exfil:
        bonus += 15.0  # Advanced compromise in flight
    if has_initial_access and has_c2_or_exfil:
        bonus += 10.0  # Full life-cycle breach

    return stage_count, min(bonus, 35.0), ordered_observed
