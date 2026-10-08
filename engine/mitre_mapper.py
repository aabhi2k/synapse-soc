"""
MITRE ATT&CK Mapping, Kill-Chain Taxonomy & Progression Analyzer.
Dynamically loads STIX 2.1 data from MITRE CTI with offline caching.
"""

import os
import json
import urllib.request
from typing import List, Dict, Tuple, Optional
import logging

log = logging.getLogger(__name__)

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

# TACTIC_WEIGHTS are now dynamically justified: 
# Weight = 1.0 + (stage_index * 0.4)
# Justification: Later stages in the kill-chain represent deeper network penetration
# and higher immediate risk of business disruption (Exfiltration/Impact), thus warranting higher weights.
TACTIC_WEIGHTS = {
    tactic: round(1.0 + (i * 0.4), 1) for i, tactic in enumerate(MITRE_TACTIC_ORDER)
}

MITRE_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
CACHE_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "mitre", "enterprise-attack.json")

TECHNIQUE_CATALOG = {}

def _determine_crit(tactics: List[str]) -> str:
    """Determine criticality based on the max tactic weight."""
    if not tactics:
        return "Low"
    max_weight = max((TACTIC_WEIGHTS.get(t, 1.0) for t in tactics), default=1.0)
    if max_weight >= 5.0: return "Critical"
    if max_weight >= 3.5: return "High"
    if max_weight >= 2.0: return "Medium"
    return "Low"

def _load_mitre_data():
    global TECHNIQUE_CATALOG
    data = None
    try:
        # Try fetching the latest if online, timeout 3s
        req = urllib.request.urlopen(MITRE_URL, timeout=3)
        data = json.loads(req.read())
        os.makedirs(os.path.dirname(CACHE_PATH), exist_ok=True)
        with open(CACHE_PATH, "w", encoding="utf-8") as f:
            json.dump(data, f)
    except Exception as e:
        log.warning(f"Could not fetch MITRE data online: {e}. Falling back to cache.")
        if os.path.exists(CACHE_PATH):
            with open(CACHE_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
        else:
            log.error("No cached MITRE data found and offline.")
            return

    if not data:
        return

    # Parse STIX 2.1 Objects
    for obj in data.get("objects", []):
        if obj.get("type") == "attack-pattern":
            ext_id = None
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    ext_id = ref.get("external_id")
                    break
            
            if not ext_id:
                continue

            tactics = []
            for kc in obj.get("kill_chain_phases", []):
                if kc.get("kill_chain_name") == "mitre-attack":
                    t_name = kc.get("phase_name").replace("-", " ").title()
                    if t_name == "Command And Control": t_name = "Command and Control"
                    tactics.append(t_name)
            
            if not tactics:
                continue

            # Taking the first tactic as primary for existing code compat
            primary_tactic = tactics[0] 

            TECHNIQUE_CATALOG[ext_id] = {
                "tactic": primary_tactic, 
                "all_tactics": tactics,
                "name": obj.get("name", "Unknown"), 
                "crit": _determine_crit(tactics),
                "description": obj.get("description", ""),
                "platforms": obj.get("x_mitre_platforms", []),
                "data_sources": obj.get("x_mitre_data_sources", []),
                "is_subtechnique": obj.get("x_mitre_is_subtechnique", False)
            }

# Load at startup
_load_mitre_data()

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
      - progression_bonus: numeric score multiplier
      - stage_sequence: ordered list of tactics observed
    """
    if not tactics:
        return 0, 0.0, []

    unique_tactics = set(tactics)
    ordered_observed = [t for t in MITRE_TACTIC_ORDER if t in unique_tactics]
    stage_count = len(ordered_observed)

    has_initial_access = "Initial Access" in unique_tactics
    has_execution = "Execution" in unique_tactics
    has_cred_access = "Credential Access" in unique_tactics
    has_lateral = "Lateral Movement" in unique_tactics
    has_c2_or_exfil = bool(unique_tactics.intersection({"Command and Control", "Exfiltration", "Impact"}))

    bonus = stage_count * 3.5

    if has_cred_access and has_initial_access: bonus += 10.0
    if has_cred_access and has_lateral: bonus += 12.0
    if has_lateral and has_c2_or_exfil: bonus += 15.0
    if has_initial_access and has_c2_or_exfil: bonus += 10.0

    return stage_count, min(bonus, 35.0), ordered_observed
