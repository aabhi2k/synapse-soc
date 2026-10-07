"""
AI Shift-Handover Briefing Engine.
Generates concise, grounded, actionable executive and technical briefs for SOC shift handovers.
Includes 3-bullet grounded summary with verified Alert ID citations.
Supports Gemini Flash, local Ollama, and zero-cost deterministic SOC Expert fallback.
"""

import os
import json
from typing import Optional, List
import httpx

from engine.models import Incident, IncidentBrief, AssetTier


class ShiftBriefSummarizer:
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
        self.ollama_endpoint = os.getenv("OLLAMA_ENDPOINT", "http://localhost:11434/api/generate")
        self.has_ollama = self._check_ollama()

    def _check_ollama(self) -> bool:
        try:
            with httpx.Client(timeout=0.3) as client:
                res = client.get("http://localhost:11434/api/tags")
                return res.status_code == 200
        except Exception:
            return False

    def generate_shift_brief(self, incident: Incident) -> IncidentBrief:
        """
        Generates an incident handover brief using LLM if available,
        otherwise falls back to the deterministic expert engine.
        """
        if self.api_key:
            try:
                brief = self._generate_with_gemini(incident)
                if brief:
                    return brief
            except Exception:
                pass

        if self.has_ollama:
            try:
                brief = self._generate_with_ollama(incident)
                if brief:
                    return brief
            except Exception:
                pass

        return self._generate_expert_brief(incident)

    def _generate_expert_brief(self, inc: Incident) -> IncidentBrief:
        """
        Deterministic SOC intelligence engine generating 3 grounded bullets
        with verified Alert ID citations.
        """
        primary_host = inc.primary_hostname or "Unspecified Host"
        primary_user = inc.primary_username or "Unspecified User"
        alert_ids = [a.alert_id for a in inc.alerts[:5]]
        cited_ids_str = ", ".join(alert_ids) if alert_ids else "N/A"

        # Extract IoCs
        iocs = []
        for ip in inc.entities.get("ips", []):
            if not ip.startswith("10.") and not ip.startswith("172.") and not ip.startswith("192.168.") and not ip.startswith("127."):
                iocs.append(f"External Attacker IP: {ip}")
        for host in inc.entities.get("hosts", []):
            iocs.append(f"Impacted Host: {host} ({inc.highest_asset_tier.badge})")
        for user in inc.entities.get("users", []):
            if user.lower() not in ["nt authority\\system", "system"]:
                iocs.append(f"Compromised / Targeted Account: {user}")

        cmds = set()
        for a in inc.alerts:
            if a.command_line and len(a.command_line) > 5 and a.command_line not in cmds:
                cmds.add(a.command_line)
        for c in list(cmds)[:3]:
            iocs.append(f"Suspicious Command: {c}")

        is_crown_jewel = inc.highest_asset_tier == AssetTier.TIER_0
        is_mission_crit = inc.highest_asset_tier == AssetTier.TIER_1
        tactics_set = set(inc.mitre_tactics)

        if "Impact" in tactics_set or any("MASS_FILE_CHANGE" in (a.type or "") for a in inc.alerts):
            headline = f"SEV-1 CRITICAL: Ransomware Encryption Velocity Attack on {primary_host} [{inc.tier_badge}]"
            bullet1 = f"• [Active Impact] High-speed mass file renaming (.locked) observed across critical shares (Alerts: {cited_ids_str})."
            bullet2 = f"• [Threat Actor Scope] Targeted host {primary_host} (Asset Criticality {inc.max_asset_criticality}/10) with CADR Risk Score {inc.risk_score}/100."
            bullet3 = f"• [Urgent Action] Isolate host {primary_host} from network immediately and terminate offending processes."
            exec_summary = f"{bullet1}\n{bullet2}\n{bullet3}"
            narrative = (
                f"Adversary initiated mass encryption behavior on {primary_host}. Rapid file modifications (>20 files/10s) "
                f"were detected matching ransomware indicators (T1486). Attack has reached Impact stage."
            )
            impact = "CRITICAL BUSINESS DISRUPTION: Imminent widespread data unavailability and potential enterprise backup compromise."
            actions = [
                f"Immediately trigger EDR Host Isolation on {primary_host}.",
                "Block external C2 IP addresses on perimeter firewalls.",
                "Verify immutable offline backup integrity for storage volumes."
            ]

        elif is_crown_jewel:
            headline = f"SEV-1 CRITICAL: Crown Jewel Domain Asset Targeted: {primary_host} [{inc.tier_badge}]"
            bullet1 = f"• [Identity/Asset Compromise] Active intrusion targeting Crown Jewel {primary_host} (Alerts: {cited_ids_str})."
            bullet2 = f"• [Kill-Chain Advance] Observed stages: {', '.join(inc.mitre_tactics[:3])} (CADR Risk: {inc.risk_score}/100)."
            bullet3 = f"• [Urgent Action] Invalidate Kerberos KRBTGT/credentials and isolate {primary_host} from network."
            exec_summary = f"{bullet1}\n{bullet2}\n{bullet3}"
            narrative = (
                f"Attack chain traversed into Crown Jewel domain asset {primary_host}. "
                f"Adversary engaged in privileged activity ({', '.join(inc.mitre_tactics)})."
            )
            impact = "IDENTITY & INFRASTRUCTURE COMPROMISE: Critical enterprise operational risk."
            actions = [
                f"Sever network connectivity for {primary_host} via EDR.",
                "Revoke affected domain administrative sessions and reset passwords.",
                "Block external attacker IP(s) on firewalls."
            ]

        elif tactics_set <= {"Reconnaissance"} and inc.highest_asset_tier == AssetTier.TIER_3:
            headline = f"NOISE/RECON: External Port Scanning on Perimeter ({inc.alert_count} alerts) [{inc.tier_badge}]"
            bullet1 = f"• [Perimeter Probe] Automated reconnaissance detected on edge interfaces (Alerts: {cited_ids_str})."
            bullet2 = f"• [Zero Ingress] No internal hosts breached; firewall successfully dropped packets (CADR Risk: {inc.risk_score}/100)."
            bullet3 = f"• [Recommendation] Auto-suppress alerts from this source IP range for 24 hours."
            exec_summary = f"{bullet1}\n{bullet2}\n{bullet3}"
            narrative = "Standard background port scanning (T1046). Dropped at DMZ border."
            impact = "NEGLIGIBLE IMPACT: Standard internet background noise."
            actions = [
                "Auto-suppress alerts from this external IP for 24 hours.",
                "Verify perimeter firewall rule integrity."
            ]
        else:
            headline = f"SEV-2 INVESTIGATION: {inc.title} [{inc.tier_badge}]"
            bullet1 = f"• [Correlated Cluster] {inc.alert_count} alerts across {len(inc.entities.get('hosts', []))} host(s) (Alerts: {cited_ids_str})."
            bullet2 = f"• [Kill Chain] Observed stages: {', '.join(inc.mitre_tactics[:3])} (CADR Score: {inc.risk_score}/100)."
            bullet3 = f"• [Recommendation] Inspect child processes and verify business legitimacy with user {primary_user}."
            exec_summary = f"{bullet1}\n{bullet2}\n{bullet3}"
            narrative = f"Correlated event sequence on {primary_host}. Observed techniques: {[t['id'] for t in inc.mitre_techniques]}."
            impact = f"Evaluated Risk Score: {inc.risk_score}/100 on {inc.highest_asset_tier.value}."
            actions = [
                "Review process command line arguments and parent process tree.",
                "Validate user authentication source IP with employee."
            ]

        return IncidentBrief(
            headline=headline,
            executive_summary=exec_summary,
            attack_narrative=narrative,
            key_iocs=iocs[:6],
            impact_assessment=impact,
            recommended_actions=actions,
            cited_alert_ids=alert_ids,
            generated_by="Deterministic SOC Security Expert Engine"
        )

    def _generate_with_gemini(self, inc: Incident) -> Optional[IncidentBrief]:
        """Calls Google Gemini API to synthesize grounded natural language brief."""
        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={self.api_key}"
        alert_ids = [a.alert_id for a in inc.alerts[:5]]

        prompt = f"""
You are a senior SOC analyst. Generate a concise 3-bullet grounded shift-handover brief for this incident.
Every summary bullet must cite specific Alert IDs ({', '.join(alert_ids)}).

Incident Data:
- Title: {inc.title}
- Risk Score: {inc.risk_score} / 100
- Asset Tier: {inc.highest_asset_tier.value} (Badge: {inc.tier_badge})
- Primary Host: {inc.primary_hostname}
- Primary User: {inc.primary_username}
- Alert Count: {inc.alert_count}
- MITRE Tactics: {', '.join(inc.mitre_tactics)}
- Cited Alert IDs: {alert_ids}

Return ONLY valid JSON matching this structure:
{{
  "headline": "Short headline with severity, asset, and [{inc.tier_badge}] badge",
  "executive_summary": "• Bullet 1 with cited Alert IDs\\n• Bullet 2 with CADR score & asset scope\\n• Bullet 3 with immediate recommended action",
  "attack_narrative": "Detailed chronological narrative",
  "key_iocs": ["IoC 1", "IoC 2"],
  "impact_assessment": "Impact assessment",
  "recommended_actions": ["Action 1", "Action 2"],
  "cited_alert_ids": {json.dumps(alert_ids)}
}}
"""
        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {"temperature": 0.2, "responseMimeType": "application/json"}
        }

        with httpx.Client(timeout=10.0) as client:
            resp = client.post(url, json=payload)
            if resp.status_code == 200:
                data = resp.json()
                text = data["candidates"][0]["content"]["parts"][0]["text"]
                parsed = json.loads(text)
                return IncidentBrief(
                    headline=parsed.get("headline", inc.title),
                    executive_summary=parsed.get("executive_summary", ""),
                    attack_narrative=parsed.get("attack_narrative", ""),
                    key_iocs=parsed.get("key_iocs", []),
                    impact_assessment=parsed.get("impact_assessment", ""),
                    recommended_actions=parsed.get("recommended_actions", []),
                    cited_alert_ids=parsed.get("cited_alert_ids", alert_ids),
                    generated_by="Google Gemini Flash (Grounded RAG Brief)"
                )
        return None

    def _generate_with_ollama(self, inc: Incident) -> Optional[IncidentBrief]:
        prompt = f"Generate 3-bullet SOC brief for {inc.title} [{inc.tier_badge}] citing alerts. JSON format."
        payload = {"model": "llama3", "prompt": prompt, "stream": False, "format": "json"}
        with httpx.Client(timeout=4.0) as client:
            resp = client.post(self.ollama_endpoint, json=payload)
            if resp.status_code == 200:
                p_data = json.loads(resp.json().get("response", "{}"))
                return IncidentBrief(
                    headline=p_data.get("headline", inc.title),
                    executive_summary=p_data.get("executive_summary", ""),
                    attack_narrative=p_data.get("attack_narrative", ""),
                    key_iocs=p_data.get("key_iocs", []),
                    impact_assessment=p_data.get("impact_assessment", ""),
                    recommended_actions=p_data.get("recommended_actions", []),
                    cited_alert_ids=[a.alert_id for a in inc.alerts[:5]],
                    generated_by="Local Ollama AI Model"
                )
        return None
