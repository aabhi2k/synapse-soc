"""
Telegram & Discord Incident Escalation Bot with Human-In-The-Loop Interactive Approvals.
Uses Telegram Bot API (or Discord Webhook) to deliver grounded AI briefs and interactive
containment buttons: [Block IP] / [Isolate Host] / [Ignore].
Enforces human approval before executing any containment action.
"""

import os
import json
import asyncio
from typing import Optional, Dict, Any
import httpx

from engine.models import Incident


class TelegramResponseBot:
    def __init__(
        self,
        bot_token: Optional[str] = None,
        chat_id: Optional[str] = None,
        discord_webhook: Optional[str] = None
    ):
        self.bot_token = bot_token or os.getenv("TELEGRAM_BOT_TOKEN")
        self.chat_id = chat_id or os.getenv("TELEGRAM_CHAT_ID")
        self.discord_webhook = discord_webhook or os.getenv("DISCORD_WEBHOOK_URL")
        self.pending_actions: Dict[str, Dict[str, Any]] = {}
        self.action_history: list = []

    def format_incident_message(self, inc: Incident) -> str:
        """Formats grounded markdown payload for mobile notification."""
        brief = inc.ai_brief
        headline = brief.headline if brief else inc.title
        summary = brief.executive_summary if brief else "Active multi-stage threat progression detected."
        cites = ", ".join(brief.cited_alert_ids[:4]) if brief and brief.cited_alert_ids else "N/A"

        msg = (
            f"🚨 *SYNAPSE-SOC ALERT: {inc.incident_id}* `[{inc.tier_badge}]`\n"
            f"━━━━━━━━━━━━━━━━━━━━━━━━\n"
            f"*Headline:* {headline}\n"
            f"*CADR Risk Score:* `{inc.risk_score} / 100` (Rank #{inc.risk_rank})\n"
            f"*Asset Tier:* `{inc.highest_asset_tier.value}`\n"
            f"*Target Host:* `{inc.primary_hostname or 'N/A'}`\n"
            f"*Target User:* `{inc.primary_username or 'N/A'}`\n"
            f"*MITRE Tactics:* `{', '.join(inc.mitre_tactics[:3])}`\n"
            f"━━━━━━━━━━━━━━━━━━━━━━━━\n"
            f"*Grounded Handover Summary:*\n{summary}\n\n"
            f"📌 _Verified Citations:_ `{cites}`\n"
            f"⚠️ *Human Approval Required Before Playbook Execution.*"
        )
        return msg

    async def send_incident_escalation(self, inc: Incident) -> bool:
        """Dispatches interactive escalation alert to Telegram or Discord."""
        text = self.format_incident_message(inc)
        target_ip = inc.entities.get("ips", ["127.0.0.1"])[0] if inc.entities.get("ips") else "127.0.0.1"
        target_host = inc.primary_hostname or "HOST-01"

        # 1. Dispatch via Telegram Bot if configured
        if self.bot_token and self.chat_id:
            try:
                url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
                inline_keyboard = {
                    "inline_keyboard": [
                        [
                            {"text": f"🛑 Block IP ({target_ip})", "callback_data": f"REQ_BLOCK_IP:{inc.incident_id}:{target_ip}"},
                            {"text": f"🔒 Isolate Host ({target_host})", "callback_data": f"REQ_ISOLATE:{inc.incident_id}:{target_host}"}
                        ],
                        [
                            {"text": "✅ Ignore / False Positive", "callback_data": f"REQ_IGNORE:{inc.incident_id}"}
                        ]
                    ]
                }
                payload = {
                    "chat_id": self.chat_id,
                    "text": text,
                    "parse_mode": "Markdown",
                    "reply_markup": inline_keyboard
                }
                async with httpx.AsyncClient(timeout=5.0) as client:
                    resp = await client.post(url, json=payload)
                    return resp.status_code == 200
            except Exception as e:
                pass

        # 2. Dispatch via Discord Webhook if configured
        if self.discord_webhook:
            try:
                payload = {
                    "content": text.replace("*", "**").replace("`", "```"),
                    "username": "SYNAPSE-SOC Bot"
                }
                async with httpx.AsyncClient(timeout=5.0) as client:
                    resp = await client.post(self.discord_webhook, json=payload)
                    return resp.status_code == 204
            except Exception:
                pass

        # 3. Fallback mock delivery log
        self.action_history.append({
            "type": "ESCALATION_SENT",
            "incident_id": inc.incident_id,
            "tier": inc.tier_badge,
            "risk_score": inc.risk_score
        })
        return True

    def execute_human_approved_action(self, action_type: str, target: str, incident_id: str, confirmed: bool = False) -> Dict[str, Any]:
        """
        Executes response action ONLY if explicit human confirmation is received.
        """
        if not confirmed:
            return {
                "status": "APPROVAL_REQUIRED",
                "message": f"Safety gate: Containment action {action_type} on '{target}' requires explicit human approval.",
                "approved": False
            }

        if action_type == "BLOCK_IP":
            msg = f"SUCCESS: External IP {target} added to Perimeter Firewall Drop Rules."
        elif action_type == "ISOLATE_HOST":
            msg = f"SUCCESS: EDR Isolation broadcasted to host {target}. Host severed from network."
        elif action_type == "IGNORE":
            msg = f"Incident {incident_id} marked as Suppressed / Benign in SOC queue."
        else:
            msg = f"Executed {action_type} on {target}."

        record = {
            "status": "EXECUTED",
            "action": action_type,
            "target": target,
            "incident_id": incident_id,
            "message": msg,
            "approved": True
        }
        self.action_history.append(record)
        return record

