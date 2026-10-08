"""
Incident Notification & Escalation Dispatcher.
Implements incident-level notification, 10-minute deduplication windows,
and critical risk escalation triggers.
"""

import time
from typing import Dict, Optional, Tuple
from engine.models import Incident
from engine.summarizer import ShiftBriefSummarizer
from notifications.telegram_bot import TelegramResponseBot


class IncidentNotifier:
    def __init__(self, bot: Optional[TelegramResponseBot] = None, rate_limit_seconds: float = 600.0):
        self.bot = bot or TelegramResponseBot()
        self.rate_limit_seconds = rate_limit_seconds  # 10 minutes deduplication window
        self.summarizer = ShiftBriefSummarizer()
        # Track last notification timestamp and last notified risk score per incident
        self.last_notified: Dict[str, Tuple[float, float, str]] = {}  # incident_id -> (timestamp, risk_score, kill_chain_stage)

    async def maybe_notify(self, inc: Incident) -> bool:
        """
        Evaluates whether an incident should trigger a mobile notification:
        1. Brand new incident: NOTIFY if risk_score >= 40 or Tier 0/1.
        2. Existing incident: RE-NOTIFY only if risk score increased by >= 15 pts OR new critical stage reached,
           and respect the 10-minute rate limit window.
        """
        now = time.time()
        inc_id = inc.incident_id
        score = inc.risk_score
        stage = inc.current_kill_chain_stage or (inc.mitre_tactics[-1] if inc.mitre_tactics else "Reconnaissance")

        should_send = False

        if inc_id not in self.last_notified:
            # New incident: notify if elevated risk or critical asset
            if score >= 35.0 or inc.highest_asset_tier.badge in ["T0", "T1"]:
                should_send = True
        else:
            last_ts, last_score, last_stage = self.last_notified[inc_id]
            time_elapsed = now - last_ts

            # Check critical escalation
            score_jump = score - last_score >= 15.0
            stage_escalated = stage != last_stage and stage in ["Execution", "Lateral Movement", "Impact", "Exfiltration"]

            if (score_jump or stage_escalated) and (time_elapsed >= 60.0 or score >= 80.0):
                should_send = True
            elif time_elapsed >= self.rate_limit_seconds and score >= 60.0:
                should_send = True

        if should_send:
            # Ensure AI brief is generated
            if not inc.ai_brief:
                inc.ai_brief = self.summarizer.generate_shift_brief(inc)

            self.last_notified[inc_id] = (now, score, stage)
            return await self.bot.send_incident_escalation(inc)

        return False

