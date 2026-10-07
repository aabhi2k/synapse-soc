"""
5 Core Detection Rules Engine.
Detects attack behavioral patterns over stateful sliding windows:
  1. Brute Force (T1110): >= 5 failed logins within 5 minutes from same user/host/IP.
  2. Post-Brute Login (T1078): Successful login after preceding failed attempts.
  3. Spawn After Login (T1059): Suspicious child process execution within 5 minutes of logon.
  4. Mass File Change (T1486): Rapid file encryption or mass modifications in protected directory.
  5. Honeypot Hit (T1083 / T1046): Unauthorized probe/connection on isolated honeypot interface.
"""

from typing import List, Dict, Optional, Tuple
from datetime import datetime, timezone, timedelta
from collections import defaultdict

from engine.models import Alert, Severity, AssetTier


class DetectionRuleEngine:
    def __init__(self, time_window_minutes: float = 15.0):
        self.time_window = timedelta(minutes=time_window_minutes)
        # Sliding state tracking
        self.recent_failed_logins: Dict[str, List[Alert]] = defaultdict(list)
        self.recent_successful_logins: Dict[str, List[Alert]] = defaultdict(list)
        self.recent_file_events: Dict[str, List[Alert]] = defaultdict(list)
        self.recent_honeypot_hits: Dict[str, List[Alert]] = defaultdict(list)

    def evaluate(self, alert: Alert) -> List[Tuple[str, str, Severity, str, str, str]]:
        """
        Evaluates the incoming alert against stateful detection rules.
        Returns a list of triggered rule findings:
          (rule_title, rule_type, severity, mitre_tactic, mitre_tech_id, mitre_tech_name)
        """
        findings = []
        now = alert.timestamp

        # Purge stale states older than time_window
        self._purge_stale(now)

        key_user = (alert.username or "unknown").lower()
        key_host = (alert.hostname or "unknown").upper()
        key_ip = alert.source_ip or "127.0.0.1"
        composite_key = f"{key_user}@{key_host}"

        # -------------------------------------------------------------
        # Rule 1: Brute Force (T1110)
        # -------------------------------------------------------------
        if alert.type == "AUTH_FAILED" or "Failed Logon" in alert.rule_name:
            self.recent_failed_logins[composite_key].append(alert)
            self.recent_failed_logins[key_ip].append(alert)

            # Check threshold (>= 5 failed attempts in window)
            failed_count = len([a for a in self.recent_failed_logins[composite_key] if (now - a.timestamp) <= timedelta(minutes=5)])
            if failed_count >= 5:
                findings.append((
                    f"Credential Brute Force / Password Spray ({failed_count} attempts on {key_user})",
                    "BRUTE_FORCE_BURST",
                    Severity.HIGH,
                    "Credential Access",
                    "T1110.001",
                    "Password Guessing"
                ))

        # -------------------------------------------------------------
        # Rule 2: Post-Brute Successful Login (T1078)
        # -------------------------------------------------------------
        elif alert.type == "AUTH_SUCCESS" or "Successful Logon" in alert.rule_name:
            # Check if there were failed logins for this user or IP in the last 15 minutes
            prior_fails = [a for a in self.recent_failed_logins.get(composite_key, []) if (now - a.timestamp) <= timedelta(minutes=15)]
            prior_ip_fails = [a for a in self.recent_failed_logins.get(key_ip, []) if (now - a.timestamp) <= timedelta(minutes=15)]

            if len(prior_fails) >= 3 or len(prior_ip_fails) >= 3:
                findings.append((
                    f"CRITICAL: Successful Authentication Following Password Guessing ({key_user} on {key_host})",
                    "POST_BRUTE_LOGIN",
                    Severity.CRITICAL,
                    "Initial Access",
                    "T1078",
                    "Valid Accounts"
                ))
            self.recent_successful_logins[composite_key].append(alert)

        # -------------------------------------------------------------
        # Rule 3: Spawn After Login (T1059)
        # -------------------------------------------------------------
        elif alert.type == "PROCESS_SPAWN" or "Process Created" in alert.rule_name or alert.process_name:
            # Check if an interactive login occurred recently (within 5 minutes)
            logins = [a for a in self.recent_successful_logins.get(composite_key, []) if (now - a.timestamp) <= timedelta(minutes=5)]
            is_suspicious_cmd = alert.severity in [Severity.HIGH, Severity.CRITICAL] or (
                alert.command_line and any(kw in alert.command_line.lower() for kw in ["powershell", "cmd.exe", "whoami", "mimikatz", "vssadmin", "net user"])
            )

            if logins and is_suspicious_cmd:
                findings.append((
                    f"HIGH: Suspicious Process Spawned Immediately Post-Logon ({alert.process_name or 'cmd.exe'})",
                    "SPAWN_AFTER_LOGIN",
                    Severity.HIGH,
                    "Execution",
                    "T1059.001",
                    "Command and Scripting Interpreter: PowerShell"
                ))

        # -------------------------------------------------------------
        # Rule 4: Mass File Change / Ransomware (T1486)
        # -------------------------------------------------------------
        elif alert.source == "fim" or alert.type in ["MASS_FILE_CHANGE", "SUSPICIOUS_FILE_ENCRYPTION"]:
            self.recent_file_events[key_host].append(alert)
            findings.append((
                alert.rule_name,
                "MASS_FILE_CHANGE_ACTIVE",
                Severity.CRITICAL if alert.type == "MASS_FILE_CHANGE" else Severity.HIGH,
                "Impact",
                "T1486",
                "Data Encrypted for Impact"
            ))

        # -------------------------------------------------------------
        # Rule 5: Honeypot Hit / Recon (T1083 / T1046)
        # -------------------------------------------------------------
        elif alert.source in ["honeypot", "cowrie"] or alert.type in ["HONEYPOT_PROBE", "HONEYPOT_AUTH_ATTEMPT"]:
            self.recent_honeypot_hits[key_ip].append(alert)
            findings.append((
                f"Active Deception Hit: Attacker Probed SSH Honeypot from {key_ip}",
                "HONEYPOT_INTERACTION",
                Severity.HIGH,
                "Reconnaissance",
                "T1046",
                "Network Service Discovery"
            ))

        return findings

    def _purge_stale(self, current_time: datetime) -> None:
        cutoff = current_time - self.time_window
        for d in [self.recent_failed_logins, self.recent_successful_logins, self.recent_file_events, self.recent_honeypot_hits]:
            for k in list(d.keys()):
                d[k] = [a for a in d[k] if a.timestamp >= cutoff]
                if not d[k]:
                    del d[k]

