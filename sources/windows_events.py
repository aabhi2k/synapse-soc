"""
Windows Security Event Log Listener & Schema Normalizer.
Monitors Windows Security Event IDs:
  - 4625: An account failed to log on (Credential Access / Brute Force - T1110)
  - 4624: An account was successfully logged on (Valid Accounts - T1078)
  - 4688: A new process has been created (Command and Scripting Interpreter - T1059)
"""

import sys
import os
import re
import uuid
import asyncio
import threading
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Optional, Dict, Any

from sources.base_source import BaseSource
from sources.event_queue import UnifiedEventQueue
from engine.models import Alert, Severity, AssetTier


class WindowsEventSource(BaseSource):
    def __init__(self, event_queue: Optional[UnifiedEventQueue] = None, poll_interval_sec: float = 1.0):
        super().__init__(name="WindowsEventLog", event_queue=event_queue)
        self.poll_interval = poll_interval_sec
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._has_pywin32 = False
        self._is_admin = False
        self.degraded_reason: Optional[str] = None
        self._check_environment()

    def _check_environment(self) -> None:
        if sys.platform.startswith("win"):
            try:
                import ctypes
                self._is_admin = (ctypes.windll.shell32.IsUserAnAdmin() != 0)
            except Exception:
                self._is_admin = False
        else:
            self._is_admin = False

        try:
            import win32evtlog
            self._has_pywin32 = True
        except ImportError:
            self._has_pywin32 = False

        if not sys.platform.startswith("win"):
            self.degraded_reason = "Non-Windows platform"
        elif not self._has_pywin32:
            self.degraded_reason = "pywin32 library not installed"
        elif not self._is_admin:
            self.degraded_reason = "Non-elevated privileges (Requires Administrator or Event Log Readers group to access Security log)"

    def normalize_event_data(self, event_id: int, xml_or_dict: Any) -> Optional[Alert]:
        """
        Parses raw WinEvt XML/dict into Common Alert Schema:
        source, type, host, user, src_ip, timestamp, severity.
        """
        data: Dict[str, Any] = {}
        if isinstance(xml_or_dict, str):
            data = self._parse_winevt_xml(xml_or_dict)
        elif isinstance(xml_or_dict, dict):
            data = xml_or_dict
        else:
            return None

        user = data.get("TargetUserName") or data.get("SubjectUserName") or data.get("user") or "SYSTEM"
        host = data.get("WorkstationName") or data.get("Computer") or data.get("host") or os.environ.get("COMPUTERNAME", "WIN-ENDPOINT-01")
        src_ip = data.get("IpAddress") or data.get("SourceNetworkAddress") or data.get("src_ip")
        if src_ip in ["-", "127.0.0.1", "::1", None]:
            src_ip = "127.0.0.1"

        proc_name = data.get("NewProcessName") or data.get("ProcessName") or data.get("process_name")
        if proc_name and "\\" in proc_name:
            proc_name = proc_name.split("\\")[-1]

        cmd_line = data.get("CommandLine") or data.get("command_line") or proc_name
        parent_proc = data.get("ParentProcessName") or data.get("parent_process")
        if parent_proc and "\\" in parent_proc:
            parent_proc = parent_proc.split("\\")[-1]

        ts_str = data.get("TimeCreated") or data.get("timestamp")
        if isinstance(ts_str, datetime):
            ts = ts_str
        else:
            ts = datetime.now(timezone.utc)

        # Classify by Event ID
        if event_id == 4625:
            rule_name = "Windows Security: Failed Logon Attempt (Event 4625)"
            event_type = "AUTH_FAILED"
            sev = Severity.MEDIUM
            tactic = "Credential Access"
            tech_id = "T1110.001"
            tech_name = "Password Guessing / Brute Force"
        elif event_id == 4624:
            rule_name = "Windows Security: Successful Logon (Event 4624)"
            event_type = "AUTH_SUCCESS"
            sev = Severity.INFORMATIONAL
            tactic = "Initial Access"
            tech_id = "T1078"
            tech_name = "Valid Accounts"
        elif event_id == 4688:
            rule_name = f"Windows Security: Process Created ({proc_name or 'Process'}) (Event 4688)"
            event_type = "PROCESS_SPAWN"
            sev = Severity.INFORMATIONAL
            tactic = "Execution"
            tech_id = "T1059"
            tech_name = "Command and Scripting Interpreter"

            # Check for suspicious process or commands
            suspicious_patterns = ["powershell", "cmd.exe /c", "whoami", "mimikatz", "vssadmin", "certutil", "rundll32", "reg.exe", "net.exe user"]
            if cmd_line and any(p in cmd_line.lower() for p in suspicious_patterns):
                sev = Severity.HIGH
                rule_name = f"Suspicious Command Execution Detected: {proc_name}"
        else:
            rule_name = f"Windows Security Event {event_id}"
            event_type = "WINEVT_GENERIC"
            sev = Severity.LOW
            tactic = "Discovery"
            tech_id = "T1082"
            tech_name = "System Information Discovery"

        # Determine asset tier
        tier = AssetTier.TIER_2
        crit = 5.0
        if "DC" in host.upper() or "DOMAIN" in host.upper() or "AD" in host.upper():
            tier = AssetTier.TIER_0
            crit = 10.0
        elif "PROD" in host.upper() or "SQL" in host.upper() or "APP" in host.upper():
            tier = AssetTier.TIER_1
            crit = 8.0

        alert = Alert(
            alert_id=f"WIN-{uuid.uuid4().hex[:8].upper()}",
            timestamp=ts,
            rule_name=rule_name,
            severity=sev,
            source="winevt",
            type=event_type,
            host=host,
            user=user,
            src_ip=src_ip,
            hostname=host,
            username=user,
            source_ip=src_ip,
            process_name=proc_name,
            command_line=cmd_line,
            parent_process=parent_proc,
            event_id=event_id,
            mitre_tactic=tactic,
            mitre_technique_id=tech_id,
            mitre_technique_name=tech_name,
            asset_tier=tier,
            asset_criticality_score=crit,
            raw_payload=data
        )
        return alert

    def _parse_winevt_xml(self, xml_content: str) -> Dict[str, Any]:
        """Parses WinEvt XML string into key-value map."""
        result = {}
        try:
            root = ET.fromstring(xml_content)
            # Find Data elements in EventData
            for elem in root.findall(".//{*}Data"):
                name = elem.attrib.get("Name")
                if name:
                    result[name] = elem.text or ""
            # Also extract System elements
            for elem in root.findall(".//{*}System/*"):
                tag = elem.tag.split("}")[-1]
                if elem.attrib.get("Name"):
                    result[elem.attrib["Name"]] = elem.text or ""
                elif elem.attrib.get("SystemTime"):
                    result["TimeCreated"] = elem.attrib["SystemTime"]
                elif elem.text:
                    result[tag] = elem.text
        except Exception:
            pass
        return result

    def _live_win32_listener(self) -> None:
        """Background thread polling Windows Event Log via win32evtlog."""
        try:
            import win32evtlog
            server = 'localhost'
            log_type = 'Security'
            flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEEK_READ
            h_log = win32evtlog.OpenEventLog(server, log_type)
            num_records = win32evtlog.GetNumberOfEventLogRecords(h_log)
            oldest_record = win32evtlog.GetOldestEventLogRecord(h_log)
            last_record = oldest_record + num_records - 1

            while not self._stop_event.is_set():
                num_records = win32evtlog.GetNumberOfEventLogRecords(h_log)
                new_oldest = win32evtlog.GetOldestEventLogRecord(h_log)
                current_latest = new_oldest + num_records - 1

                if current_latest > last_record:
                    # Read new records
                    records = win32evtlog.ReadEventLog(
                        h_log,
                        flags,
                        last_record + 1
                    )
                    for r in records:
                        last_record = max(last_record, r.RecordNumber)
                        event_id = r.EventID & 0x1FFFFFFF  # Strip facility bits
                        if event_id in [4625, 4624, 4688]:
                            strings = r.StringInserts or []
                            raw_dict = {"raw_strings": strings}
                            if event_id == 4625 and len(strings) >= 6:
                                raw_dict["TargetUserName"] = strings[5] if len(strings) > 5 else "unknown"
                                raw_dict["WorkstationName"] = strings[1] if len(strings) > 1 else "WIN-HOST"
                                raw_dict["IpAddress"] = strings[19] if len(strings) > 19 else "127.0.0.1"
                            elif event_id == 4624 and len(strings) >= 6:
                                raw_dict["TargetUserName"] = strings[5] if len(strings) > 5 else "unknown"
                                raw_dict["WorkstationName"] = strings[1] if len(strings) > 1 else "WIN-HOST"
                                raw_dict["IpAddress"] = strings[18] if len(strings) > 18 else "127.0.0.1"
                            elif event_id == 4688 and len(strings) >= 6:
                                raw_dict["NewProcessName"] = strings[5] if len(strings) > 5 else "proc.exe"
                                raw_dict["CommandLine"] = strings[8] if len(strings) > 8 else raw_dict.get("NewProcessName", "")
                                raw_dict["ParentProcessName"] = strings[13] if len(strings) > 13 else ""
                                raw_dict["TargetUserName"] = strings[1] if len(strings) > 1 else "user"

                            alert = self.normalize_event_data(event_id, raw_dict)
                            if alert and self.event_queue:
                                self.event_queue.put_threadsafe(alert)

                self._stop_event.wait(self.poll_interval)
            win32evtlog.CloseEventLog(h_log)
        except Exception as e:
            self.degraded_reason = f"Event log access denied or failed: {e}"

    async def start(self) -> None:
        self._running = True
        self._stop_event.clear()
        if self._has_pywin32 and sys.platform.startswith("win") and self._is_admin:
            self._thread = threading.Thread(target=self._live_win32_listener, daemon=True)
            self._thread.start()
        else:
            reason = self.degraded_reason or "Administrator elevation required"
            print(f"[!] [{self.name}] Operating in graceful fallback: {reason}. Telemetry will continue via FIM and Honeypot sources.")

    def get_status(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "running": self._running,
            "degraded": bool(self.degraded_reason),
            "reason": self.degraded_reason or "Operational (Live Windows Security Log Ingestion)",
            "is_admin": self._is_admin,
            "has_pywin32": self._has_pywin32
        }

    async def stop(self) -> None:
        self._running = False
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1.0)

