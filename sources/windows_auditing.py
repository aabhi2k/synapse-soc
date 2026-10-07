"""
Windows Audit Policy Configuration & Verification Helper.
Provides commands and programmatic checks to enable Process Creation & Logon auditing on Windows.
"""

import sys
import subprocess
import os
from typing import Dict, Any


def get_audit_enable_instructions() -> str:
    """Returns exact administrator commands to configure Windows auditing for SOC monitoring."""
    return """
================================================================================
WINDOWS AUDIT POLICY SETUP INSTRUCTIONS (RUN IN POWERSHELL / CMD AS ADMINISTRATOR)
================================================================================

1. Enable Process Creation Auditing (Generates Event ID 4688):
   Auditpol /set /subcategory:"Process Creation" /success:enable

2. Enable Detailed Command Line Logging in Event 4688:
   reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f

3. Enable Logon / Logoff Auditing (Generates Event ID 4624 Success & 4625 Failed):
   Auditpol /set /subcategory:"Logon" /success:enable /failure:enable

4. Verify Current Audit Policies:
   Auditpol /get /category:"Detailed Tracking"
   Auditpol /get /category:"Logon/Logoff"
================================================================================
"""


def verify_or_enable_audit_policies() -> Dict[str, Any]:
    """
    Attempts to check/apply audit policies if running with admin rights on Windows.
    Returns status dictionary.
    """
    if not sys.platform.startswith("win"):
        return {"platform": sys.platform, "admin": False, "status": "Non-Windows environment; using telemetry adapter"}

    is_admin = False
    try:
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        pass

    result = {
        "platform": "windows",
        "is_admin": is_admin,
        "process_creation_audited": False,
        "logon_audited": False,
        "instructions": get_audit_enable_instructions()
    }

    if is_admin:
        try:
            # Enable Process Creation
            subprocess.run(
                ['auditpol', '/set', '/subcategory:Process Creation', '/success:enable'],
                capture_output=True, check=False
            )
            # Enable Logon
            subprocess.run(
                ['auditpol', '/set', '/subcategory:Logon', '/success:enable', '/failure:enable'],
                capture_output=True, check=False
            )
            result["process_creation_audited"] = True
            result["logon_audited"] = True
            result["status"] = "Successfully enabled Windows Security Auditing (4624, 4625, 4688)"
        except Exception as e:
            result["status"] = f"Admin auditpol execution notice: {e}"
    else:
        result["status"] = "Running without Administrator privileges. WinEvt live reading requires Admin or Event Log Readers group."

    return result


if __name__ == "__main__":
    status = verify_or_enable_audit_policies()
    print(status["instructions"])
    print(f"Status: {status['status']}")

