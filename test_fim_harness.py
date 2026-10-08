"""
FIM Safe Verification Harness.
Safely creates and renames 25 test files in protected_assets/ to verify
the File Integrity Monitor's mass modification and suspicious extension detection rules.
"""

import os
import sys
import time
import asyncio
from pathlib import Path

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

from sources.fim_source import FIMSource
from sources.event_queue import UnifiedEventQueue


async def run_fim_harness(target_dir: str = "protected_assets", file_count: int = 25):
    print(f"\n=======================================================")
    print(f"  SYNAPSE-SOC: SAFE FIM RANSOMWARE SIMULATION HARNESS  ")
    print(f"=======================================================\n")

    watch_path = Path(target_dir).resolve()
    watch_path.mkdir(parents=True, exist_ok=True)

    event_queue = UnifiedEventQueue()
    captured_alerts = []

    def on_alert(alert):
        captured_alerts.append(alert)
        print(f"  [+] DETECTED: [{alert.severity.value.upper()}] {alert.rule_name}")

    event_queue.subscribe(on_alert)

    fim = FIMSource(watch_dir=str(watch_path), event_queue=event_queue)
    await fim.start()
    print(f"[*] FIM Watchdog monitoring directory: {watch_path}")
    print(f"[*] Creating {file_count} dummy files in {target_dir}...")

    created_files = []
    for i in range(file_count):
        fpath = watch_path / f"confidential_record_{i+1:03d}.txt"
        with open(fpath, "w", encoding="utf-8") as f:
            f.write(f"Sample corporate financial record #{i+1}\nTimestamp: {time.time()}")
        fim.handler.handle_file_event("created", str(fpath))
        created_files.append(fpath)
        time.sleep(0.02)

    print(f"\n[*] Simulating rapid ransomware encryption across {file_count} files (.locked extension)...")
    for fpath in created_files:
        locked_path = fpath.with_suffix(".txt.locked")
        if fpath.exists():
            fpath.rename(locked_path)
        fim.handler.handle_file_event("renamed", str(locked_path))
        time.sleep(0.03)

    await asyncio.sleep(0.5)
    await fim.stop()

    print(f"\n-------------------------------------------------------")
    print(f"HARNESS SUMMARY: Ingested {len(captured_alerts)} alerts into queue.")
    mass_alerts = [a for a in captured_alerts if a.type == "MASS_FILE_CHANGE"]
    suspicious_alerts = [a for a in captured_alerts if a.type == "SUSPICIOUS_FILE_ENCRYPTION"]

    print(f"  • Mass File Change Alerts (>20/10s): {len(mass_alerts)}")
    print(f"  • Suspicious Extension Alerts (.locked): {len(suspicious_alerts)}")

    # Clean up test files safely
    print("[*] Cleaning up safe dummy test files...")
    for p in watch_path.glob("confidential_record_*"):
        try:
            p.unlink()
        except Exception:
            pass

    print("[+] FIM Safe Harness Completed Successfully!\n")


if __name__ == "__main__":
    asyncio.run(run_fim_harness())
