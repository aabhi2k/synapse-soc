"""
Demo Replay Engine for SYNAPSE-SOC.
Replays recorded real threat telemetry datasets into the Unified Event Queue,
demonstrating the live streaming correlator, kill-chain progression, and Rich terminal dashboard.
"""

import sys
import json
import argparse
import asyncio
from pathlib import Path
from datetime import datetime, timezone

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

from engine.models import Alert
from engine.streaming_correlator import StreamingCorrelator
from sources.event_queue import UnifiedEventQueue
from live_dashboard import TerminalDashboard
from notifications.notifier import IncidentNotifier


async def run_replay(dataset_path: str, delay: float = 0.6, notify: bool = False):
    path = Path(dataset_path)
    if not path.exists():
        print(f"Error: Dataset {dataset_path} not found.")
        return

    with open(path, "r", encoding="utf-8") as f:
        raw_events = json.load(f)

    event_queue = UnifiedEventQueue()
    correlator = StreamingCorrelator(time_window_minutes=15.0)
    notifier = IncidentNotifier() if notify else None
    dashboard = TerminalDashboard(event_queue=event_queue, correlator=correlator)

    # Background streamer
    async def event_feeder():
        await asyncio.sleep(0.5)
        for raw in raw_events:
            alert = Alert(**raw)
            # Update to current timestamp
            alert.timestamp = datetime.now(timezone.utc)
            await event_queue.put(alert)
            if notifier:
                # Check notification on top incident
                incs = correlator.get_ranked_incidents()
                if incs:
                    await notifier.maybe_notify(incs[0])
            await asyncio.sleep(delay)

    feeder_task = asyncio.create_task(event_feeder())
    dash_task = asyncio.create_task(dashboard.run(refresh_per_second=4.0))

    await feeder_task
    # Let dashboard run a bit after all events finish
    await asyncio.sleep(2.0)
    dash_task.cancel()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SYNAPSE-SOC Replay Mode")
    parser.add_argument("--dataset", type=str, default="data/captured_attacks.json", help="Path to JSON dataset")
    parser.add_argument("--delay", type=float, default=0.5, help="Delay between replayed events (seconds)")
    parser.add_argument("--notify", action="store_true", help="Enable live Telegram/Discord notification triggers")
    args = parser.parse_args()

    try:
        asyncio.run(run_replay(dataset_path=args.dataset, delay=args.delay, notify=args.notify))
    except KeyboardInterrupt:
        print("\n[+] Replay mode terminated cleanly.")
