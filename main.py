"""
Main Orchestration CLI for SYNAPSE-SOC.
Event-Driven Live Streaming SOC Detector, Correlator & Handover Engine.
Supports:
  - --live: Ingests real-time events from Windows Event Log, FIM Watchdog, and SSH Honeypot.
  - --replay: Replays recorded real attacker telemetry into streaming correlator with Live Terminal UI.
  - --demo: Runs 3-minute end-to-end multi-stage attack and containment simulation.
  - --batch: Correlates historical batch alert datasets.
  - --web: Starts the FastAPI Human-in-the-Loop triage web console.
"""

import os
import sys
import json
import argparse
import asyncio
from pathlib import Path

# Fix Windows cp1252 encoding
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

from rich.console import Console
from engine.models import Alert, Incident
from engine.streaming_correlator import StreamingCorrelator
from engine.risk_scorer import RiskScorer
from engine.summarizer import ShiftBriefSummarizer
from engine.metrics import TriageMetricsCalculator
from sources.event_queue import UnifiedEventQueue
from sources.windows_events import WindowsEventSource
from sources.fim_source import FIMSource
from sources.ssh_honeypot import SSHHoneypotSource
from live_dashboard import TerminalDashboard
from notifications.notifier import IncidentNotifier

console = Console(highlight=False)


async def run_live_pipeline(enable_honeypot: bool = False, honeypot_port: int = 2222, enable_notify: bool = False):
    console.print("\n[bold cyan]===========================================================[/bold cyan]")
    console.print("[bold white on blue]  SYNAPSE-SOC: LIVE EVENT-DRIVEN STREAMING DETECTOR       [/bold white on blue]")
    console.print("[bold cyan]===========================================================[/bold cyan]\n")

    event_queue = UnifiedEventQueue()
    event_queue.set_loop(asyncio.get_running_loop())
    correlator = StreamingCorrelator(time_window_minutes=15.0)
    notifier = IncidentNotifier() if enable_notify else None

    # Attach Live Sources
    sources = []

    # 1. Windows Security Event Log Source
    win_source = WindowsEventSource(event_queue=event_queue)
    sources.append(win_source)

    # 2. File Integrity Monitor (watchdog on protected_assets/)
    fim_source = FIMSource(watch_dir="protected_assets", event_queue=event_queue)
    sources.append(fim_source)

    # 3. SSH Deception Honeypot (optional on isolated interface)
    if enable_honeypot:
        honey_source = SSHHoneypotSource(port=honeypot_port, event_queue=event_queue)
        sources.append(honey_source)

    for src in sources:
        await src.start()
        console.print(f"[green][+][/green] Initialized Live Telemetry Source: [bold cyan]{src.name}[/bold cyan]")

    dashboard = TerminalDashboard(event_queue=event_queue, correlator=correlator)
    console.print("[green][+][/green] Live Streaming Correlator & Rich UI Console Active. Awaiting events...\n")

    try:
        await dashboard.run(refresh_per_second=4.0)
    finally:
        for src in sources:
            await src.stop()


def run_batch_pipeline(alerts_file: str = "data/alerts_3000.json", output_dir: str = "data"):
    from engine.correlator import AlertCorrelator
    console.print("\n[bold cyan]===========================================================[/bold cyan]")
    console.print("[bold white on blue]  SYNAPSE-SOC: BATCH INCIDENT CORRELATION ENGINE          [/bold white on blue]")
    console.print("[bold cyan]===========================================================[/bold cyan]\n")

    alerts_path = Path(alerts_file)
    if not alerts_path.exists():
        console.print(f"[yellow]Alerts file {alerts_file} not found. Generating sample dataset...[/yellow]")
        from data.generator import generate_enterprise_dataset
        generate_enterprise_dataset(output_path=str(alerts_path), target_count=3000)

    with open(alerts_path, "r", encoding="utf-8") as f:
        raw_alerts = json.load(f)

    console.print(f"[green][+][/green] Ingested [bold]{len(raw_alerts):,}[/bold] telemetry alerts.")
    correlator = AlertCorrelator(time_window_hours=6.0)
    incidents = correlator.correlate_alerts(raw_alerts)
    console.print(f"[green][+][/green] Correlated into [bold]{len(incidents)}[/bold] cohesive security incidents.")

    scorer = RiskScorer()
    ranked_incidents = scorer.score_and_rank_incidents(incidents)

    summarizer = ShiftBriefSummarizer()
    for inc in ranked_incidents:
        inc.ai_brief = summarizer.generate_shift_brief(inc)

    metrics_calc = TriageMetricsCalculator()
    benchmark = metrics_calc.calculate_benchmark(ranked_incidents, len(raw_alerts))

    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    with open(out_dir / "incidents_triaged.json", "w", encoding="utf-8") as f:
        json.dump([inc.model_dump(mode="json") for inc in ranked_incidents], f, indent=2, default=str)

    console.print(f"[bold green][+] Batch Run Complete![/bold green] Triaged [bold]{len(ranked_incidents)}[/bold] incidents.\n")
    return ranked_incidents, benchmark


def start_web_server(port: int = 8000):
    from run_server import start_server
    start_server(port=port)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SYNAPSE-SOC Live Streaming SOC Detection Engine")
    parser.add_argument("--live", action="store_true", help="Start real-time live telemetry ingestion & terminal dashboard")
    parser.add_argument("--replay", action="store_true", help="Replay recorded real attack telemetry")
    parser.add_argument("--dataset", type=str, default="data/captured_attacks.json", help="Path to replay dataset")
    parser.add_argument("--demo", action="store_true", help="Run 3-minute end-to-end multi-stage attack simulation")
    parser.add_argument("--batch", action="store_true", help="Run legacy/historical batch correlation")
    parser.add_argument("--web", action="store_true", help="Launch FastAPI Web Triage Console")
    parser.add_argument("--health", action="store_true", help="Run telemetry sources and subsystem health diagnostics")
    parser.add_argument("--honeypot", action="store_true", help="Enable local SSH deception honeypot listener")
    parser.add_argument("--port", type=int, default=8000, help="Web server port")

    args = parser.parse_args()

    if args.health:
        from health_check import run_diagnostics
        run_diagnostics()
    elif args.demo:
        from demo_attack_simulation import run_attack_demo
        asyncio.run(run_attack_demo())
    elif args.replay:
        from replay_mode import run_replay
        asyncio.run(run_replay(dataset_path=args.dataset, delay=0.5))
    elif args.web:
        start_web_server(port=args.port)
    elif args.batch:
        run_batch_pipeline()
    else:
        # Default mode: Live streaming or replay
        try:
            asyncio.run(run_live_pipeline(enable_honeypot=args.honeypot))
        except KeyboardInterrupt:
            console.print("\n[+] SYNAPSE-SOC Live detector stopped.")
