"""
Real-Time Terminal Dashboard (Rich Live UI).
Renders split-pane interactive live terminal display:
  - Header: Metrics & Noise Compression Bar (Events In, Incidents Out, Noise Compression %)
  - Top/Left Pane: Live Incident Queue with Tier Badges (T0, T1, T2, T3), CADR scores, kill-chain stages
  - Right/Bottom Pane: Grounded AI Shift-Handover Brief for top-ranked incident (3 bullets with verified Alert IDs)
"""

import sys
import asyncio
from datetime import datetime
from typing import Optional, List

if sys.platform.startswith("win"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

from rich.console import Console, Group
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.live import Live

from engine.models import Incident, Alert, AssetTier, Severity
from engine.streaming_correlator import StreamingCorrelator
from engine.summarizer import ShiftBriefSummarizer
from sources.event_queue import UnifiedEventQueue


class TerminalDashboard:
    def __init__(self, event_queue: UnifiedEventQueue, correlator: StreamingCorrelator):
        self.queue = event_queue
        self.correlator = correlator
        self.summarizer = ShiftBriefSummarizer()
        self.console = Console()
        self.layout = Layout()
        self.total_events_in = 0
        self.top_incident_brief: Optional[str] = None
        self._setup_layout()

    def _setup_layout(self) -> None:
        self.layout.split_column(
            Layout(name="header", size=3),
            Layout(name="main", ratio=1)
        )
        self.layout["main"].split_row(
            Layout(name="incidents_pane", ratio=3),
            Layout(name="brief_pane", ratio=2)
        )

    def render_header(self) -> Panel:
        events_in = self.queue.total_ingested or self.total_events_in
        ranked = self.correlator.get_ranked_incidents()
        incidents_out = len(ranked)
        compression = ((events_in - incidents_out) / max(1, events_in)) * 100 if events_in > 0 else 0.0

        grid = Table.grid(expand=True)
        grid.add_column(justify="left", ratio=2)
        grid.add_column(justify="center", ratio=3)
        grid.add_column(justify="right", ratio=2)

        t_title = Text("🛡️ SYNAPSE-SOC • LIVE STREAMING DETECTOR", style="bold cyan")
        t_stats = Text.from_markup(
            f"[bold white]Events In:[/bold white] [bold cyan]{events_in:,}[/bold cyan] | "
            f"[bold white]Incidents Out:[/bold white] [bold magenta]{incidents_out}[/bold magenta] | "
            f"[bold white]Noise Compression:[/bold white] [bold green]{compression:.1f}%[/bold green]"
        )
        t_time = Text(f"⏰ {datetime.now().strftime('%H:%M:%S')}", style="dim")

        grid.add_row(t_title, t_stats, t_time)
        return Panel(grid, style="bold blue", border_style="blue")

    def render_incident_table(self) -> Panel:
        ranked = self.correlator.get_ranked_incidents()

        table = Table(
            expand=True,
            box=None,
            header_style="bold magenta",
            show_header=True,
            row_styles=["", "dim"]
        )
        table.add_column("Rank", width=5, justify="center")
        table.add_column("ID", width=10, style="cyan")
        table.add_column("Tier", width=6, justify="center")
        table.add_column("CADR Score", width=12, justify="center")
        table.add_column("Severity", width=10, justify="center")
        table.add_column("Kill Chain", width=18)
        table.add_column("Host / Target", width=16)
        table.add_column("Title", ratio=1)

        if not ranked:
            table.add_row("-", "NO INCIDENTS", "-", "-", "-", "-", "-", "Waiting for live telemetry ingestion...")
        else:
            for inc in ranked[:8]:
                # Tier badge with distinct colors
                badge = inc.tier_badge
                if badge == "T0":
                    tier_str = "[bold white on red] T0 [/bold white on red]"
                elif badge == "T1":
                    tier_str = "[bold white on dark_orange] T1 [/bold white on dark_orange]"
                elif badge == "T2":
                    tier_str = "[bold white on blue] T2 [/bold white on blue]"
                else:
                    tier_str = "[bold white on grey37] T3 [/bold white on grey37]"

                # Score color
                score_val = inc.risk_score
                if score_val >= 80:
                    score_str = f"[bold red]{score_val:.1f}[/bold red]"
                elif score_val >= 50:
                    score_str = f"[bold yellow]{score_val:.1f}[/bold yellow]"
                else:
                    score_str = f"[bold green]{score_val:.1f}[/bold green]"

                # Severity
                sev = inc.highest_alert_severity
                if sev == Severity.CRITICAL:
                    sev_str = "[bold red]CRITICAL[/bold red]"
                elif sev == Severity.HIGH:
                    sev_str = "[red]HIGH[/red]"
                elif sev == Severity.MEDIUM:
                    sev_str = "[yellow]MEDIUM[/yellow]"
                else:
                    sev_str = "[dim]LOW[/dim]"

                kill_chain_tactic = inc.current_kill_chain_stage or (inc.mitre_tactics[-1] if inc.mitre_tactics else "Recon")
                stage_display = f"{kill_chain_tactic} ({inc.kill_chain_stages_covered}stg)"

                table.add_row(
                    f"#{inc.risk_rank}",
                    inc.incident_id,
                    tier_str,
                    score_str,
                    sev_str,
                    f"[magenta]{stage_display}[/magenta]",
                    f"[white]{inc.primary_hostname or 'N/A'}[/white]",
                    inc.title[:38] + ("…" if len(inc.title) > 38 else "")
                )

        return Panel(table, title="[bold yellow]ACTIVE INCIDENT STREAM (ASSET CRITICALITY OVER ALERT COUNT)[/bold yellow]", border_style="yellow")

    def render_brief_pane(self) -> Panel:
        ranked = self.correlator.get_ranked_incidents()
        if not ranked:
            content = "[dim]No active incidents to summarize. Awaiting event stream...[/dim]"
            return Panel(content, title="[bold red]GROUNDED AI SHIFT HANDOVER BRIEF[/bold red]", border_style="red")

        top_inc = ranked[0]
        if not top_inc.ai_brief:
            top_inc.ai_brief = self.summarizer.generate_shift_brief(top_inc)

        brief = top_inc.ai_brief
        alert_cites = ", ".join(brief.cited_alert_ids[:4]) if brief.cited_alert_ids else "N/A"

        content = (
            f"[bold red]{brief.headline}[/bold red]\n"
            f"[dim]Asset: {top_inc.highest_asset_tier.value} | CADR Risk: {top_inc.risk_score}/100 | Target: {top_inc.primary_hostname}[/dim]\n\n"
            f"[bold cyan]GROUNDED 3-BULLET HANDOVER SUMMARY:[/bold cyan]\n"
            f"{brief.executive_summary}\n\n"
            f"[bold green]RECOMMENDED ACTIONS:[/bold green]\n"
        )
        for act in brief.recommended_actions[:3]:
            content += f"  [bold green]>[/bold green] {act}\n"

        content += f"\n[dim italic]Verified Citations: [{alert_cites}][/dim italic]"

        return Panel(content, title=f"[bold red]TOP THREAT BRIEF: {top_inc.incident_id} [{top_inc.tier_badge}][/bold red]", border_style="red")

    def update_view(self) -> Layout:
        self.layout["header"].update(self.render_header())
        self.layout["incidents_pane"].update(self.render_incident_table())
        self.layout["brief_pane"].update(self.render_brief_pane())
        return self.layout

    async def run(self, refresh_per_second: float = 3.0) -> None:
        """Starts the live dashboard loop."""
        with Live(self.update_view(), console=self.console, refresh_per_second=refresh_per_second, screen=False) as live:
            while True:
                # Process pending events from queue
                while not self.queue.empty:
                    try:
                        alert = await self.queue.get()
                        self.total_events_in += 1
                        self.correlator.on_new_alert(alert)
                        self.queue.task_done()
                    except Exception:
                        break

                live.update(self.update_view())
                await asyncio.sleep(1.0 / refresh_per_second)


if __name__ == "__main__":
    from main import run_live_pipeline
    print("Starting SYNAPSE-SOC Live Streaming Dashboard...")
    try:
        asyncio.run(run_live_pipeline())
    except KeyboardInterrupt:
        print("\n[+] SYNAPSE-SOC Live detector stopped.")
