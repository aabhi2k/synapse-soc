"""
Health Check & Telemetry Source Diagnostics for SYNAPSE-SOC.
Verifies operational readiness of:
  1. Windows Security Event Log (Admin rights, pywin32, audit policies)
  2. File Integrity Monitor (Watchdog, protected_assets/ directory)
  3. SSH Deception Honeypot (Port 2222 socket availability)
  4. Core Datasets & Triage Cache
"""

import sys
import socket
from pathlib import Path

# Fix Windows cp1252 encoding
if sys.platform.startswith("win"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console(highlight=False)


def check_port_free(port: int, host: str = "127.0.0.1") -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.4)
        try:
            s.bind((host, port))
            return True
        except OSError:
            return False


def run_diagnostics():
    table = Table(
        title="SYNAPSE-SOC Telemetry Sources & Subsystem Diagnostics",
        expand=True,
        header_style="bold cyan",
        show_lines=True
    )
    table.add_column("Subsystem / Telemetry Source", width=28, style="bold")
    table.add_column("Status", width=14, justify="center")
    table.add_column("Operational Details & Diagnostics", ratio=1)

    # 1. Windows Security Event Log Source
    from sources.windows_events import WindowsEventSource
    win_src = WindowsEventSource()
    status_win = win_src.get_status()
    if not status_win["is_admin"]:
        badge_win = "[bold yellow]DEGRADED[/bold yellow]"
        details_win = (
            "[yellow]Running without Administrator privileges.[/yellow]\n"
            "• Direct Security Event Log (4624, 4625, 4688) reading requires Admin elevation.\n"
            "• Fallback active: Engine degrades gracefully and continues with FIM & Honeypot sources.\n"
            "• [dim]To elevate: Run terminal as Administrator to enable live WinEvt monitoring.[/dim]"
        )
    else:
        badge_win = "[bold green]OPERATIONAL[/bold green]"
        details_win = "[green]Administrator elevation verified. Live WinEvt ingestion ready.[/green]"

    table.add_row("Windows Security Event Log", badge_win, details_win)

    # 2. File Integrity Monitor (FIM)
    from sources.fim_source import FIMSource
    fim_src = FIMSource(watch_dir="protected_assets")
    status_fim = fim_src.get_status()
    if status_fim["degraded"]:
        badge_fim = "[bold red]FAILED[/bold red]"
        details_fim = "[red]Watchdog library missing. Run: pip install watchdog[/red]"
    else:
        badge_fim = "[bold green]OPERATIONAL[/bold green]"
        details_fim = (
            f"[green]Watchdog filesystem observer active.[/green]\n"
            f"• Target watch directory: [cyan]{status_fim['watch_dir']}[/cyan]\n"
            "• Detection rules: Mass modification (>20 files/10s), ransomware extensions (.locked, .crypto)"
        )

    table.add_row("File Integrity Monitor (FIM)", badge_fim, details_fim)

    # 3. SSH Deception Honeypot
    honey_port = 2222
    honey_free = check_port_free(honey_port)
    if honey_free:
        badge_honey = "[bold green]READY[/bold green]"
        details_honey = f"[green]Socket interface ready. Port {honey_port} is unallocated and listening-capable.[/green]"
    else:
        badge_honey = "[bold yellow]PORT IN USE[/bold yellow]"
        details_honey = f"[yellow]Port {honey_port} is currently bound or active.[/yellow]"

    table.add_row("SSH Deception Honeypot", badge_honey, details_honey)

    # 4. Web Console Port 8000
    web_free = check_port_free(8000)
    if web_free:
        badge_web = "[bold green]READY[/bold green]"
        details_web = "[green]Port 8000 is free. FastAPI Web Console can start immediately.[/green]"
    else:
        badge_web = "[bold cyan]RUNNING[/bold cyan]"
        details_web = "[cyan]Port 8000 is currently occupied (Web console may already be active).[/cyan]"

    table.add_row("FastAPI Web Console (Port 8000)", badge_web, details_web)

    # 5. Data Assets
    data_dir = PROJECT_ROOT / "data"
    alerts_file = data_dir / "alerts_3000.json"
    triaged_file = data_dir / "incidents_triaged.json"
    has_data = alerts_file.exists() and triaged_file.exists()
    if has_data:
        badge_data = "[bold green]READY[/bold green]"
        details_data = f"[green]Datasets present: alerts_3000.json ({alerts_file.stat().st_size // 1024:,} KB), incidents_triaged.json ({triaged_file.stat().st_size // 1024:,} KB)[/green]"
    else:
        badge_data = "[bold yellow]GENERATABLE[/bold yellow]"
        details_data = "[yellow]Alert datasets will auto-generate on first run via data/generator.py[/yellow]"

    table.add_row("Enterprise Alert Datasets", badge_data, details_data)

    console.print("\n")
    console.print(table)
    console.print("\n")


if __name__ == "__main__":
    run_diagnostics()

