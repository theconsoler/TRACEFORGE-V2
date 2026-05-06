"""
TraceForge v2 — Interactive Launcher
The main entry point for interactive use.
Run with: python -m traceforge.launcher
"""

import os
import sys
import subprocess
from pathlib import Path
from datetime import datetime, timezone

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.columns import Columns
from rich.text import Text
from rich import box
from loguru import logger

# Disable loguru output in launcher mode
logger.remove()

console = Console()

BANNER = """
████████╗██████╗  █████╗  ██████╗███████╗███████╗ ██████╗ ██████╗  ██████╗ ███████╗
   ██╔══╝██╔══██╗██╔══██╗██╔════╝██╔════╝██╔════╝██╔═══██╗██╔══██╗██╔════╝ ██╔════╝
   ██║   ██████╔╝███████║██║     █████╗  █████╗  ██║   ██║██████╔╝██║  ███╗█████╗
   ██║   ██╔══██╗██╔══██║██║     ██╔══╝  ██╔══╝  ██║   ██║██╔══██╗██║   ██║██╔══╝
   ██║   ██║  ██║██║  ██║╚██████╗███████╗██║     ╚██████╔╝██║  ██║╚██████╔╝███████╗
   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚══════╝╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝
"""

VERSION = "v2.0.0"
GITHUB  = "github.com/theconsoler/TRACEFORGE-V2"


def clear():
    os.system("clear")


def get_live_stats() -> dict:
    """Pull live stats from the database."""
    try:
        from traceforge.core.ledger import init_db, list_cases
        from traceforge.core.store import get_artifact_count
        init_db()
        cases = list_cases()
        total_artifacts = 0
        for c in cases:
            counts = get_artifact_count(c["id"])
            total_artifacts += sum(counts.values())
        return {
            "total_cases": len(cases),
            "total_artifacts": total_artifacts,
            "cases": cases[:5]
        }
    except Exception:
        return {"total_cases": 0, "total_artifacts": 0, "cases": []}


def print_banner():
    """Print the TraceForge ASCII banner."""
    banner_text = Text(BANNER, style="bold cyan")
    console.print(banner_text)
    console.print(
        f"  [bold white]Digital Forensics & Incident Response Toolkit[/bold white]  "
        f"[dim]{VERSION}[/dim]  [dim]{GITHUB}[/dim]\n"
    )


def print_stats(stats: dict):
    """Print live case statistics."""
    panels = [
        Panel(
            f"[bold cyan]{stats['total_cases']}[/bold cyan]\n[dim]Total Cases[/dim]",
            border_style="cyan",
            padding=(0, 2)
        ),
        Panel(
            f"[bold cyan]{stats['total_artifacts']}[/bold cyan]\n[dim]Total Artifacts[/dim]",
            border_style="cyan",
            padding=(0, 2)
        ),
        Panel(
            f"[bold cyan]{datetime.now().strftime('%Y-%m-%d')}[/bold cyan]\n[dim]Today[/dim]",
            border_style="cyan",
            padding=(0, 2)
        ),
    ]
    console.print(Columns(panels))
    console.print()


def print_recent_cases(stats: dict):
    """Print the most recent cases."""
    if not stats["cases"]:
        console.print("  [dim]No cases found. Create your first case with option 1.[/dim]\n")
        return

    table = Table(
        box=box.SIMPLE,
        show_header=True,
        header_style="dim",
        padding=(0, 2)
    )
    table.add_column("Case ID", style="cyan", no_wrap=True)
    table.add_column("Name")
    table.add_column("Analyst", style="dim")
    table.add_column("Created", style="dim")

    for c in stats["cases"]:
        table.add_row(
            c["id"],
            c["name"],
            c["analyst"],
            c["created_at"][:10]
        )

    console.print("  [bold]Recent Cases[/bold]")
    console.print(table)


def print_menu():
    """Print the quick-start menu."""
    console.print("  [bold cyan]=== Main Menu ===[/bold cyan]\n")
    menu_items = [
        ("1", "New Investigation Case",  "Create a new case and begin evidence collection"),
        ("2", "Analyze Evidence",         "Run memory, disk, log, or network analysis"),
        ("3", "Correlate Findings",       "Run cross-module correlation engine"),
        ("4", "Generate Report",          "Export case report as JSON, HTML, or PDF"),
        ("5", "View All Cases",           "List all investigation cases"),
        ("6", "Launch Web Dashboard",     "Open the Flask dashboard in browser"),
        ("7", "Run Full Pipeline",        "New case + analyze + correlate + report in one flow"),
        ("0", "Exit",                     "Quit TraceForge"),
    ]

    for num, title, desc in menu_items:
        color = "red" if num == "0" else "cyan"
        console.print(
            f"  [{color}]{num}[/{color}]  [bold]{title:<30}[/bold] [dim]{desc}[/dim]"
        )
    console.print()


def handle_new_case():
    """Interactive new case creation."""
    console.print("\n[bold cyan]New Investigation Case[/bold cyan]\n")
    case_id  = console.input("  Case ID (e.g. CASE-2026-001): ").strip()
    name     = console.input("  Case name: ").strip()
    analyst  = console.input("  Analyst name: ").strip()
    notes    = console.input("  Notes (optional): ").strip()

    if not case_id or not name or not analyst:
        console.print("[red]Case ID, name, and analyst are required.[/red]")
        return

    subprocess.run([
        sys.executable, "-m", "traceforge.cli",
        "case", "new",
        "--id", case_id,
        "--name", name,
        "--analyst", analyst,
        "--notes", notes or ""
    ], capture_output=False)


def handle_analyze():
    """Interactive evidence analysis."""
    console.print("\n[bold cyan]Analyze Evidence[/bold cyan]\n")
    case_id   = console.input("  Case ID: ").strip()
    module    = console.input("  Module [memory/disk/logs/network]: ").strip().lower()
    file_path = console.input("  Evidence file path: ").strip()
    analyst   = console.input("  Analyst name: ").strip()
    host_id   = console.input("  Host identifier (optional): ").strip()

    if module not in ("memory", "disk", "logs", "network"):
        console.print("[red]Invalid module. Choose from: memory, disk, logs, network[/red]")
        return

    cmd = [
        sys.executable, "-m", "traceforge.cli", "analyze",
        "--case", case_id,
        "--module", module,
        "--file", file_path,
        "--analyst", analyst,
    ]
    if host_id:
        cmd += ["--host", host_id]

    subprocess.run(cmd, capture_output=False)


def handle_correlate():
    """Interactive correlation."""
    console.print("\n[bold cyan]Correlation Engine[/bold cyan]\n")
    case_id = console.input("  Case ID: ").strip()
    window  = console.input("  Time window in seconds (default 30): ").strip()
    window  = window if window.isdigit() else "30"

    subprocess.run([
        sys.executable, "-m", "traceforge.cli", "correlate",
        "--case", case_id,
        "--window", window
    ], capture_output=False)


def handle_report():
    """Interactive report generation."""
    console.print("\n[bold cyan]Generate Report[/bold cyan]\n")
    case_id = console.input("  Case ID: ").strip()
    fmt     = console.input("  Format [json/html/pdf/all] (default all): ").strip().lower()
    fmt     = fmt if fmt in ("json", "html", "pdf", "all") else "all"

    subprocess.run([
        sys.executable, "-m", "traceforge.cli", "report",
        "--case", case_id,
        "--format", fmt
    ], capture_output=False)


def handle_view_cases():
    """View all cases."""
    console.print("\n[bold cyan]All Cases[/bold cyan]\n")
    subprocess.run([
        sys.executable, "-m", "traceforge.cli", "case", "list"
    ], capture_output=False)


def handle_dashboard():
    """Launch the Flask dashboard."""
    console.print("\n[bold cyan]Launching Web Dashboard[/bold cyan]")
    console.print("  Opening at: [cyan]http://127.0.0.1:5000[/cyan]")
    console.print("  Press [bold]Ctrl+C[/bold] to stop the dashboard\n")

    try:
        subprocess.run([
            sys.executable, "-m", "dashboard.app"
        ], capture_output=False)
    except KeyboardInterrupt:
        console.print("\n[dim]Dashboard stopped.[/dim]")


def handle_full_pipeline():
    """Run the full pipeline interactively."""
    console.print("\n[bold cyan]Full Pipeline — New Case to Report[/bold cyan]\n")
    console.print("  This will walk you through: Create case → Analyze → Correlate → Report\n")

    case_id = console.input("  Case ID: ").strip()
    name    = console.input("  Case name: ").strip()
    analyst = console.input("  Analyst name: ").strip()

    # Create case
    console.print("\n[bold]Step 1 — Creating case...[/bold]")
    subprocess.run([
        sys.executable, "-m", "traceforge.cli",
        "case", "new",
        "--id", case_id, "--name", name, "--analyst", analyst
    ], capture_output=False)

    # Analyze loop
    while True:
        console.print("\n[bold]Step 2 — Add evidence file[/bold]")
        console.print("  Modules available: memory, disk, logs, network")
        module = console.input("  Module (or 'done' to skip to correlation): ").strip().lower()
        if module == "done":
            break
        if module not in ("memory", "disk", "logs", "network"):
            console.print("[red]Invalid module.[/red]")
            continue
        file_path = console.input("  Evidence file path: ").strip()
        host_id   = console.input("  Host identifier (optional): ").strip()

        cmd = [
            sys.executable, "-m", "traceforge.cli", "analyze",
            "--case", case_id, "--module", module,
            "--file", file_path, "--analyst", analyst
        ]
        if host_id:
            cmd += ["--host", host_id]
        subprocess.run(cmd, capture_output=False)

    # Correlate
    console.print("\n[bold]Step 3 — Running correlation engine...[/bold]")
    subprocess.run([
        sys.executable, "-m", "traceforge.cli",
        "correlate", "--case", case_id
    ], capture_output=False)

    # Report
    console.print("\n[bold]Step 4 — Generating report...[/bold]")
    subprocess.run([
        sys.executable, "-m", "traceforge.cli",
        "report", "--case", case_id, "--format", "all"
    ], capture_output=False)

    console.print(f"\n[bold green]Pipeline complete for case {case_id}[/bold green]")


def main():
    """Main launcher loop."""
    while True:
        clear()
        print_banner()

        stats = get_live_stats()
        print_stats(stats)
        print_recent_cases(stats)
        console.print()
        print_menu()

        choice = console.input("  [bold cyan]Select an option:[/bold cyan] ").strip()

        if choice == "1":
            handle_new_case()
        elif choice == "2":
            handle_analyze()
        elif choice == "3":
            handle_correlate()
        elif choice == "4":
            handle_report()
        elif choice == "5":
            handle_view_cases()
        elif choice == "6":
            handle_dashboard()
        elif choice == "7":
            handle_full_pipeline()
        elif choice == "0":
            clear()
            console.print("[bold cyan]TraceForge v2[/bold cyan] — Session ended.\n")
            sys.exit(0)
        else:
            console.print("[red]Invalid option. Press Enter to continue.[/red]")

        console.input("\n  Press Enter to return to menu...")


if __name__ == "__main__":
    main()
