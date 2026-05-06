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
    """Print the TraceForge ASCII banner — cyan."""
    banner_text = Text(BANNER, style="bold cyan")
    console.print(banner_text)
    console.print(
        f"  [bold white]Digital Forensics & Incident Response Toolkit[/bold white]  "
        f"[dim white]{VERSION}[/dim white]  [dim]{GITHUB}[/dim]\n"
    )


def print_stats(stats: dict):
    """Print live case statistics — green panels."""
    panels = [
        Panel(
            f"[bold green]{stats['total_cases']}[/bold green]\n[dim]Total Cases[/dim]",
            border_style="green",
            padding=(0, 2)
        ),
        Panel(
            f"[bold green]{stats['total_artifacts']}[/bold green]\n[dim]Total Artifacts[/dim]",
            border_style="green",
            padding=(0, 2)
        ),
        Panel(
            f"[bold green]{datetime.now().strftime('%Y-%m-%d')}[/bold green]\n[dim]Today[/dim]",
            border_style="green",
            padding=(0, 2)
        ),
    ]
    console.print(Columns(panels))
    console.print()


def print_recent_cases(stats: dict):
    """Print the most recent cases — yellow header."""
    if not stats["cases"]:
        console.print("  [dim]No cases found. Create your first case with option 1.[/dim]\n")
        return

    table = Table(
        box=box.SIMPLE,
        show_header=True,
        header_style="bold yellow",
        padding=(0, 2)
    )
    table.add_column("Case ID", style="cyan", no_wrap=True)
    table.add_column("Name", style="white")
    table.add_column("Analyst", style="dim")
    table.add_column("Created", style="dim")

    for c in stats["cases"]:
        table.add_row(
            c["id"],
            c["name"],
            c["analyst"],
            c["created_at"][:10]
        )

    console.print("  [bold yellow]Recent Cases[/bold yellow]")
    console.print(table)


def print_menu():
    """Print the quick-start menu — options in magenta, descriptions in dim."""
    console.print("  [bold magenta]=== Main Menu ===[/bold magenta]\n")
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
        if num == "0":
            console.print(
                f"  [bold red]{num}[/bold red]  [bold red]{title:<30}[/bold red] [dim]{desc}[/dim]"
            )
        else:
            console.print(
                f"  [bold magenta]{num}[/bold magenta]  [bold white]{title:<30}[/bold white] [dim]{desc}[/dim]"
            )
    console.print()


def handle_new_case():
    """Interactive new case creation."""
    console.print("\n[bold cyan]New Investigation Case[/bold cyan]\n")
    case_id  = console.input("  [cyan]Case ID[/cyan] (e.g. CASE-2026-001): ").strip()
    name     = console.input("  [cyan]Case name[/cyan]: ").strip()
    analyst  = console.input("  [cyan]Analyst name[/cyan]: ").strip()
    notes    = console.input("  [cyan]Notes[/cyan] (optional): ").strip()

    if not case_id or not name or not analyst:
        console.print("[bold red]Case ID, name, and analyst are required.[/bold red]")
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
    case_id   = console.input("  [cyan]Case ID[/cyan]: ").strip()
    module    = console.input("  [cyan]Module[/cyan] [memory/disk/logs/network]: ").strip().lower()
    file_path = console.input("  [cyan]Evidence file path[/cyan]: ").strip()
    analyst   = console.input("  [cyan]Analyst name[/cyan]: ").strip()
    host_id   = console.input("  [cyan]Host identifier[/cyan] (optional): ").strip()

    if module not in ("memory", "disk", "logs", "network"):
        console.print("[bold red]Invalid module. Choose from: memory, disk, logs, network[/bold red]")
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

    console.print(f"\n[bold green]Running {module.upper()} analysis...[/bold green]")
    subprocess.run(cmd, capture_output=False)


def handle_correlate():
    """Interactive correlation."""
    console.print("\n[bold cyan]Correlation Engine[/bold cyan]\n")
    case_id = console.input("  [cyan]Case ID[/cyan]: ").strip()
    window  = console.input("  [cyan]Time window in seconds[/cyan] (default 30): ").strip()
    window  = window if window.isdigit() else "30"

    console.print(f"\n[bold green]Running correlation engine...[/bold green]")
    subprocess.run([
        sys.executable, "-m", "traceforge.cli", "correlate",
        "--case", case_id,
        "--window", window
    ], capture_output=False)


def handle_report():
    """Interactive report generation."""
    console.print("\n[bold cyan]Generate Report[/bold cyan]\n")
    case_id = console.input("  [cyan]Case ID[/cyan]: ").strip()
    fmt     = console.input("  [cyan]Format[/cyan] [json/html/pdf/all] (default all): ").strip().lower()
    fmt     = fmt if fmt in ("json", "html", "pdf", "all") else "all"

    console.print(f"\n[bold green]Generating {fmt.upper()} report...[/bold green]")
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
    console.print("  Opening at: [bold green]http://127.0.0.1:5000[/bold green]")
    console.print("  Press [bold red]Ctrl+C[/bold red] to stop the dashboard\n")

    try:
        subprocess.run([
            sys.executable, "-m", "dashboard.app"
        ], capture_output=False)
    except KeyboardInterrupt:
        console.print("\n[yellow]Dashboard stopped.[/yellow]")


def handle_full_pipeline():
    """Run the full pipeline interactively."""
    console.print("\n[bold cyan]Full Pipeline — New Case to Report[/bold cyan]\n")
    console.print("  [dim]Create case → Analyze → Correlate → Report[/dim]\n")

    case_id = console.input("  [cyan]Case ID[/cyan]: ").strip()
    name    = console.input("  [cyan]Case name[/cyan]: ").strip()
    analyst = console.input("  [cyan]Analyst name[/cyan]: ").strip()

    console.print("\n[bold green]Step 1 — Creating case...[/bold green]")
    subprocess.run([
        sys.executable, "-m", "traceforge.cli",
        "case", "new",
        "--id", case_id, "--name", name, "--analyst", analyst
    ], capture_output=False)

    while True:
        console.print("\n[bold green]Step 2 — Add evidence file[/bold green]")
        console.print("  [dim]Modules available: memory, disk, logs, network[/dim]")
        module = console.input("  [cyan]Module[/cyan] (or 'done' to skip to correlation): ").strip().lower()
        if module == "done":
            break
        if module not in ("memory", "disk", "logs", "network"):
            console.print("[bold red]Invalid module.[/bold red]")
            continue
        file_path = console.input("  [cyan]Evidence file path[/cyan]: ").strip()
        host_id   = console.input("  [cyan]Host identifier[/cyan] (optional): ").strip()

        cmd = [
            sys.executable, "-m", "traceforge.cli", "analyze",
            "--case", case_id, "--module", module,
            "--file", file_path, "--analyst", analyst
        ]
        if host_id:
            cmd += ["--host", host_id]
        subprocess.run(cmd, capture_output=False)

    console.print("\n[bold green]Step 3 — Running correlation engine...[/bold green]")
    subprocess.run([
        sys.executable, "-m", "traceforge.cli",
        "correlate", "--case", case_id
    ], capture_output=False)

    console.print("\n[bold green]Step 4 — Generating report...[/bold green]")
    subprocess.run([
        sys.executable, "-m", "traceforge.cli",
        "report", "--case", case_id, "--format", "all"
    ], capture_output=False)

    console.print(f"\n[bold green]Pipeline complete for case {case_id}[/bold green]")


def goodbye():
    """Print goodbye message on exit."""
    clear()
    console.print(Text(BANNER, style="bold cyan"))
    console.print("\n  [bold yellow]Thank you for using TraceForge v2[/bold yellow]")
    console.print("  [dim]Stay sharp. Stay forensic.[/dim]")
    console.print(f"\n  [dim]{GITHUB}[/dim]\n")


def main():
    """Main launcher loop."""
    try:
        while True:
            clear()
            print_banner()

            stats = get_live_stats()
            print_stats(stats)
            print_recent_cases(stats)
            console.print()
            print_menu()

            try:
                choice = console.input("  [bold magenta]Select an option:[/bold magenta] ").strip()
            except KeyboardInterrupt:
                goodbye()
                sys.exit(0)

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
                goodbye()
                sys.exit(0)
            else:
                console.print("\n[bold red]Invalid option.[/bold red] [dim]Please select a number from the menu.[/dim]")

            try:
                console.input("\n  [dim]Press Enter to return to menu...[/dim]")
            except KeyboardInterrupt:
                goodbye()
                sys.exit(0)

    except KeyboardInterrupt:
        goodbye()
        sys.exit(0)


if __name__ == "__main__":
    main()
