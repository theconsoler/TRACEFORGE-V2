"""
TraceForge v2 — CLI Entry Point
Run: python -m traceforge.cli --help
"""

import click
from rich.console import Console
from rich.table import Table
from rich import box
from loguru import logger
import sys
import os

from traceforge.core.ledger import init_db, create_case, get_case, list_cases, log_evidence
from traceforge.core.hasher import compute_sha256, verify_hash

console = Console()

BANNER = """
[bold cyan]
 ████████╗██████╗  █████╗  ██████╗███████╗███████╗ ██████╗ ██████╗  ██████╗ ███████╗
    ██╔══╝██╔══██╗██╔══██╗██╔════╝██╔════╝██╔════╝██╔═══██╗██╔══██╗██╔════╝ ██╔════╝
    ██║   ██████╔╝███████║██║     █████╗  █████╗  ██║   ██║██████╔╝██║  ███╗█████╗
    ██║   ██╔══██╗██╔══██║██║     ██╔══╝  ██╔══╝  ██║   ██║██╔══██╗██║   ██║██╔══╝
    ██║   ██║  ██║██║  ██║╚██████╗███████╗██║     ╚██████╔╝██║  ██║╚██████╔╝███████╗
    ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚══════╝╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝
[/bold cyan]
[bold white]    Digital Forensics & Incident Response Toolkit v2[/bold white]
[dim]    github.com/theconsoler/TRACEFORGE-V2[/dim]
"""


@click.group()
def cli():
    """TraceForge v2 — DFIR Toolkit"""
    init_db()


# ── CASE MANAGEMENT ──────────────────────────────────────────────────────────

@cli.group()
def case():
    """Create and manage investigation cases."""
    pass


@case.command("new")
@click.option("--id",       "case_id",  required=True,  help="Unique case identifier (e.g. CASE-2026-001)")
@click.option("--name",     required=True,               help="Case name or description")
@click.option("--analyst",  required=True,               help="Analyst name or ID")
@click.option("--notes",    default="",                  help="Optional notes")
def case_new(case_id, name, analyst, notes):
    """Create a new investigation case."""
    try:
        result = create_case(case_id, name, analyst, notes)
        console.print(f"\n[bold green]Case created successfully[/bold green]")
        console.print(f"  ID      : [cyan]{result['case_id']}[/cyan]")
        console.print(f"  Name    : {result['name']}")
        console.print(f"  Analyst : {result['analyst']}")
        console.print(f"  Created : {result['created_at']}\n")
    except ValueError as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        sys.exit(1)


@case.command("list")
def case_list():
    """List all investigation cases."""
    cases = list_cases()
    if not cases:
        console.print("[yellow]No cases found. Create one with: traceforge case new[/yellow]")
        return

    table = Table(box=box.ROUNDED, show_header=True, header_style="bold cyan")
    table.add_column("Case ID", style="cyan")
    table.add_column("Name")
    table.add_column("Analyst")
    table.add_column("Created")

    for c in cases:
        table.add_row(c["id"], c["name"], c["analyst"], c["created_at"][:19])

    console.print(table)


@case.command("info")
@click.argument("case_id")
def case_info(case_id):
    """Show details for a specific case."""
    c = get_case(case_id)
    if not c:
        console.print(f"[bold red]Case '{case_id}' not found.[/bold red]")
        sys.exit(1)

    console.print(f"\n[bold cyan]Case: {c['id']}[/bold cyan]")
    console.print(f"  Name    : {c['name']}")
    console.print(f"  Analyst : {c['analyst']}")
    console.print(f"  Created : {c['created_at']}")
    console.print(f"  Notes   : {c['notes'] or 'None'}\n")


# ── EVIDENCE MANAGEMENT ───────────────────────────────────────────────────────

@cli.command()
@click.option("--case",     "case_id",  required=True, help="Case ID to log evidence for")
@click.option("--file",     "file_path", required=True, help="Path to evidence file")
@click.option("--analyst",  required=True,              help="Analyst name or ID")
@click.option("--module",   required=True,
              type=click.Choice(["memory", "disk", "logs", "network"]),
              help="Module this evidence is for")
@click.option("--notes",    default="",                 help="Optional notes")
def ingest(case_id, file_path, analyst, module, notes):
    """Hash and log an evidence file into the ledger before analysis."""
    console.print(f"\n[bold]Ingesting evidence:[/bold] {file_path}")

    try:
        sha256, size = compute_sha256(file_path)
        row_id = log_evidence(case_id, analyst, file_path, sha256, size, module, notes)

        console.print(f"[bold green]Evidence logged successfully[/bold green]")
        console.print(f"  Ledger ID : {row_id}")
        console.print(f"  SHA-256   : [cyan]{sha256}[/cyan]")
        console.print(f"  Size      : {size:,} bytes")
        console.print(f"  Module    : {module}\n")

    except FileNotFoundError as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        sys.exit(1)
    except ValueError as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        sys.exit(1)


# ── ANALYSIS MODULE STUBS ─────────────────────────────────────────────────────

@cli.command()
@click.option("--case",  "case_id",   required=True, help="Case ID")
@click.option("--image", required=True,               help="Path to memory image file")
def memory(case_id, image):
    """Run memory forensics on a memory dump. (Phase 2)"""
    console.print(f"[yellow]Memory module — coming in Phase 2[/yellow]")
    console.print(f"  Case  : {case_id}")
    console.print(f"  Image : {image}")


@cli.command()
@click.option("--case",  "case_id",   required=True, help="Case ID")
@click.option("--image", required=True,               help="Path to disk image file")
def disk(case_id, image):
    """Run disk image analysis. (Phase 2)"""
    console.print(f"[yellow]Disk module — coming in Phase 2[/yellow]")
    console.print(f"  Case  : {case_id}")
    console.print(f"  Image : {image}")


@cli.command()
@click.option("--case",  "case_id",   required=True, help="Case ID")
@click.option("--file",  "log_file",  required=True, help="Path to log file")
def logs(case_id, log_file):
    """Run log correlation analysis. (Phase 2)"""
    console.print(f"[yellow]Logs module — coming in Phase 2[/yellow]")
    console.print(f"  Case : {case_id}")
    console.print(f"  File : {log_file}")


@cli.command()
@click.option("--case",  "case_id",   required=True, help="Case ID")
@click.option("--pcap",  required=True,               help="Path to PCAP file")
def network(case_id, pcap):
    """Run network packet analysis. (Phase 2)"""
    console.print(f"[yellow]Network module — coming in Phase 2[/yellow]")
    console.print(f"  Case : {case_id}")
    console.print(f"  PCAP : {pcap}")


@cli.command()
@click.option("--case",   "case_id",  required=True, help="Case ID")
@click.option("--format", "fmt",      default="json",
              type=click.Choice(["json", "html", "pdf"]),
              help="Output format")
def report(case_id, fmt):
    """Generate case report. (Phase 3)"""
    console.print(f"[yellow]Report module — coming in Phase 3[/yellow]")
    console.print(f"  Case   : {case_id}")
    console.print(f"  Format : {fmt}")


@cli.command()
@click.option("--case", "case_id", required=True, help="Case ID to correlate")
def correlate(case_id):
    """Run cross-module correlation engine. (Phase 3)"""
    console.print(f"[yellow]Correlation engine — coming in Phase 3[/yellow]")
    console.print(f"  Case : {case_id}")


@cli.command()
def banner():
    """Show TraceForge banner."""
    console.print(BANNER)


if __name__ == "__main__":
    cli()
