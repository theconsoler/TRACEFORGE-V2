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
@click.option("--case",    "case_id",  required=True, help="Case ID")
@click.option("--image",   required=True,              help="Path to memory image")
@click.option("--analyst", required=True,              help="Analyst name or ID")
@click.option("--host",    "host_id",  default=None,   help="Host identifier")
@click.option("--plugins", default="pslist,netstat,cmdline",
              help="Comma-separated list of plugins to run")
def memory(case_id, image, analyst, host_id, plugins):
    """Run memory forensics on a memory dump."""
    from traceforge.modules.memory import analyze
    plugin_list = [p.strip() for p in plugins.split(",")]
    console.print(f"\n[bold cyan]Memory Forensics Analysis[/bold cyan]")
    console.print(f"  Case    : {case_id}")
    console.print(f"  Image   : {image}")
    console.print(f"  Plugins : {plugin_list}\n")
    try:
        artifacts = analyze(case_id, image, analyst, host_id, plugin_list)
        console.print(f"[bold green]{len(artifacts)} artifacts found[/bold green]\n")
        for a in artifacts[:30]:
            console.print(f"  [cyan]{a.artifact_type:<25}[/cyan] {a.summary()}")
        if len(artifacts) > 30:
            console.print(f"  [dim]... and {len(artifacts) - 30} more[/dim]")
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")


@cli.command()
@click.option("--case",    "case_id",  required=True, help="Case ID")
@click.option("--image",   required=True,              help="Path to disk image or directory")
@click.option("--analyst", required=True,              help="Analyst name or ID")
@click.option("--host",    "host_id",  default=None,   help="Host identifier")
def disk(case_id, image, analyst, host_id):
    """Run disk image analysis."""
    from traceforge.modules.disk import analyze
    console.print(f"\n[bold cyan]Disk Image Analysis[/bold cyan]")
    console.print(f"  Case  : {case_id} | Image : {image}\n")
    try:
        artifacts = analyze(case_id, image, analyst, host_id)
        console.print(f"[bold green]{len(artifacts)} artifacts found[/bold green]\n")
        for a in artifacts[:20]:
            console.print(f"  [cyan]{a.artifact_type:<25}[/cyan] {a.summary()}")
        if len(artifacts) > 20:
            console.print(f"  [dim]... and {len(artifacts) - 20} more[/dim]")
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")

@cli.command()
@click.option("--case",    "case_id",   required=True, help="Case ID")
@click.option("--file",    "log_file",  required=True, help="Path to log file")
@click.option("--analyst", required=True,               help="Analyst name or ID")
@click.option("--host",    "host_id",   default=None,   help="Hostname or IP of log source")
def logs(case_id, log_file, analyst, host_id):
    """Run log correlation analysis."""
    from traceforge.modules.logs import analyze
    console.print(f"\n[bold cyan]Log Correlation Analysis[/bold cyan]")
    console.print(f"  Case : {case_id} | File : {log_file}\n")
    try:
        artifacts = analyze(case_id, log_file, analyst, host_id)
        console.print(f"[bold green]{len(artifacts)} artifacts found[/bold green]\n")
        for a in artifacts:
            console.print(f"  [cyan]{a.artifact_type:<25}[/cyan] {a.summary()}")
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")

@cli.command()
@click.option("--case",    "case_id",  required=True, help="Case ID")
@click.option("--pcap",    required=True,              help="Path to PCAP file")
@click.option("--analyst", required=True,              help="Analyst name or ID")
@click.option("--host",    "host_id",  default=None,   help="Host identifier")
def network(case_id, pcap, analyst, host_id):
    """Run network packet analysis."""
    from traceforge.modules.network import analyze
    console.print(f"\n[bold cyan]Network Packet Analysis[/bold cyan]")
    console.print(f"  Case : {case_id} | PCAP : {pcap}\n")
    try:
        artifacts = analyze(case_id, pcap, analyst, host_id)
        console.print(f"[bold green]{len(artifacts)} artifacts found[/bold green]\n")
        for a in artifacts:
            console.print(f"  [cyan]{a.artifact_type:<25}[/cyan] {a.summary()}")
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")


@cli.command()
@click.option("--case",    "case_id", required=True, help="Case ID")
@click.option("--format",  "fmt",     default="all",
              type=click.Choice(["json", "html", "pdf", "all"]),
              help="Output format (default: all)")
@click.option("--output",  "out_dir", default=None, help="Output directory")
def report(case_id, fmt, out_dir):
    """Generate case report in JSON, HTML, and/or PDF."""
    from traceforge.core.report import generate_report
    from traceforge.core.store import save_artifacts
    formats = ["json", "html", "pdf"] if fmt == "all" else [fmt]
    console.print(f"\n[bold cyan]Generating Case Report[/bold cyan]")
    console.print(f"  Case    : {case_id}")
    console.print(f"  Formats : {formats}\n")
    try:
        paths = generate_report(case_id, formats, out_dir)
        console.print(f"[bold green]Report generated successfully[/bold green]\n")
        for fmt_name, path in paths.items():
            console.print(f"  {fmt_name.upper():<6} : {path}")
        console.print()
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")


@cli.command()
@click.option("--case",   "case_id", required=True, help="Case ID to correlate")
@click.option("--window", default=30, help="Timestamp proximity window in seconds")
def correlate(case_id, window):
    """Run cross-module correlation engine."""
    from traceforge.core.correlator import correlate as run_correlate, correlate_summary
    console.print(f"\n[bold cyan]Cross-Module Correlation Engine[/bold cyan]")
    console.print(f"  Case: {case_id} | Window: {window}s\n")
    results = run_correlate(case_id, window)
    summary = correlate_summary(results)
    console.print(f"[bold green]Correlation complete[/bold green]")
    console.print(f"  Total links      : {summary['total']}")
    console.print(f"  High confidence  : {summary['high_confidence']}")
    console.print(f"  Medium confidence: {summary['medium_confidence']}")
    console.print(f"  Low confidence   : {summary['low_confidence']}\n")
    for r in results[:10]:
        conf_color = "red" if r.confidence >= 0.8 else "yellow" if r.confidence >= 0.5 else "dim"
        console.print(f"  [{conf_color}]{r.confidence:.0%}[/{conf_color}] {r.description}")
    if len(results) > 10:
        console.print(f"  [dim]... and {len(results) - 10} more[/dim]")


@cli.command()
def banner():
    """Show TraceForge banner."""
    console.print(BANNER)


# ── ADD THE ANALYZE COMMAND HERE ──────────────────────────────────────────────

@cli.command()
@click.option("--case",    "case_id",   required=True, help="Case ID")
@click.option("--module",  required=True,
              type=click.Choice(["memory", "disk", "logs", "network"]),
              help="Module to run and store artifacts for")
@click.option("--file",    "file_path", required=True, help="Path to evidence file")
@click.option("--analyst", required=True,               help="Analyst name or ID")
@click.option("--host",    "host_id",   default=None,   help="Host identifier")
def analyze(case_id, module, file_path, analyst, host_id):
    """Run a module and store artifacts for correlation."""
    from traceforge.core.store import save_artifacts
    module_map = {
        "logs":    ("traceforge.modules.logs",    "analyze"),
        "network": ("traceforge.modules.network", "analyze"),
        "disk":    ("traceforge.modules.disk",    "analyze"),
        "memory":  ("traceforge.modules.memory",  "analyze"),
    }
    import importlib
    mod_path, func_name = module_map[module]
    mod = importlib.import_module(mod_path)
    analyze_fn = getattr(mod, func_name)
    console.print(f"\n[bold cyan]Running {module.upper()} analysis and storing artifacts[/bold cyan]\n")
    try:
        artifacts = analyze_fn(case_id, file_path, analyst, host_id)
        saved = save_artifacts(artifacts)
        console.print(f"[bold green]{len(artifacts)} artifacts found, {saved} stored[/bold green]")
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")


# ── ENTRY POINT ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    cli()

from traceforge.core.store import save_artifacts
