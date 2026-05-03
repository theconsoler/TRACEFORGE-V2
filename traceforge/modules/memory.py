"""
TraceForge v2 — Memory Forensics Module
Uses Volatility3 Python API directly — no subprocess calls.
Runs PsList, NetStat, CmdLine, and DllList plugins programmatically.
"""

from pathlib import Path
from datetime import datetime, timezone
from typing import Optional
from loguru import logger

from traceforge.core.artifact import Artifact
from traceforge.core.hasher import compute_sha256
from traceforge.core.ledger import init_db, log_evidence

# Volatility3 imports
try:
    import volatility3
    from volatility3 import framework
    from volatility3.framework import contexts, automagic, interfaces
    from volatility3.framework.configuration import requirements
    from volatility3.plugins.windows import pslist, netstat, cmdline, dlllist
    from volatility3.plugins.linux import pslist as linux_pslist
    VOL3_AVAILABLE = True
    logger.info(f"Volatility3 {volatility3.__version__} available")
except ImportError as e:
    VOL3_AVAILABLE = False
    logger.warning(f"Volatility3 not fully available: {e}")


def _build_context(image_path: str):
    """Build a Volatility3 context for the given memory image."""
    ctx = contexts.Context()
    ctx.config["automagic.LayerStacker.single_location"] = f"file://{image_path}"
    return ctx


def _run_pslist(ctx, case_id: str, host_id: str) -> list[Artifact]:
    """Run PsList plugin and return process artifacts."""
    artifacts = []
    try:
        automagics = automagic.choose_automagic(
            automagic.available(ctx), pslist.PsList
        )
        plugin = automagic.run(automagics, pslist.PsList, ctx, "plugins")

        for proc in plugin.run():
            try:
                pid = int(proc.UniqueProcessId)
                ppid = int(proc.InheritedFromUniqueProcessId)
                name = proc.ImageFileName.cast(
                    "string",
                    max_length=proc.ImageFileName.vol.count,
                    errors="replace"
                )
                create_time = ""
                try:
                    create_time = proc.CreateTime.strftime("%Y-%m-%dT%H:%M:%SZ")
                except Exception:
                    pass

                artifacts.append(Artifact(
                    case_id=case_id,
                    source_module="memory",
                    artifact_type="process",
                    host_id=host_id,
                    timestamp=create_time,
                    data={
                        "pid": pid,
                        "ppid": ppid,
                        "name": str(name),
                        "create_time": create_time,
                        "plugin": "PsList"
                    }
                ))
            except Exception as e:
                logger.debug(f"Skipping process entry: {e}")
                continue

    except Exception as e:
        logger.error(f"PsList failed: {e}")

    return artifacts


def _run_netstat(ctx, case_id: str, host_id: str) -> list[Artifact]:
    """Run NetStat plugin and return network connection artifacts."""
    artifacts = []
    try:
        automagics = automagic.choose_automagic(
            automagic.available(ctx), netstat.NetStat
        )
        plugin = automagic.run(automagics, netstat.NetStat, ctx, "plugins")

        for conn in plugin.run():
            try:
                artifacts.append(Artifact(
                    case_id=case_id,
                    source_module="memory",
                    artifact_type="network_connection",
                    host_id=host_id,
                    timestamp="",
                    data={
                        "pid": int(conn.PID),
                        "protocol": str(conn.Proto),
                        "local_addr": str(conn.LocalAddr),
                        "local_port": int(conn.LocalPort),
                        "remote_addr": str(conn.ForeignAddr),
                        "remote_port": int(conn.ForeignPort),
                        "state": str(conn.State),
                        "plugin": "NetStat"
                    }
                ))
            except Exception as e:
                logger.debug(f"Skipping connection entry: {e}")
                continue

    except Exception as e:
        logger.error(f"NetStat failed: {e}")

    return artifacts


def _run_cmdline(ctx, case_id: str, host_id: str) -> list[Artifact]:
    """Run CmdLine plugin and return command line artifacts."""
    artifacts = []
    try:
        automagics = automagic.choose_automagic(
            automagic.available(ctx), cmdline.CmdLine
        )
        plugin = automagic.run(automagics, cmdline.CmdLine, ctx, "plugins")

        for proc in plugin.run():
            try:
                pid = int(proc.PID)
                name = str(proc.ImageFileName)
                args = str(proc.Args) if proc.Args else ""

                artifacts.append(Artifact(
                    case_id=case_id,
                    source_module="memory",
                    artifact_type="cmdline",
                    host_id=host_id,
                    timestamp="",
                    data={
                        "pid": pid,
                        "name": name,
                        "commandline": args,
                        "plugin": "CmdLine"
                    }
                ))
            except Exception as e:
                logger.debug(f"Skipping cmdline entry: {e}")
                continue

    except Exception as e:
        logger.error(f"CmdLine failed: {e}")

    return artifacts


def analyze(
    case_id: str,
    image_path: str,
    analyst: str,
    host_id: Optional[str] = None,
    plugins: Optional[list[str]] = None
) -> list[Artifact]:
    """
    Analyze a memory image using Volatility3 and return Artifact objects.

    Args:
        case_id    : The investigation case ID
        image_path : Path to memory image (.raw, .mem, .lime, .vmem)
        analyst    : Analyst name or ID
        host_id    : Optional host identifier
        plugins    : List of plugins to run. Defaults to ["pslist", "netstat", "cmdline"]

    Returns:
        List of Artifact objects
    """
    init_db()
    path = Path(image_path)

    if not path.exists():
        raise FileNotFoundError(f"Memory image not found: {image_path}")

    if not VOL3_AVAILABLE:
        raise RuntimeError(
            "Volatility3 is not fully available. "
            "Run: pip install volatility3"
        )

    # Hash before analysis — chain of custody
    sha256, size = compute_sha256(path)
    log_evidence(case_id, analyst, str(path), sha256, size, "memory")

    host = host_id or path.stem
    active_plugins = plugins or ["pslist", "netstat", "cmdline"]

    logger.info(
        f"Memory analysis: {path.name} | "
        f"Case: {case_id} | Plugins: {active_plugins}"
    )

    ctx = _build_context(str(path.resolve()))
    artifacts = []

    plugin_map = {
        "pslist":   _run_pslist,
        "netstat":  _run_netstat,
        "cmdline":  _run_cmdline,
    }

    for plugin_name in active_plugins:
        if plugin_name in plugin_map:
            logger.info(f"Running plugin: {plugin_name}")
            results = plugin_map[plugin_name](ctx, case_id, host)
            artifacts.extend(results)
            logger.info(f"{plugin_name}: {len(results)} artifacts")
        else:
            logger.warning(f"Unknown plugin: {plugin_name} — skipping")

    logger.info(f"Memory analysis complete: {len(artifacts)} total artifacts")
    return artifacts
