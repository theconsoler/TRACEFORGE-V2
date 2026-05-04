"""
TraceForge v2 — IOC Timeline Generator
Produces a unified chronological timeline across all modules.
Merges artifacts with their correlation links.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
from loguru import logger

from traceforge.core.artifact import Artifact
from traceforge.core.correlator import CorrelationResult
from traceforge.core.store import get_artifacts


MODULE_COLORS = {
    "memory":  "#7C3AED",
    "disk":    "#0284C7",
    "logs":    "#059669",
    "network": "#DC2626",
}

SEVERITY_MAP = {
    "brute_force_detected":   "critical",
    "suspicious_connection":  "high",
    "failed_login":           "medium",
    "sudo_command":           "medium",
    "successful_login":       "low",
    "process":                "info",
    "network_connection":     "info",
    "dns_query":              "info",
    "http_request":           "low",
    "tcp_flow":               "info",
    "file":                   "info",
    "deleted_file":           "medium",
    "cmdline":                "low",
    "service_event":          "info",
}


@dataclass
class TimelineEvent:
    """
    A single event in the unified IOC timeline.

    Fields:
        timestamp        : ISO 8601 timestamp
        module           : Source module name
        artifact_type    : Type of artifact
        host_id          : Host or IP identifier
        summary          : One-line human-readable summary
        severity         : critical / high / medium / low / info
        data             : Full artifact data dict
        correlation_links: List of descriptions of related artifacts
        color            : Module color for dashboard display
    """
    timestamp:         str
    module:            str
    artifact_type:     str
    host_id:           str
    summary:           str
    severity:          str
    data:              dict
    correlation_links: list[str] = field(default_factory=list)
    color:             str = "#6B7280"

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "module": self.module,
            "artifact_type": self.artifact_type,
            "host_id": self.host_id,
            "summary": self.summary,
            "severity": self.severity,
            "data": self.data,
            "correlation_links": self.correlation_links,
            "color": self.color
        }


def _make_summary(artifact: Artifact) -> str:
    """Generate a one-line summary for an artifact."""
    d = artifact.data
    t = artifact.artifact_type

    summaries = {
        "failed_login": lambda: f"Failed login — user: {d.get('user', '?')} from {d.get('src_ip', '?')}",
        "successful_login": lambda: f"Successful login — user: {d.get('user', '?')} from {d.get('src_ip', '?')}",
        "sudo_command": lambda: f"Sudo command — {d.get('user', '?')}: {d.get('command', '?')[:60]}",
        "process": lambda: f"Process — {d.get('name', '?')} (PID {d.get('pid', '?')}, PPID {d.get('ppid', '?')})",
        "network_connection": lambda: f"Connection — {d.get('local_addr', '?')}:{d.get('local_port', '?')} -> {d.get('remote_addr', '?')}:{d.get('remote_port', '?')} [{d.get('state', '?')}]",
        "dns_query": lambda: f"DNS query — {d.get('query', '?')} from {d.get('src_ip', '?')}",
        "http_request": lambda: f"HTTP {d.get('method', '?')} {d.get('host', '?')}{d.get('uri', '?')}",
        "tcp_flow": lambda: f"TCP flow — {d.get('src_ip', '?')}:{d.get('src_port', '?')} -> {d.get('dst_ip', '?')}:{d.get('dst_port', '?')} ({d.get('total_bytes', 0):,} bytes)",
        "suspicious_connection": lambda: f"SUSPICIOUS — {d.get('src_ip', '?')}:{d.get('src_port', '?')} -> {d.get('dst_ip', '?')}:{d.get('dst_port', '?')}",
        "file": lambda: f"File — {d.get('path', d.get('name', '?'))} ({d.get('size_bytes', 0):,} bytes)",
        "deleted_file": lambda: f"Deleted file — {d.get('path', d.get('name', '?'))}",
        "cmdline": lambda: f"Command line — PID {d.get('pid', '?')}: {d.get('commandline', '?')[:80]}",
        "service_event": lambda: f"Service {d.get('event', '?')} — {d.get('service', '?')}",
    }

    if t in summaries:
        try:
            return summaries[t]()
        except Exception:
            pass

    if d.get("type") == "brute_force_detected":
        return f"BRUTE FORCE — {d.get('attempt_count', '?')} attempts from {d.get('src_ip', '?')}"

    return f"{t} on {artifact.host_id}"


def build_timeline(
    case_id: str,
    correlation_results: Optional[list[CorrelationResult]] = None
) -> list[TimelineEvent]:
    """
    Build a unified IOC timeline for a case.

    Args:
        case_id             : The investigation case ID
        correlation_results : Optional pre-computed correlation results

    Returns:
        List of TimelineEvent objects sorted chronologically
    """
    artifacts = get_artifacts(case_id)

    if not artifacts:
        logger.warning(f"No artifacts to build timeline for case {case_id}")
        return []

    logger.info(f"Building timeline for {len(artifacts)} artifacts")

    # Build correlation index: artifact id -> list of link descriptions
    corr_index: dict[int, list[str]] = {}
    if correlation_results:
        for r in correlation_results:
            a_id = id(r.artifact_a)
            b_id = id(r.artifact_b)
            corr_index.setdefault(a_id, []).append(r.description)
            corr_index.setdefault(b_id, []).append(r.description)

    events = []
    for artifact in artifacts:
        event = TimelineEvent(
            timestamp=artifact.timestamp or artifact.recorded_at,
            module=artifact.source_module,
            artifact_type=artifact.artifact_type,
            host_id=artifact.host_id,
            summary=_make_summary(artifact),
            severity=SEVERITY_MAP.get(artifact.artifact_type, "info"),
            data=artifact.data,
            correlation_links=corr_index.get(id(artifact), []),
            color=MODULE_COLORS.get(artifact.source_module, "#6B7280")
        )
        events.append(event)

    # Sort by timestamp, put events without timestamps at the end
    def sort_key(e: TimelineEvent):
        try:
            return datetime.fromisoformat(e.timestamp.replace("Z", "+00:00"))
        except Exception:
            return datetime.max.replace(tzinfo=timezone.utc)

    events.sort(key=sort_key)

    severity_counts = {}
    for e in events:
        severity_counts[e.severity] = severity_counts.get(e.severity, 0) + 1

    logger.info(f"Timeline built: {len(events)} events | {severity_counts}")
    return events


def timeline_to_dict(events: list[TimelineEvent]) -> list[dict]:
    """Serialise timeline events to a list of dicts."""
    return [e.to_dict() for e in events]
