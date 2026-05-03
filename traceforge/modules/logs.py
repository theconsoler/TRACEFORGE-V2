"""
TraceForge v2 — Log Correlation Module
Parses Linux auth logs, syslog, and structured log files.
Extracts authentication events, sudo usage, and suspicious patterns.
"""

import re
from pathlib import Path
from datetime import datetime, timezone
from collections import defaultdict
from loguru import logger
from typing import Optional

from traceforge.core.artifact import Artifact
from traceforge.core.hasher import compute_sha256
from traceforge.core.ledger import init_db, log_evidence


# Regex patterns for log parsing
PATTERNS = {
    "failed_login": re.compile(
        r"(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+\S+:\s+Failed password for (?:invalid user )?(\S+) from (\S+) port"
    ),
    "successful_login": re.compile(
        r"(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+\S+:\s+Accepted (?:password|publickey) for (\S+) from (\S+) port"
    ),
    "sudo_command": re.compile(
        r"(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+sudo:\s+(\S+)\s+:.*COMMAND=(.*)"
    ),
    "service_start": re.compile(
        r"(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+systemd\[\d+\]:\s+Started (.+)\."
    ),
}

BRUTE_FORCE_THRESHOLD = 5


def _parse_timestamp(raw: str) -> str:
    """Convert log timestamp to ISO 8601. Returns raw string if parsing fails."""
    try:
        current_year = datetime.now().year
        dt = datetime.strptime(f"{current_year} {raw.strip()}", "%Y %b %d %H:%M:%S")
        return dt.replace(tzinfo=timezone.utc).isoformat()
    except ValueError:
        return raw.strip()


def analyze(
    case_id: str,
    log_path: str,
    analyst: str,
    host_id: Optional[str] = None
) -> list[Artifact]:
    """
    Analyze a log file and return a list of Artifact objects.

    Args:
        case_id   : The investigation case ID
        log_path  : Path to the log file
        analyst   : Analyst name or ID
        host_id   : Optional hostname or IP of the machine the log came from

    Returns:
        List of Artifact objects representing forensic findings
    """
    init_db()
    path = Path(log_path)

    if not path.exists():
        raise FileNotFoundError(f"Log file not found: {log_path}")

    # Hash before analysis — chain of custody
    sha256, size = compute_sha256(path)
    log_evidence(case_id, analyst, str(path), sha256, size, "logs")

    logger.info(f"Analyzing log file: {path.name} | Case: {case_id}")

    artifacts = []
    failed_logins: dict[str, list] = defaultdict(list)
    host = host_id or path.stem

    with open(path, "r", errors="replace") as f:
        lines = f.readlines()

    for line in lines:
        line = line.strip()
        if not line:
            continue

        # Failed login attempts
        m = PATTERNS["failed_login"].search(line)
        if m:
            ts, hostname, user, src_ip = m.groups()
            failed_logins[src_ip].append({
                "timestamp": _parse_timestamp(ts),
                "user": user,
                "hostname": hostname,
                "raw": line
            })
            artifacts.append(Artifact(
                case_id=case_id,
                source_module="logs",
                artifact_type="failed_login",
                host_id=host,
                timestamp=_parse_timestamp(ts),
                data={
                    "user": user,
                    "src_ip": src_ip,
                    "hostname": hostname,
                    "raw_line": line
                }
            ))
            continue

        # Successful logins
        m = PATTERNS["successful_login"].search(line)
        if m:
            ts, hostname, user, src_ip = m.groups()
            artifacts.append(Artifact(
                case_id=case_id,
                source_module="logs",
                artifact_type="successful_login",
                host_id=host,
                timestamp=_parse_timestamp(ts),
                data={
                    "user": user,
                    "src_ip": src_ip,
                    "hostname": hostname,
                    "raw_line": line
                }
            ))
            continue

        # Sudo commands
        m = PATTERNS["sudo_command"].search(line)
        if m:
            ts, hostname, user, command = m.groups()
            artifacts.append(Artifact(
                case_id=case_id,
                source_module="logs",
                artifact_type="sudo_command",
                host_id=host,
                timestamp=_parse_timestamp(ts),
                data={
                    "user": user,
                    "command": command.strip(),
                    "hostname": hostname,
                    "raw_line": line
                }
            ))
            continue

        # Service events
        m = PATTERNS["service_start"].search(line)
        if m:
            ts, hostname, service = m.groups()
            artifacts.append(Artifact(
                case_id=case_id,
                source_module="logs",
                artifact_type="service_event",
                host_id=host,
                timestamp=_parse_timestamp(ts),
                data={
                    "service": service.strip(),
                    "hostname": hostname,
                    "event": "started",
                    "raw_line": line
                }
            ))

    # Detect brute force — flag IPs with >= threshold failed logins
    for src_ip, attempts in failed_logins.items():
        if len(attempts) >= BRUTE_FORCE_THRESHOLD:
            logger.warning(
                f"Brute force detected: {src_ip} — {len(attempts)} failed attempts"
            )
            artifacts.append(Artifact(
                case_id=case_id,
                source_module="logs",
                artifact_type="failed_login",
                host_id=host,
                timestamp=attempts[0]["timestamp"],
                data={
                    "type": "brute_force_detected",
                    "src_ip": src_ip,
                    "attempt_count": len(attempts),
                    "targeted_users": list({a["user"] for a in attempts}),
                    "first_attempt": attempts[0]["timestamp"],
                    "last_attempt": attempts[-1]["timestamp"]
                }
            ))

    logger.info(f"Log analysis complete: {len(artifacts)} artifacts found")
    return artifacts
