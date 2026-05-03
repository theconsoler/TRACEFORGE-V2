"""
TraceForge v2 — Artifact Schema
Standardised dataclass returned by every analysis module.
The correlation engine depends on this schema — do not change
field names without updating correlator.py in Phase 3.
"""

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any


@dataclass
class Artifact:
    """
    A single forensic artifact produced by any TraceForge module.

    Fields:
        case_id       : The investigation case this artifact belongs to
        source_module : Which module produced this (memory/disk/logs/network)
        artifact_type : What kind of artifact (process/connection/login/dns_query etc)
        timestamp     : ISO 8601 timestamp of the artifact event (not when it was recorded)
        host_id       : IP address, hostname, or machine identifier
        data          : Dict of module-specific artifact details
        recorded_at   : When this artifact was stored (auto-set, do not pass manually)
    """
    case_id:       str
    source_module: str
    artifact_type: str
    host_id:       str
    data:          dict[str, Any]
    timestamp:     str = ""
    recorded_at:   str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    # Valid module names — enforced on creation
    VALID_MODULES = {"memory", "disk", "logs", "network"}

    # Common artifact types per module
    ARTIFACT_TYPES = {
        "memory":  {"process", "network_connection", "dll", "cmdline", "registry_key"},
        "disk":    {"file", "deleted_file", "directory", "mft_entry"},
        "logs":    {"failed_login", "successful_login", "sudo_command", "service_event"},
        "network": {"dns_query", "http_request", "tcp_flow", "suspicious_connection"},
    }

    def __post_init__(self):
        if self.source_module not in self.VALID_MODULES:
            raise ValueError(
                f"Invalid source_module '{self.source_module}'. "
                f"Must be one of: {self.VALID_MODULES}"
            )

    def to_dict(self) -> dict:
        """Serialise artifact to a plain dictionary."""
        return asdict(self)

    def to_json(self) -> str:
        """Serialise artifact to a JSON string."""
        return json.dumps(self.to_dict(), indent=2)

    @classmethod
    def from_dict(cls, data: dict) -> "Artifact":
        """Deserialise an artifact from a dictionary."""
        return cls(
            case_id=data["case_id"],
            source_module=data["source_module"],
            artifact_type=data["artifact_type"],
            host_id=data["host_id"],
            data=data["data"],
            timestamp=data.get("timestamp", ""),
            recorded_at=data.get("recorded_at", datetime.now(timezone.utc).isoformat())
        )

    def summary(self) -> str:
        """Return a one-line human-readable summary of this artifact."""
        ts = self.timestamp or self.recorded_at
        return (
            f"[{self.source_module.upper()}] {self.artifact_type} | "
            f"host={self.host_id} | ts={ts[:19]} | "
            f"data={list(self.data.keys())}"
        )
