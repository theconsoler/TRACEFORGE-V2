"""
TraceForge v2 — Cross-Module Correlation Engine
Links artifacts across memory, disk, logs, and network modules.
Two strategies: timestamp proximity and host/IP matching.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
from loguru import logger

from traceforge.core.artifact import Artifact
from traceforge.core.store import get_artifacts


TIMESTAMP_WINDOW_SECONDS = 30


@dataclass
class CorrelationResult:
    """
    A link between two artifacts from different modules.

    Fields:
        artifact_a    : First artifact
        artifact_b    : Second artifact
        link_type     : How they were linked (timestamp_proximity / host_match / ip_match)
        confidence    : 0.0 to 1.0 confidence score
        description   : Human-readable explanation of the link
    """
    artifact_a:  Artifact
    artifact_b:  Artifact
    link_type:   str
    confidence:  float
    description: str


def _parse_ts(ts: str) -> Optional[datetime]:
    """Parse an ISO 8601 timestamp string into a datetime object."""
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except Exception:
        return None


def _ts_diff_seconds(a: Artifact, b: Artifact) -> Optional[float]:
    """Return absolute difference in seconds between two artifact timestamps."""
    ts_a = _parse_ts(a.timestamp)
    ts_b = _parse_ts(b.timestamp)
    if ts_a and ts_b:
        return abs((ts_a - ts_b).total_seconds())
    return None


def _extract_ips(artifact: Artifact) -> set[str]:
    """Extract all IP addresses from an artifact's data dict."""
    ips = set()
    ip_fields = ["src_ip", "dst_ip", "remote_addr", "local_addr", "ip"]
    for field_name in ip_fields:
        val = artifact.data.get(field_name)
        if val and isinstance(val, str) and val not in ("0.0.0.0", "::"):
            ips.add(val)
    return ips


def _correlate_by_timestamp(
    artifacts: list[Artifact],
    window_seconds: int = TIMESTAMP_WINDOW_SECONDS
) -> list[CorrelationResult]:
    """
    Find artifacts from different modules that occurred within
    the timestamp window of each other.
    """
    results = []

    for i, a in enumerate(artifacts):
        for b in artifacts[i + 1:]:
            if a.source_module == b.source_module:
                continue

            diff = _ts_diff_seconds(a, b)
            if diff is None:
                continue

            if diff <= window_seconds:
                confidence = round(1.0 - (diff / window_seconds), 2)
                results.append(CorrelationResult(
                    artifact_a=a,
                    artifact_b=b,
                    link_type="timestamp_proximity",
                    confidence=max(confidence, 0.1),
                    description=(
                        f"{a.source_module.upper()} [{a.artifact_type}] and "
                        f"{b.source_module.upper()} [{b.artifact_type}] "
                        f"occurred within {diff:.1f}s of each other"
                    )
                ))

    return results


def _correlate_by_host(
    artifacts: list[Artifact]
) -> list[CorrelationResult]:
    """
    Find artifacts from different modules that share the same
    host ID, IP address, or hostname.
    """
    results = []

    for i, a in enumerate(artifacts):
        for b in artifacts[i + 1:]:
            if a.source_module == b.source_module:
                continue

            # Direct host_id match
            if (a.host_id and b.host_id and
                    a.host_id == b.host_id and
                    a.host_id != "unknown"):
                results.append(CorrelationResult(
                    artifact_a=a,
                    artifact_b=b,
                    link_type="host_match",
                    confidence=0.9,
                    description=(
                        f"{a.source_module.upper()} [{a.artifact_type}] and "
                        f"{b.source_module.upper()} [{b.artifact_type}] "
                        f"share host: {a.host_id}"
                    )
                ))
                continue

            # IP address match across artifact data fields
            ips_a = _extract_ips(a)
            ips_b = _extract_ips(b)
            shared_ips = ips_a & ips_b

            if shared_ips:
                for ip in shared_ips:
                    results.append(CorrelationResult(
                        artifact_a=a,
                        artifact_b=b,
                        link_type="ip_match",
                        confidence=0.85,
                        description=(
                            f"{a.source_module.upper()} [{a.artifact_type}] and "
                            f"{b.source_module.upper()} [{b.artifact_type}] "
                            f"share IP address: {ip}"
                        )
                    ))

    return results


def _deduplicate(results: list[CorrelationResult]) -> list[CorrelationResult]:
    """Remove duplicate correlation results keeping highest confidence."""
    seen = {}
    for r in results:
        key = (
            id(r.artifact_a),
            id(r.artifact_b),
            r.link_type
        )
        if key not in seen or r.confidence > seen[key].confidence:
            seen[key] = r
    return list(seen.values())


def correlate(
    case_id: str,
    window_seconds: int = TIMESTAMP_WINDOW_SECONDS
) -> list[CorrelationResult]:
    """
    Run the full correlation engine for a case.
    Loads all artifacts from the store and finds cross-module links.

    Args:
        case_id        : The investigation case ID
        window_seconds : Timestamp proximity window in seconds

    Returns:
        List of CorrelationResult objects sorted by confidence descending
    """
    artifacts = get_artifacts(case_id)

    if not artifacts:
        logger.warning(f"No artifacts found for case {case_id}")
        return []

    logger.info(
        f"Running correlation on {len(artifacts)} artifacts "
        f"for case {case_id}"
    )

    results = []

    ts_results = _correlate_by_timestamp(artifacts, window_seconds)
    logger.info(f"Timestamp proximity: {len(ts_results)} links found")
    results.extend(ts_results)

    host_results = _correlate_by_host(artifacts)
    logger.info(f"Host/IP matching: {len(host_results)} links found")
    results.extend(host_results)

    results = _deduplicate(results)
    results.sort(key=lambda r: r.confidence, reverse=True)

    logger.info(f"Correlation complete: {len(results)} total links")
    return results


def correlate_summary(results: list[CorrelationResult]) -> dict:
    """Return a summary dict of correlation results by link type."""
    summary = {
        "total": len(results),
        "by_type": {},
        "high_confidence": len([r for r in results if r.confidence >= 0.8]),
        "medium_confidence": len([r for r in results if 0.5 <= r.confidence < 0.8]),
        "low_confidence": len([r for r in results if r.confidence < 0.5])
    }
    for r in results:
        summary["by_type"][r.link_type] = summary["by_type"].get(r.link_type, 0) + 1
    return summary
