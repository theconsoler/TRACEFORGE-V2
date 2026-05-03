"""
TraceForge v2 — Disk Image Analysis Module
Traverses disk images using dfVFS when available.
Falls back to filesystem traversal for accessible directories.
Extracts file timelines, deleted file markers, and metadata.
"""

from pathlib import Path
from datetime import datetime, timezone
from typing import Optional
from loguru import logger

from traceforge.core.artifact import Artifact
from traceforge.core.hasher import compute_sha256
from traceforge.core.ledger import init_db, log_evidence

# Try to import dfVFS — graceful fallback if not installed
try:
    from dfvfs.lib import definitions as dfvfs_definitions
    from dfvfs.path import factory as path_spec_factory
    from dfvfs.resolver import resolver as dfvfs_resolver
    DFVFS_AVAILABLE = True
    logger.info("dfVFS available — full disk image support enabled")
except ImportError:
    DFVFS_AVAILABLE = False
    logger.warning("dfVFS not available — using filesystem fallback mode")


def _ts_to_iso(timestamp) -> str:
    """Convert various timestamp formats to ISO 8601."""
    try:
        if isinstance(timestamp, (int, float)):
            return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()
        return str(timestamp)
    except Exception:
        return ""


def _analyze_with_dfvfs(
    case_id: str,
    image_path: str,
    analyst: str,
    host_id: str
) -> list[Artifact]:
    """Analyze a disk image using dfVFS."""
    artifacts = []

    try:
        path_spec = path_spec_factory.Factory.NewPathSpec(
            dfvfs_definitions.TYPE_INDICATOR_OS,
            location=image_path
        )
        file_entry = dfvfs_resolver.Resolver.OpenFileEntry(path_spec)

        if file_entry is None:
            raise ValueError(f"Could not open disk image: {image_path}")

        def process_entry(entry, depth=0):
            if depth > 20:
                return

            try:
                stat = entry.GetStat()
                name = entry.name or "unknown"

                if stat:
                    mtime = _ts_to_iso(getattr(stat, "mtime", None))
                    atime = _ts_to_iso(getattr(stat, "atime", None))
                    ctime = _ts_to_iso(getattr(stat, "ctime", None))
                    size = getattr(stat, "size", 0)
                    is_allocated = getattr(stat, "is_allocated", True)

                    artifact_type = "deleted_file" if not is_allocated else "file"

                    artifacts.append(Artifact(
                        case_id=case_id,
                        source_module="disk",
                        artifact_type=artifact_type,
                        host_id=host_id,
                        timestamp=mtime or ctime or "",
                        data={
                            "name": name,
                            "size_bytes": size,
                            "modified": mtime,
                            "accessed": atime,
                            "created": ctime,
                            "allocated": is_allocated,
                            "path": entry.path_spec.location if hasattr(entry.path_spec, "location") else name
                        }
                    ))

                for sub_entry in entry.sub_file_entries:
                    process_entry(sub_entry, depth + 1)

            except Exception as e:
                logger.debug(f"Skipping entry due to error: {e}")

        process_entry(file_entry)

    except Exception as e:
        logger.error(f"dfVFS analysis failed: {e}")
        raise

    return artifacts


def _analyze_filesystem_fallback(
    case_id: str,
    path: Path,
    analyst: str,
    host_id: str
) -> list[Artifact]:
    """
    Fallback analysis using Python's standard library.
    Works on directories and accessible filesystem paths.
    Used when dfVFS is not installed.
    """
    artifacts = []

    target = path if path.is_dir() else path.parent
    logger.info(f"Fallback mode: traversing {target}")

    for item in target.rglob("*"):
        try:
            stat = item.stat()
            artifacts.append(Artifact(
                case_id=case_id,
                source_module="disk",
                artifact_type="file" if item.is_file() else "directory",
                host_id=host_id,
                timestamp=_ts_to_iso(stat.st_mtime),
                data={
                    "name": item.name,
                    "path": str(item),
                    "size_bytes": stat.st_size if item.is_file() else 0,
                    "modified": _ts_to_iso(stat.st_mtime),
                    "accessed": _ts_to_iso(stat.st_atime),
                    "created": _ts_to_iso(stat.st_ctime),
                    "is_file": item.is_file(),
                    "suffix": item.suffix
                }
            ))
        except PermissionError:
            continue
        except Exception as e:
            logger.debug(f"Skipping {item}: {e}")
            continue

    return artifacts


def analyze(
    case_id: str,
    image_path: str,
    analyst: str,
    host_id: Optional[str] = None
) -> list[Artifact]:
    """
    Analyze a disk image or directory and return Artifact objects.

    Args:
        case_id    : The investigation case ID
        image_path : Path to disk image (.dd, .E01) or directory
        analyst    : Analyst name or ID
        host_id    : Optional host identifier

    Returns:
        List of Artifact objects
    """
    init_db()
    path = Path(image_path)

    if not path.exists():
        raise FileNotFoundError(f"Disk image or path not found: {image_path}")

    # Hash before analysis — chain of custody
    if path.is_file():
        sha256, size = compute_sha256(path)
    else:
        sha256, size = "directory-no-hash", 0

    log_evidence(case_id, analyst, str(path), sha256, size, "disk")

    host = host_id or path.stem
    logger.info(f"Analyzing disk: {path.name} | Case: {case_id} | dfVFS: {DFVFS_AVAILABLE}")

    if DFVFS_AVAILABLE and path.is_file():
        artifacts = _analyze_with_dfvfs(case_id, str(path), analyst, host)
    else:
        artifacts = _analyze_filesystem_fallback(case_id, path, analyst, host)

    logger.info(f"Disk analysis complete: {len(artifacts)} artifacts found")
    return artifacts
