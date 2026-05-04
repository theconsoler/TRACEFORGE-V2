"""
TraceForge v2 — Artifact Store
Persists Artifact objects from all modules into SQLite.
The correlation engine reads directly from this store.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from loguru import logger

from traceforge.core.ledger import _get_connection, init_db
from traceforge.core.artifact import Artifact


def save_artifacts(artifacts: list[Artifact]) -> int:
    """
    Persist a list of Artifact objects to the database.
    Returns the number of artifacts saved.
    Skips duplicates silently.
    """
    if not artifacts:
        return 0

    init_db()
    conn = _get_connection()
    cursor = conn.cursor()
    saved = 0

    for a in artifacts:
        try:
            cursor.execute("""
                INSERT INTO artifacts
                    (case_id, source_module, artifact_type, host_id,
                     timestamp, data_json, recorded_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                a.case_id,
                a.source_module,
                a.artifact_type,
                a.host_id,
                a.timestamp,
                json.dumps(a.data),
                a.recorded_at
            ))
            saved += 1
        except Exception as e:
            logger.debug(f"Skipping artifact: {e}")
            continue

    conn.commit()
    conn.close()
    logger.info(f"Saved {saved} artifacts to store")
    return saved


def get_artifacts(case_id: str, module: str = None) -> list[Artifact]:
    """
    Retrieve all artifacts for a case from the database.
    Optionally filter by source module.
    Returns a list of Artifact objects sorted by timestamp.
    """
    init_db()
    conn = _get_connection()

    if module:
        rows = conn.execute("""
            SELECT * FROM artifacts
            WHERE case_id = ? AND source_module = ?
            ORDER BY timestamp ASC, recorded_at ASC
        """, (case_id, module)).fetchall()
    else:
        rows = conn.execute("""
            SELECT * FROM artifacts
            WHERE case_id = ?
            ORDER BY timestamp ASC, recorded_at ASC
        """, (case_id,)).fetchall()

    conn.close()

    artifacts = []
    for row in rows:
        try:
            artifacts.append(Artifact(
                case_id=row["case_id"],
                source_module=row["source_module"],
                artifact_type=row["artifact_type"],
                host_id=row["host_id"] or "unknown",
                timestamp=row["timestamp"] or "",
                data=json.loads(row["data_json"]),
                recorded_at=row["recorded_at"]
            ))
        except Exception as e:
            logger.debug(f"Skipping stored artifact: {e}")
            continue

    return artifacts


def get_artifact_count(case_id: str) -> dict:
    """Return artifact counts per module for a case."""
    init_db()
    conn = _get_connection()
    rows = conn.execute("""
        SELECT source_module, COUNT(*) as count
        FROM artifacts
        WHERE case_id = ?
        GROUP BY source_module
    """, (case_id,)).fetchall()
    conn.close()
    return {row["source_module"]: row["count"] for row in rows}


def clear_artifacts(case_id: str, module: str = None) -> int:
    """
    Remove artifacts for a case.
    Use this to re-run analysis without duplicate artifacts.
    Optionally clear only a specific module's artifacts.
    """
    init_db()
    conn = _get_connection()

    if module:
        cursor = conn.execute(
            "DELETE FROM artifacts WHERE case_id = ? AND source_module = ?",
            (case_id, module)
        )
    else:
        cursor = conn.execute(
            "DELETE FROM artifacts WHERE case_id = ?",
            (case_id,)
        )

    count = cursor.rowcount
    conn.commit()
    conn.close()
    logger.info(f"Cleared {count} artifacts for case {case_id}")
    return count
