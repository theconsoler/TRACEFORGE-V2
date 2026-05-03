"""
TraceForge v2 — Evidence Ledger
Append-only SQLite ledger for chain-of-custody tracking.
No evidence record is ever modified or deleted after creation.
"""

import sqlite3
import os
from datetime import datetime, timezone
from pathlib import Path
from loguru import logger


DB_PATH = Path.home() / "traceforge" / "data" / "traceforge.db"


def _get_connection() -> sqlite3.Connection:
    """Return a connection to the TraceForge SQLite database."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """
    Initialise the database schema.
    Creates tables if they do not exist.
    Safe to call multiple times.
    """
    conn = _get_connection()
    cursor = conn.cursor()

    # Cases table — one row per investigation
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS cases (
            id          TEXT PRIMARY KEY,
            name        TEXT NOT NULL,
            analyst     TEXT NOT NULL,
            created_at  TEXT NOT NULL,
            notes       TEXT
        )
    """)

    # Evidence log — append only, never updated or deleted
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS evidence_log (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id         TEXT NOT NULL,
            analyst         TEXT NOT NULL,
            file_path       TEXT NOT NULL,
            sha256_hash     TEXT NOT NULL,
            file_size_bytes INTEGER NOT NULL,
            recorded_at     TEXT NOT NULL,
            module          TEXT NOT NULL,
            notes           TEXT,
            FOREIGN KEY (case_id) REFERENCES cases(id)
        )
    """)

    # Artifacts table — stores all module outputs
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS artifacts (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id         TEXT NOT NULL,
            source_module   TEXT NOT NULL,
            artifact_type   TEXT NOT NULL,
            host_id         TEXT,
            timestamp       TEXT,
            data_json       TEXT NOT NULL,
            recorded_at     TEXT NOT NULL,
            FOREIGN KEY (case_id) REFERENCES cases(id)
        )
    """)

    conn.commit()
    conn.close()
    logger.info(f"Database initialised at {DB_PATH}")


def create_case(case_id: str, name: str, analyst: str, notes: str = "") -> dict:
    """
    Create a new investigation case.
    Raises ValueError if case_id already exists.
    """
    conn = _get_connection()
    cursor = conn.cursor()

    existing = cursor.execute(
        "SELECT id FROM cases WHERE id = ?", (case_id,)
    ).fetchone()

    if existing:
        conn.close()
        raise ValueError(f"Case '{case_id}' already exists.")

    created_at = datetime.now(timezone.utc).isoformat()

    cursor.execute(
        "INSERT INTO cases (id, name, analyst, created_at, notes) VALUES (?, ?, ?, ?, ?)",
        (case_id, name, analyst, created_at, notes)
    )

    conn.commit()
    conn.close()

    logger.info(f"Case created: {case_id} — {name} (analyst: {analyst})")
    return {
        "case_id": case_id,
        "name": name,
        "analyst": analyst,
        "created_at": created_at,
        "notes": notes
    }


def log_evidence(
    case_id: str,
    analyst: str,
    file_path: str,
    sha256_hash: str,
    file_size_bytes: int,
    module: str,
    notes: str = ""
) -> int:
    """
    Record an evidence file in the append-only ledger.
    The hash must be computed BEFORE this function is called.
    Returns the row ID of the new ledger entry.
    """
    conn = _get_connection()
    cursor = conn.cursor()

    case_exists = cursor.execute(
        "SELECT id FROM cases WHERE id = ?", (case_id,)
    ).fetchone()

    if not case_exists:
        conn.close()
        raise ValueError(f"Case '{case_id}' does not exist. Create it first.")

    recorded_at = datetime.now(timezone.utc).isoformat()

    cursor.execute("""
        INSERT INTO evidence_log
            (case_id, analyst, file_path, sha256_hash, file_size_bytes, recorded_at, module, notes)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (case_id, analyst, file_path, sha256_hash, file_size_bytes, recorded_at, module, notes))

    row_id = cursor.lastrowid
    conn.commit()
    conn.close()

    logger.info(f"Evidence logged: {file_path} | SHA256: {sha256_hash[:16]}... | Case: {case_id}")
    return row_id


def get_case(case_id: str) -> dict | None:
    """Retrieve a case by ID. Returns None if not found."""
    conn = _get_connection()
    row = conn.execute(
        "SELECT * FROM cases WHERE id = ?", (case_id,)
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def get_evidence_log(case_id: str) -> list[dict]:
    """Return all evidence entries for a case, ordered by recorded_at."""
    conn = _get_connection()
    rows = conn.execute(
        "SELECT * FROM evidence_log WHERE case_id = ? ORDER BY recorded_at ASC",
        (case_id,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def list_cases() -> list[dict]:
    """Return all cases in the database."""
    conn = _get_connection()
    rows = conn.execute("SELECT * FROM cases ORDER BY created_at DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]
