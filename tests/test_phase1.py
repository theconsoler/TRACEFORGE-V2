"""
TraceForge v2 — Phase 1 Tests
Tests for ledger, hasher, and artifact schema.
Run with: pytest tests/test_phase1.py -v
"""

import pytest
import os
import tempfile
from pathlib import Path
from traceforge.core.ledger import init_db, create_case, log_evidence, get_case, get_evidence_log
from traceforge.core.hasher import compute_sha256, verify_hash
from traceforge.core.artifact import Artifact


# ── LEDGER TESTS ──────────────────────────────────────────────────────────────

def test_init_db():
    """Database initialises without errors."""
    init_db()

def test_create_case():
    """A case can be created and retrieved."""
    import time
    init_db()
    unique_id = f"TEST-{int(time.time())}"
    case = create_case(unique_id, "Phase 1 Test Case", "theconsoler")
    assert case["case_id"] == unique_id
    assert case["name"] == "Phase 1 Test Case"
    assert case["analyst"] == "theconsoler"

def test_duplicate_case_raises():
    """Creating a case with an existing ID raises ValueError."""
    init_db()
    try:
        create_case("TEST-DUP", "Duplicate Test", "theconsoler")
    except ValueError:
        pass
    with pytest.raises(ValueError):
        create_case("TEST-DUP", "Duplicate Test", "theconsoler")


def test_get_case_not_found():
    """get_case returns None for a non-existent case."""
    init_db()
    result = get_case("NONEXISTENT-9999")
    assert result is None


def test_log_evidence():
    """Evidence can be logged against a valid case."""
    init_db()
    try:
        create_case("TEST-EVID", "Evidence Test", "theconsoler")
    except ValueError:
        pass

    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
        f.write(b"fake evidence data for testing" * 100)
        tmp_path = f.name

    try:
        sha256, size = compute_sha256(tmp_path)
        row_id = log_evidence(
            case_id="TEST-EVID",
            analyst="theconsoler",
            file_path=tmp_path,
            sha256_hash=sha256,
            file_size_bytes=size,
            module="memory",
            notes="test evidence"
        )
        assert isinstance(row_id, int)
        assert row_id > 0

        log = get_evidence_log("TEST-EVID")
        assert len(log) > 0
        assert log[-1]["sha256_hash"] == sha256

    finally:
        os.unlink(tmp_path)


# ── HASHER TESTS ──────────────────────────────────────────────────────────────

def test_sha256_consistency():
    """Same file produces same hash every time."""
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"traceforge test content 12345")
        tmp_path = f.name

    try:
        hash1, size1 = compute_sha256(tmp_path)
        hash2, size2 = compute_sha256(tmp_path)
        assert hash1 == hash2
        assert size1 == size2
        assert len(hash1) == 64  # SHA-256 hex digest is always 64 chars
    finally:
        os.unlink(tmp_path)


def test_sha256_file_not_found():
    """FileNotFoundError raised for missing file."""
    with pytest.raises(FileNotFoundError):
        compute_sha256("/nonexistent/path/to/file.raw")


def test_verify_hash_correct():
    """verify_hash returns True for an unmodified file."""
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"unchanged content")
        tmp_path = f.name

    try:
        sha256, _ = compute_sha256(tmp_path)
        assert verify_hash(tmp_path, sha256) is True
    finally:
        os.unlink(tmp_path)


def test_verify_hash_tampered():
    """verify_hash returns False if file content changes."""
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"original content")
        tmp_path = f.name

    try:
        sha256, _ = compute_sha256(tmp_path)
        with open(tmp_path, "wb") as f:
            f.write(b"tampered content")
        assert verify_hash(tmp_path, sha256) is False
    finally:
        os.unlink(tmp_path)


# ── ARTIFACT TESTS ────────────────────────────────────────────────────────────

def test_artifact_creation():
    """Artifact is created with correct fields."""
    a = Artifact(
        case_id="TEST-001",
        source_module="memory",
        artifact_type="process",
        host_id="192.168.1.10",
        data={"pid": 1234, "name": "malware.exe", "ppid": 500},
        timestamp="2026-05-03T10:00:00+00:00"
    )
    assert a.case_id == "TEST-001"
    assert a.source_module == "memory"
    assert a.data["pid"] == 1234


def test_artifact_invalid_module():
    """Artifact raises ValueError for invalid source_module."""
    with pytest.raises(ValueError):
        Artifact(
            case_id="TEST-001",
            source_module="invalid_module",
            artifact_type="process",
            host_id="192.168.1.10",
            data={}
        )


def test_artifact_serialisation():
    """Artifact serialises to dict and back correctly."""
    a = Artifact(
        case_id="TEST-001",
        source_module="network",
        artifact_type="dns_query",
        host_id="10.0.0.5",
        data={"query": "malicious.com", "response": "1.2.3.4"},
        timestamp="2026-05-03T10:00:00+00:00"
    )
    d = a.to_dict()
    a2 = Artifact.from_dict(d)
    assert a2.case_id == a.case_id
    assert a2.data["query"] == "malicious.com"


def test_artifact_summary():
    """Artifact summary returns a non-empty string."""
    a = Artifact(
        case_id="TEST-001",
        source_module="logs",
        artifact_type="failed_login",
        host_id="server-01",
        data={"user": "root", "ip": "10.0.0.99", "attempts": 5}
    )
    summary = a.summary()
    assert isinstance(summary, str)
    assert len(summary) > 0
    assert "LOGS" in summary
