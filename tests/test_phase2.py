"""
TraceForge v2 — Phase 2 Tests
Tests for all four analysis modules.
Run with: pytest tests/test_phase2.py -v
"""

import pytest
import os
import tempfile
from pathlib import Path
from traceforge.core.ledger import init_db, create_case
from traceforge.core.artifact import Artifact


def setup_test_case(case_id: str):
    """Helper to create a test case, ignoring duplicate errors."""
    init_db()
    try:
        create_case(case_id, f"Test case {case_id}", "test_analyst")
    except ValueError:
        pass


# ── LOGS MODULE TESTS ─────────────────────────────────────────────────────────

def test_logs_analyze_returns_artifacts():
    """Logs module returns artifacts from a valid log file."""
    from traceforge.modules.logs import analyze
    setup_test_case("TEST-LOGS-001")

    log_content = """May  3 10:01:22 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2
May  3 10:01:25 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2
May  3 10:01:31 server sshd[1234]: Accepted password for admin from 192.168.1.50 port 22 ssh2
May  3 10:02:10 server sudo: admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/bash
"""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
        f.write(log_content)
        tmp_path = f.name

    try:
        artifacts = analyze("TEST-LOGS-001", tmp_path, "test_analyst")
        assert isinstance(artifacts, list)
        assert len(artifacts) > 0
        assert all(isinstance(a, Artifact) for a in artifacts)
    finally:
        os.unlink(tmp_path)


def test_logs_detects_failed_login():
    """Logs module correctly identifies failed login artifacts."""
    from traceforge.modules.logs import analyze
    setup_test_case("TEST-LOGS-002")

    log_content = "May  3 10:01:22 server sshd[1234]: Failed password for root from 10.0.0.5 port 22 ssh2\n"

    with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
        f.write(log_content)
        tmp_path = f.name

    try:
        artifacts = analyze("TEST-LOGS-002", tmp_path, "test_analyst")
        failed = [a for a in artifacts if a.artifact_type == "failed_login"]
        assert len(failed) > 0
        assert failed[0].data["src_ip"] == "10.0.0.5"
    finally:
        os.unlink(tmp_path)


def test_logs_detects_brute_force():
    """Logs module detects brute force when threshold is exceeded."""
    from traceforge.modules.logs import analyze, BRUTE_FORCE_THRESHOLD
    setup_test_case("TEST-LOGS-003")

    lines = "\n".join([
        f"May  3 10:0{i}:00 server sshd[1234]: Failed password for root from 10.0.0.99 port 22 ssh2"
        for i in range(BRUTE_FORCE_THRESHOLD + 1)
    ])

    with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
        f.write(lines)
        tmp_path = f.name

    try:
        artifacts = analyze("TEST-LOGS-003", tmp_path, "test_analyst")
        brute = [a for a in artifacts if a.data.get("type") == "brute_force_detected"]
        assert len(brute) > 0
    finally:
        os.unlink(tmp_path)


def test_logs_file_not_found():
    """Logs module raises FileNotFoundError for missing file."""
    from traceforge.modules.logs import analyze
    setup_test_case("TEST-LOGS-ERR")
    with pytest.raises(FileNotFoundError):
        analyze("TEST-LOGS-ERR", "/nonexistent/auth.log", "test_analyst")


# ── NETWORK MODULE TESTS ──────────────────────────────────────────────────────

def test_network_analyze_returns_artifacts():
    """Network module returns artifacts from a valid PCAP."""
    from traceforge.modules.network import analyze
    from scapy.all import wrpcap, IP, TCP, UDP, DNS, DNSQR

    setup_test_case("TEST-NET-001")

    packets = [
        IP(src="192.168.1.10", dst="8.8.8.8") / UDP() / DNS(
            rd=1, qd=DNSQR(qname="example.com")
        ),
        IP(src="192.168.1.10", dst="1.2.3.4") / TCP(dport=80) / b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
    ]

    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
        tmp_path = f.name

    try:
        wrpcap(tmp_path, packets)
        artifacts = analyze("TEST-NET-001", tmp_path, "test_analyst")
        assert isinstance(artifacts, list)
        assert len(artifacts) > 0
    finally:
        os.unlink(tmp_path)


def test_network_file_not_found():
    """Network module raises FileNotFoundError for missing PCAP."""
    from traceforge.modules.network import analyze
    setup_test_case("TEST-NET-ERR")
    with pytest.raises(FileNotFoundError):
        analyze("TEST-NET-ERR", "/nonexistent/capture.pcap", "test_analyst")


# ── DISK MODULE TESTS ─────────────────────────────────────────────────────────

def test_disk_analyze_directory():
    """Disk module analyzes a directory in fallback mode."""
    from traceforge.modules.disk import analyze
    setup_test_case("TEST-DISK-001")

    with tempfile.TemporaryDirectory() as tmpdir:
        (Path(tmpdir) / "testfile.txt").write_text("test content")
        (Path(tmpdir) / "subdir").mkdir()
        (Path(tmpdir) / "subdir" / "nested.log").write_text("nested")

        artifacts = analyze("TEST-DISK-001", tmpdir, "test_analyst")
        assert isinstance(artifacts, list)
        assert len(artifacts) > 0


def test_disk_path_not_found():
    """Disk module raises FileNotFoundError for missing path."""
    from traceforge.modules.disk import analyze
    setup_test_case("TEST-DISK-ERR")
    with pytest.raises(FileNotFoundError):
        analyze("TEST-DISK-ERR", "/nonexistent/disk.dd", "test_analyst")


# ── ARTIFACT INTEGRITY TESTS ──────────────────────────────────────────────────

def test_all_artifacts_have_required_fields():
    """Every artifact from every module has the required fields set."""
    from traceforge.modules.logs import analyze as logs_analyze
    setup_test_case("TEST-INTEGRITY-001")

    log_content = "May  3 10:01:22 server sshd[1234]: Failed password for root from 10.0.0.5 port 22 ssh2\n"
    with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
        f.write(log_content)
        tmp_path = f.name

    try:
        artifacts = logs_analyze("TEST-INTEGRITY-001", tmp_path, "test_analyst")
        for a in artifacts:
            assert a.case_id == "TEST-INTEGRITY-001"
            assert a.source_module in Artifact.VALID_MODULES
            assert isinstance(a.data, dict)
            assert a.host_id is not None
    finally:
        os.unlink(tmp_path)
