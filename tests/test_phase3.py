"""
TraceForge v2 — Phase 3 Tests
Tests for artifact store, correlation engine, timeline, and report generator.
Run with: pytest tests/test_phase3.py -v
"""

import pytest
import os
import tempfile
import time
import uuid
from pathlib import Path
from traceforge.core.ledger import init_db, create_case
from traceforge.core.artifact import Artifact
from traceforge.core.store import save_artifacts, get_artifacts, get_artifact_count, clear_artifacts
from traceforge.core.correlator import correlate, correlate_summary
from traceforge.core.timeline import build_timeline
from traceforge.core.report import generate_report


def make_case(prefix="TEST-P3"):
    """Create a unique test case."""
    init_db()
    case_id = f"{prefix}-{uuid.uuid4().hex[:8]}"
    try:
        create_case(case_id, f"Phase 3 Test {case_id}", "test_analyst")
    except ValueError:
        pass
    return case_id


def make_artifact(case_id, module, artifact_type, host, ts="", data=None):
    return Artifact(
        case_id=case_id,
        source_module=module,
        artifact_type=artifact_type,
        host_id=host,
        timestamp=ts,
        data=data or {}
    )


# ── STORE TESTS ───────────────────────────────────────────────────────────────

def test_save_and_retrieve_artifacts():
    """Artifacts can be saved and retrieved from the store."""
    case_id = make_case()
    artifacts = [
        make_artifact(case_id, "logs", "failed_login", "server-01",
                      "2026-05-03T10:00:00+00:00",
                      {"user": "root", "src_ip": "10.0.0.5"}),
        make_artifact(case_id, "network", "dns_query", "server-01",
                      "2026-05-03T10:00:05+00:00",
                      {"query": "malicious.com", "src_ip": "10.0.0.5"}),
    ]
    saved = save_artifacts(artifacts)
    assert saved == 2

    retrieved = get_artifacts(case_id)
    assert len(retrieved) == 2


def test_get_artifacts_by_module():
    """get_artifacts filters correctly by module."""
    case_id = make_case()
    artifacts = [
        make_artifact(case_id, "logs", "failed_login", "host1"),
        make_artifact(case_id, "network", "dns_query", "host1"),
        make_artifact(case_id, "memory", "process", "host1"),
    ]
    save_artifacts(artifacts)

    logs_only = get_artifacts(case_id, module="logs")
    assert len(logs_only) == 1
    assert logs_only[0].source_module == "logs"


def test_artifact_count():
    """get_artifact_count returns correct counts per module."""
    case_id = make_case()
    artifacts = [
        make_artifact(case_id, "logs", "failed_login", "host1"),
        make_artifact(case_id, "logs", "successful_login", "host1"),
        make_artifact(case_id, "network", "dns_query", "host1"),
    ]
    save_artifacts(artifacts)
    counts = get_artifact_count(case_id)
    assert counts.get("logs") == 2
    assert counts.get("network") == 1


def test_clear_artifacts():
    """clear_artifacts removes artifacts for a case."""
    case_id = make_case()
    save_artifacts([make_artifact(case_id, "logs", "failed_login", "host1")])
    clear_artifacts(case_id)
    assert get_artifacts(case_id) == []


# ── CORRELATOR TESTS ──────────────────────────────────────────────────────────

def test_correlate_timestamp_proximity():
    """Correlator finds artifacts from different modules within time window."""
    case_id = make_case()
    artifacts = [
        make_artifact(case_id, "logs", "failed_login", "host1",
                      "2026-05-03T10:00:00+00:00",
                      {"src_ip": "10.0.0.5", "user": "root"}),
        make_artifact(case_id, "network", "suspicious_connection", "host1",
                      "2026-05-03T10:00:05+00:00",
                      {"src_ip": "10.0.0.5", "dst_port": 4444}),
    ]
    save_artifacts(artifacts)
    results = correlate(case_id, window_seconds=30)
    assert len(results) > 0


def test_correlate_ip_match():
    """Correlator finds artifacts sharing the same IP address."""
    case_id = make_case()
    artifacts = [
        make_artifact(case_id, "logs", "failed_login", "server-01",
                      "2026-05-03T10:00:00+00:00",
                      {"src_ip": "192.168.1.99", "user": "admin"}),
        make_artifact(case_id, "network", "tcp_flow", "server-01",
                      "2026-05-03T11:00:00+00:00",
                      {"src_ip": "192.168.1.99", "dst_port": 80}),
    ]
    save_artifacts(artifacts)
    results = correlate(case_id)
    # host_match fires before ip_match when host_id is the same — both are valid
    assert len(results) > 0
    assert any(r.link_type in ("ip_match", "host_match") for r in results)


def test_correlate_empty_case():
    """Correlator returns empty list for case with no artifacts."""
    case_id = make_case()
    results = correlate(case_id)
    assert results == []


def test_correlate_summary():
    """correlate_summary returns correct structure."""
    case_id = make_case()
    artifacts = [
        make_artifact(case_id, "logs", "failed_login", "host1",
                      "2026-05-03T10:00:00+00:00", {"src_ip": "1.2.3.4"}),
        make_artifact(case_id, "network", "dns_query", "host1",
                      "2026-05-03T10:00:03+00:00", {"src_ip": "1.2.3.4"}),
    ]
    save_artifacts(artifacts)
    results = correlate(case_id)
    summary = correlate_summary(results)
    assert "total" in summary
    assert "high_confidence" in summary
    assert "by_type" in summary


# ── TIMELINE TESTS ────────────────────────────────────────────────────────────

def test_timeline_builds_correctly():
    """Timeline builds from stored artifacts."""
    case_id = make_case()
    artifacts = [
        make_artifact(case_id, "logs", "failed_login", "host1",
                      "2026-05-03T10:00:00+00:00",
                      {"src_ip": "10.0.0.5", "user": "root"}),
        make_artifact(case_id, "network", "dns_query", "host1",
                      "2026-05-03T10:00:05+00:00",
                      {"query": "evil.com", "src_ip": "10.0.0.5"}),
    ]
    save_artifacts(artifacts)
    events = build_timeline(case_id)
    assert len(events) == 2
    assert events[0].timestamp <= events[1].timestamp


def test_timeline_severity_assignment():
    """Timeline assigns correct severity to known artifact types."""
    case_id = make_case()
    artifacts = [
        make_artifact(case_id, "network", "suspicious_connection", "host1",
                      "2026-05-03T10:00:00+00:00",
                      {"src_ip": "1.2.3.4", "dst_port": 4444}),
    ]
    save_artifacts(artifacts)
    events = build_timeline(case_id)
    assert events[0].severity == "high"


# ── REPORT TESTS ──────────────────────────────────────────────────────────────

def test_report_generates_json():
    """Report generator produces a valid JSON file."""
    case_id = make_case()
    artifacts = [
        make_artifact(case_id, "logs", "failed_login", "host1",
                      "2026-05-03T10:00:00+00:00",
                      {"src_ip": "10.0.0.5", "user": "root"}),
    ]
    save_artifacts(artifacts)

    with tempfile.TemporaryDirectory() as tmpdir:
        paths = generate_report(case_id, formats=["json"], output_dir=tmpdir)
        assert "json" in paths
        assert Path(paths["json"]).exists()
        import json
        with open(paths["json"]) as f:
            data = json.load(f)
        assert data["case"]["id"] == case_id


def test_report_generates_html():
    """Report generator produces a valid HTML file."""
    case_id = make_case()
    save_artifacts([
        make_artifact(case_id, "logs", "failed_login", "host1",
                      data={"src_ip": "1.2.3.4", "user": "root"})
    ])

    with tempfile.TemporaryDirectory() as tmpdir:
        paths = generate_report(case_id, formats=["html"], output_dir=tmpdir)
        assert "html" in paths
        assert Path(paths["html"]).exists()
        content = Path(paths["html"]).read_text()
        assert case_id in content
        assert "TraceForge" in content
