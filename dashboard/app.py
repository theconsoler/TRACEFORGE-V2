"""
TraceForge v2 — Flask Dashboard
Reads directly from the SQLite database.
Run with: python -m dashboard.app
"""

from flask import Flask, render_template, jsonify, send_file, abort
from pathlib import Path
import json
import os
import sys

from dotenv import load_dotenv
load_dotenv()

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from traceforge.core.ledger import init_db, list_cases, get_case, get_evidence_log
from traceforge.core.store import get_artifacts, get_artifact_count
from traceforge.core.correlator import correlate, correlate_summary
from traceforge.core.timeline import build_timeline, timeline_to_dict
from traceforge.core.report import generate_report

app = Flask(__name__, template_folder="templates", static_folder="static")

REPORTS_DIR = Path.home() / "traceforge" / "reports"


@app.before_request
def setup():
    init_db()


# ── ROUTES ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    """Case list — home page."""
    cases = list_cases()
    stats = []
    for c in cases:
        counts = get_artifact_count(c["id"])
        total = sum(counts.values())
        stats.append({**c, "artifact_count": total, "module_counts": counts})
    return render_template("index.html", cases=stats)


@app.route("/case/<case_id>")
def case_overview(case_id):
    """Case overview — summary of all findings."""
    case = get_case(case_id)
    if not case:
        abort(404)
    evidence = get_evidence_log(case_id)
    counts = get_artifact_count(case_id)
    corr_results = correlate(case_id)
    corr_summary = correlate_summary(corr_results)
    timeline = build_timeline(case_id, corr_results)

    severity_counts = {}
    for e in timeline:
        severity_counts[e.severity] = severity_counts.get(e.severity, 0) + 1

    return render_template("case.html",
        case=case,
        evidence=evidence,
        counts=counts,
        total_artifacts=sum(counts.values()),
        corr_summary=corr_summary,
        severity_counts=severity_counts,
        timeline_count=len(timeline)
    )


@app.route("/case/<case_id>/timeline")
def case_timeline(case_id):
    """Full IOC timeline view."""
    case = get_case(case_id)
    if not case:
        abort(404)
    corr_results = correlate(case_id)
    timeline = build_timeline(case_id, corr_results)
    return render_template("timeline.html",
        case=case,
        events=timeline_to_dict(timeline),
        total=len(timeline)
    )


@app.route("/case/<case_id>/correlations")
def case_correlations(case_id):
    """Correlation findings view."""
    case = get_case(case_id)
    if not case:
        abort(404)
    results = correlate(case_id)
    summary = correlate_summary(results)
    corr_list = [
        {
            "link_type": r.link_type,
            "confidence": r.confidence,
            "confidence_pct": int(r.confidence * 100),
            "description": r.description,
            "module_a": r.artifact_a.source_module,
            "type_a": r.artifact_a.artifact_type,
            "module_b": r.artifact_b.source_module,
            "type_b": r.artifact_b.artifact_type,
        }
        for r in results
    ]
    return render_template("correlations.html",
        case=case,
        correlations=corr_list,
        summary=summary
    )


@app.route("/case/<case_id>/report/<fmt>")
def export_report(case_id, fmt):
    """Generate and download a case report."""
    if fmt not in ("json", "html", "pdf"):
        abort(400)
    case = get_case(case_id)
    if not case:
        abort(404)
    try:
        paths = generate_report(case_id, formats=[fmt])
        if fmt in paths:
            return send_file(paths[fmt], as_attachment=True)
        abort(500)
    except Exception as e:
        abort(500)


# ── API ENDPOINTS ─────────────────────────────────────────────────────────────

@app.route("/api/cases")
def api_cases():
    cases = list_cases()
    return jsonify(cases)


@app.route("/api/case/<case_id>/timeline")
def api_timeline(case_id):
    corr_results = correlate(case_id)
    timeline = build_timeline(case_id, corr_results)
    return jsonify(timeline_to_dict(timeline))


@app.route("/api/case/<case_id>/artifacts")
def api_artifacts(case_id):
    artifacts = get_artifacts(case_id)
    return jsonify([a.to_dict() for a in artifacts])


if __name__ == "__main__":
    flask_debug = os.getenv("FLASK_DEBUG", "false").lower() == "true"
    flask_host = os.getenv("FLASK_HOST", "127.0.0.1")
    flask_port = int(os.getenv("FLASK_PORT", 5000))

    print("\n  TraceForge v2 Dashboard")
    print(f"  Running at: http://{flask_host}:{flask_port}")
    print("  Press Ctrl+C to stop\n")
    app.run(debug=flask_debug, host=flask_host, port=flask_port)
