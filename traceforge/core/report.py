"""
TraceForge v2 — Report Generator
Generates case reports in JSON, HTML, and PDF formats.
All three formats are produced from a single function call.
"""

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from loguru import logger
from jinja2 import Environment

from traceforge.core.ledger import get_case, get_evidence_log
from traceforge.core.store import get_artifacts, get_artifact_count
from traceforge.core.correlator import correlate, correlate_summary
from traceforge.core.timeline import build_timeline, timeline_to_dict


REPORTS_DIR = Path.home() / "traceforge" / "reports"

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>TraceForge Report — {{ case.id }}</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: 'Segoe UI', Arial, sans-serif; background: #0f1117; color: #e2e8f0; padding: 40px; }
  .header { border-bottom: 2px solid #22d3ee; padding-bottom: 20px; margin-bottom: 30px; }
  .header h1 { font-size: 28px; color: #22d3ee; }
  .header .meta { font-size: 13px; color: #94a3b8; margin-top: 8px; }
  .section { margin-bottom: 30px; }
  .section h2 { font-size: 18px; color: #22d3ee; border-left: 3px solid #22d3ee; padding-left: 12px; margin-bottom: 16px; }
  .card { background: #1e2130; border: 1px solid #2d3748; border-radius: 8px; padding: 16px; margin-bottom: 12px; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; }
  .badge-critical { background: #7f1d1d; color: #fca5a5; }
  .badge-high     { background: #7c2d12; color: #fdba74; }
  .badge-medium   { background: #713f12; color: #fde68a; }
  .badge-low      { background: #1e3a5f; color: #93c5fd; }
  .badge-info     { background: #1e293b; color: #94a3b8; }
  .badge-memory   { background: #4c1d95; color: #c4b5fd; }
  .badge-disk     { background: #0c4a6e; color: #7dd3fc; }
  .badge-logs     { background: #064e3b; color: #6ee7b7; }
  .badge-network  { background: #7f1d1d; color: #fca5a5; }
  .timeline-row { display: flex; gap: 12px; align-items: flex-start; padding: 10px 0; border-bottom: 1px solid #2d3748; }
  .timeline-ts { font-size: 11px; color: #64748b; min-width: 140px; font-family: monospace; }
  .timeline-content { flex: 1; }
  .timeline-summary { font-size: 13px; color: #e2e8f0; }
  .timeline-links { font-size: 11px; color: #22d3ee; margin-top: 4px; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th { background: #1e2130; color: #94a3b8; text-align: left; padding: 10px 12px; border-bottom: 1px solid #2d3748; }
  td { padding: 8px 12px; border-bottom: 1px solid #1e2130; }
  .hash { font-family: monospace; font-size: 11px; color: #64748b; word-break: break-all; }
  .stat-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; }
  .stat-card { background: #1e2130; border: 1px solid #2d3748; border-radius: 8px; padding: 16px; text-align: center; }
  .stat-number { font-size: 28px; font-weight: 700; color: #22d3ee; }
  .stat-label { font-size: 12px; color: #94a3b8; margin-top: 4px; }
  .footer { margin-top: 40px; padding-top: 20px; border-top: 1px solid #2d3748; font-size: 12px; color: #475569; text-align: center; }
</style>
</head>
<body>

<div class="header">
  <h1>TraceForge v2 — Case Report</h1>
  <div class="meta">
    Case ID: <strong>{{ case.id }}</strong> &nbsp;|&nbsp;
    Name: <strong>{{ case.name }}</strong> &nbsp;|&nbsp;
    Analyst: <strong>{{ case.analyst }}</strong> &nbsp;|&nbsp;
    Generated: <strong>{{ generated_at }}</strong>
  </div>
</div>

<div class="section">
  <h2>Case Summary</h2>
  <div class="stat-grid">
    <div class="stat-card">
      <div class="stat-number">{{ total_artifacts }}</div>
      <div class="stat-label">Total Artifacts</div>
    </div>
    <div class="stat-card">
      <div class="stat-number">{{ total_correlations }}</div>
      <div class="stat-label">Correlations</div>
    </div>
    <div class="stat-card">
      <div class="stat-number">{{ evidence_count }}</div>
      <div class="stat-label">Evidence Files</div>
    </div>
    <div class="stat-card">
      <div class="stat-number">{{ critical_count }}</div>
      <div class="stat-label">Critical Findings</div>
    </div>
  </div>
</div>

<div class="section">
  <h2>Artifacts by Module</h2>
  <div class="card">
    <table>
      <tr><th>Module</th><th>Artifact Count</th></tr>
      {% for module, count in artifact_counts.items() %}
      <tr>
        <td><span class="badge badge-{{ module }}">{{ module.upper() }}</span></td>
        <td>{{ count }}</td>
      </tr>
      {% endfor %}
    </table>
  </div>
</div>

<div class="section">
  <h2>Evidence Ledger</h2>
  <div class="card">
    <table>
      <tr><th>File</th><th>Module</th><th>SHA-256</th><th>Size</th><th>Recorded</th></tr>
      {% for e in evidence %}
      <tr>
        <td>{{ e.file_path.split('/')[-1] }}</td>
        <td><span class="badge badge-{{ e.module }}">{{ e.module.upper() }}</span></td>
        <td class="hash">{{ e.sha256_hash }}</td>
        <td>{{ '{:,}'.format(e.file_size_bytes) }} bytes</td>
        <td>{{ e.recorded_at[:19] }}</td>
      </tr>
      {% endfor %}
    </table>
  </div>
</div>

{% if correlations %}
<div class="section">
  <h2>Correlation Findings</h2>
  {% for r in correlations %}
  <div class="card">
    <span class="badge badge-{{ 'critical' if r.confidence >= 0.9 else 'medium' if r.confidence >= 0.5 else 'low' }}">
      {{ (r.confidence * 100)|int }}% confidence
    </span>
    <span style="margin-left: 8px; font-size: 12px; color: #94a3b8;">{{ r.link_type }}</span>
    <div style="margin-top: 8px; font-size: 13px;">{{ r.description }}</div>
  </div>
  {% endfor %}
</div>
{% endif %}

<div class="section">
  <h2>IOC Timeline</h2>
  {% for event in timeline %}
  <div class="timeline-row">
    <div class="timeline-ts">{{ event.timestamp[:19] }}</div>
    <div>
      <span class="badge badge-{{ event.module }}">{{ event.module.upper() }}</span>
      <span class="badge badge-{{ event.severity }}" style="margin-left: 4px;">{{ event.severity.upper() }}</span>
    </div>
    <div class="timeline-content">
      <div class="timeline-summary">{{ event.summary }}</div>
      {% if event.correlation_links %}
      <div class="timeline-links">
        Linked: {{ event.correlation_links[0] }}
      </div>
      {% endif %}
    </div>
  </div>
  {% endfor %}
</div>

<div class="footer">
  Generated by TraceForge v2 &nbsp;|&nbsp; github.com/theconsoler/TRACEFORGE-V2 &nbsp;|&nbsp; {{ generated_at }}
</div>

</body>
</html>
"""


def generate_report(
    case_id: str,
    formats: list[str] = None,
    output_dir: str = None
) -> dict[str, str]:
    """
    Generate a case report in one or more formats.

    Args:
        case_id    : The investigation case ID
        formats    : List of formats to generate: ["json", "html", "pdf"]
                     Defaults to all three.
        output_dir : Directory to save reports. Defaults to ~/traceforge/reports/

    Returns:
        Dict mapping format name to output file path.
    """
    if formats is None:
        formats = ["json", "html", "pdf"]

    out_dir = Path(output_dir) if output_dir else REPORTS_DIR
    out_dir.mkdir(parents=True, exist_ok=True)

    case = get_case(case_id)
    if not case:
        raise ValueError(f"Case '{case_id}' not found")

    logger.info(f"Generating report for case {case_id} | formats: {formats}")

    # Gather all data
    evidence = get_evidence_log(case_id)
    artifact_counts = get_artifact_count(case_id)
    total_artifacts = sum(artifact_counts.values())

    correlation_results = correlate(case_id)
    corr_summary = correlate_summary(correlation_results)

    timeline_events = build_timeline(case_id, correlation_results)
    timeline_dicts = timeline_to_dict(timeline_events)

    critical_count = sum(1 for e in timeline_events if e.severity == "critical")
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    correlation_dicts = [
        {
            "link_type": r.link_type,
            "confidence": r.confidence,
            "description": r.description,
            "artifact_a": {
                "module": r.artifact_a.source_module,
                "type": r.artifact_a.artifact_type,
                "host": r.artifact_a.host_id,
                "timestamp": r.artifact_a.timestamp
            },
            "artifact_b": {
                "module": r.artifact_b.source_module,
                "type": r.artifact_b.artifact_type,
                "host": r.artifact_b.host_id,
                "timestamp": r.artifact_b.timestamp
            }
        }
        for r in correlation_results
    ]

    report_data = {
        "traceforge_version": "2.0.0",
        "generated_at": generated_at,
        "case": case,
        "evidence_ledger": evidence,
        "artifact_counts": artifact_counts,
        "total_artifacts": total_artifacts,
        "correlation_summary": corr_summary,
        "correlations": correlation_dicts,
        "timeline": timeline_dicts
    }

    output_paths = {}

    # JSON report
    if "json" in formats:
        json_path = out_dir / f"report_{case_id}_{ts}.json"
        with open(json_path, "w") as f:
            json.dump(report_data, f, indent=2, default=str)
        output_paths["json"] = str(json_path)
        logger.info(f"JSON report: {json_path}")

    # HTML report
    html_content = None
    if "html" in formats or "pdf" in formats:
        env = Environment(autoescape=True)
        template = env.from_string(HTML_TEMPLATE)
        html_content = template.render(
            case=case,
            generated_at=generated_at,
            total_artifacts=total_artifacts,
            total_correlations=corr_summary["total"],
            evidence_count=len(evidence),
            critical_count=critical_count,
            artifact_counts=artifact_counts,
            evidence=evidence,
            correlations=correlation_dicts,
            timeline=timeline_dicts
        )

    if "html" in formats and html_content:
        html_path = out_dir / f"report_{case_id}_{ts}.html"
        with open(html_path, "w") as f:
            f.write(html_content)
        output_paths["html"] = str(html_path)
        logger.info(f"HTML report: {html_path}")

    # PDF report
    if "pdf" in formats and html_content:
        try:
            from weasyprint import HTML as WeasyprintHTML
            pdf_path = out_dir / f"report_{case_id}_{ts}.pdf"
            WeasyprintHTML(string=html_content).write_pdf(str(pdf_path))
            output_paths["pdf"] = str(pdf_path)
            logger.info(f"PDF report: {pdf_path}")
        except Exception as e:
            logger.error(f"PDF generation failed: {e}")
            logger.info("HTML report still available")

    return output_paths
