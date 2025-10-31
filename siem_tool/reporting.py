"""Report generation utilities."""
from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Iterable, Sequence

from .alerting import Alert
from .detections import DetectionResult
from .correlation import CorrelationResult


REPORT_TEMPLATE = """# Security Analysis Report
Generated: {generated}

## Detection Summary
{detection_section}

## Correlated Incidents
{correlation_section}

## Alerts
{alert_section}
"""


def generate_markdown_report(
    path: Path,
    detections: Sequence[DetectionResult],
    correlations: Sequence[CorrelationResult],
    alerts: Sequence[Alert],
) -> Path:
    detection_lines = _render_detection_section(detections)
    correlation_lines = _render_correlation_section(correlations)
    alert_lines = _render_alert_section(alerts)
    output = REPORT_TEMPLATE.format(
        generated=datetime.utcnow().isoformat(timespec="seconds"),
        detection_section="\n".join(detection_lines) or "No detections.",
        correlation_section="\n".join(correlation_lines) or "No correlated incidents.",
        alert_section="\n".join(alert_lines) or "No alerts generated.",
    )
    path = Path(path)
    path.write_text(output, encoding="utf-8")
    return path


def _render_detection_section(detections: Sequence[DetectionResult]) -> Iterable[str]:
    if not detections:
        return []
    lines = []
    for det in detections:
        lines.append(f"- **{det.rule}** ({det.severity}) - {det.description} ({len(det.events)} events)")
    return lines


def _render_correlation_section(correlations: Sequence[CorrelationResult]) -> Iterable[str]:
    if not correlations:
        return []
    lines = []
    for corr in correlations:
        lines.append(
            f"- **{corr.name}** ({corr.severity}) - {corr.description} (Detections: {', '.join(corr.contributing_detections) or 'N/A'})"
        )
    return lines


def _render_alert_section(alerts: Sequence[Alert]) -> Iterable[str]:
    if not alerts:
        return []
    lines = []
    for alert in alerts:
        lines.append(f"- **{alert.id}** ({alert.severity}) - {alert.title} - {alert.description}")
    return lines
