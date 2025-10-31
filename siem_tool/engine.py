"""Core analysis engine for the SIEM tool."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Sequence

from .parsers import parse_logs
from .detections import analyze_events, DetectionResult, Event
from .correlation import correlate, CorrelationResult
from .alerting import alerts_from_correlations, alerts_from_detections, Alert


@dataclass
class AnalysisResults:
    events: List[Event]
    detections: List[DetectionResult]
    correlations: List[CorrelationResult]
    alerts: List[Alert]


DEFAULT_SOURCES = {
    "apache": Path("data/apache_access.log"),
    "nginx": Path("data/nginx_access.log"),
    "syslog": Path("data/syslog.log"),
    "windows": Path("data/windows_events.jsonl"),
}


def ingest_logs(sources: Dict[str, Path] | None = None) -> List[Event]:
    sources = sources or DEFAULT_SOURCES
    events: List[Event] = []
    for source, path in sources.items():
        if not Path(path).exists():
            continue
        events.extend(parse_logs(Path(path), source))
    return events


def run_analysis(events: Sequence[Event]) -> AnalysisResults:
    event_list = list(events)
    detections = analyze_events(event_list)
    correlations = correlate(event_list, detections)
    alerts = alerts_from_detections(detections) + alerts_from_correlations(correlations)
    alerts.sort(key=lambda alert: alert.timestamp)
    return AnalysisResults(
        events=event_list,
        detections=detections,
        correlations=correlations,
        alerts=alerts,
    )


def save_results(results: AnalysisResults, output_dir: Path) -> None:
    import json
    from datetime import datetime

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    def serialize_event(event):
        serialized = dict(event)
        if isinstance(serialized.get("timestamp"), datetime):
            serialized["timestamp"] = serialized["timestamp"].isoformat()
        return serialized

    events_path = output_dir / "events.json"
    events_path.write_text(
        json.dumps([serialize_event(event) for event in results.events], indent=2),
        encoding="utf-8",
    )

    detections_path = output_dir / "detections.json"
    detections_path.write_text(
        json.dumps(
            [
                {
                    "rule": det.rule,
                    "severity": det.severity,
                    "description": det.description,
                    "events": [serialize_event(event) for event in det.events],
                }
                for det in results.detections
            ],
            indent=2,
        ),
        encoding="utf-8",
    )

    correlations_path = output_dir / "correlations.json"
    correlations_path.write_text(
        json.dumps(
            [
                {
                    "name": corr.name,
                    "severity": corr.severity,
                    "description": corr.description,
                    "contributing_detections": corr.contributing_detections,
                    "events": [serialize_event(event) for event in corr.events],
                }
                for corr in results.correlations
            ],
            indent=2,
        ),
        encoding="utf-8",
    )

    alerts_path = output_dir / "alerts.json"
    alerts_path.write_text(
        json.dumps(
            [
                {
                    "id": alert.id,
                    "severity": alert.severity,
                    "title": alert.title,
                    "description": alert.description,
                    "timestamp": alert.timestamp.isoformat(),
                    "items": [serialize_event(event) for event in alert.items],
                }
                for alert in results.alerts
            ],
            indent=2,
        ),
        encoding="utf-8",
    )
