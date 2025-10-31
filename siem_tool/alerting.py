"""Alert generation utilities."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import List, Sequence

from .detections import DetectionResult
from .correlation import CorrelationResult


@dataclass
class Alert:
    id: str
    severity: str
    title: str
    description: str
    timestamp: datetime
    items: List[dict]


def alerts_from_detections(detections: Sequence[DetectionResult]) -> List[Alert]:
    alerts: List[Alert] = []
    for idx, detection in enumerate(detections, start=1):
        timestamp = _earliest_timestamp(detection.events)
        alerts.append(
            Alert(
                id=f"DET-{idx:04d}",
                severity=detection.severity,
                title=f"Detection: {detection.rule}",
                description=detection.description,
                timestamp=timestamp,
                items=list(detection.events),
            )
        )
    return alerts


def alerts_from_correlations(correlations: Sequence[CorrelationResult]) -> List[Alert]:
    alerts: List[Alert] = []
    for idx, corr in enumerate(correlations, start=1):
        timestamp = _earliest_timestamp(corr.events)
        alerts.append(
            Alert(
                id=f"CORR-{idx:04d}",
                severity=corr.severity,
                title=corr.name,
                description=corr.description,
                timestamp=timestamp,
                items=list(corr.events),
            )
        )
    return alerts


def _earliest_timestamp(events: Sequence[dict]) -> datetime:
    timestamps = [event.get("timestamp") for event in events if isinstance(event.get("timestamp"), datetime)]
    if timestamps:
        return min(timestamps)
    return datetime.utcnow()
