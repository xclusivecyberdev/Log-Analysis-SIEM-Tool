"""Correlation engine to combine related detections."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Dict, Iterable, List, Sequence

from .detections import DetectionResult, Event


@dataclass
class CorrelationResult:
    name: str
    severity: str
    description: str
    events: List[Event]
    contributing_detections: List[str]


def correlate(events: Sequence[Event], detections: Sequence[DetectionResult]) -> List[CorrelationResult]:
    """Attempt to correlate events into multi-stage attack narratives."""
    http_events: Dict[str, List[Event]] = {}
    for event in events:
        if event.get("source") in {"apache", "nginx"}:
            ip = str(event.get("ip", "unknown"))
            http_events.setdefault(ip, []).append(event)
    windows_events: Dict[str, List[Event]] = {}
    syslog_events: Dict[str, List[Event]] = {}
    for event in events:
        if event.get("source") == "windows":
            ip = str(event.get("ip_address", event.get("ip", "unknown")))
            windows_events.setdefault(ip, []).append(event)
        if event.get("source") == "syslog":
            message = str(event.get("message", ""))
            ip = _extract_ip_from_message(message)
            if ip:
                syslog_events.setdefault(ip, []).append(event)

    correlations: List[CorrelationResult] = []
    for ip, suspicious_http in http_events.items():
        time_window_start = min((e.get("timestamp") for e in suspicious_http if isinstance(e.get("timestamp"), datetime)), default=None)
        time_window_end = max((e.get("timestamp") for e in suspicious_http if isinstance(e.get("timestamp"), datetime)), default=None)
        if time_window_start is None:
            continue
        window = (time_window_start - timedelta(minutes=5), time_window_end + timedelta(minutes=30))
        related_events: List[Event] = list(suspicious_http)
        detection_ids: List[str] = [d.rule for d in detections if any(e in suspicious_http for e in d.events)]

        def within_window(ev: Event) -> bool:
            ts = ev.get("timestamp")
            return isinstance(ts, datetime) and window[0] <= ts <= window[1]

        for candidate in windows_events.get(ip, []):
            if within_window(candidate):
                related_events.append(candidate)
        for candidate in syslog_events.get(ip, []):
            if within_window(candidate):
                related_events.append(candidate)
        if len(related_events) > len(suspicious_http):
            correlations.append(
                CorrelationResult(
                    name="Multi-stage intrusion",
                    severity="high",
                    description=(
                        "Observed suspicious web traffic from IP {ip} followed by authentication activity "
                        "on internal systems."
                    ).format(ip=ip),
                    events=sorted(
                        related_events,
                        key=lambda ev: ev.get("timestamp") or datetime.min,
                    ),
                    contributing_detections=sorted(set(detection_ids)),
                )
            )
    return correlations


def _extract_ip_from_message(message: str) -> str | None:
    for token in message.split():
        if token.count(".") == 3:
            parts = token.split(".")
            if all(part.isdigit() and 0 <= int(part) <= 255 for part in parts):
                return token
    return None
