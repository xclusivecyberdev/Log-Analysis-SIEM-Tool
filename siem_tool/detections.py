"""Detection rules and anomaly heuristics."""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Dict, Iterable, List, Sequence

Event = Dict[str, object]


@dataclass
class DetectionResult:
    rule: str
    severity: str
    description: str
    events: List[Event]


FAILED_HTTP_STATUSES = {401, 403, 404}
SUSPICIOUS_ENDPOINT_KEYWORDS = {"admin", "login", "wp-login", "xmlrpc"}


def analyze_events(events: Sequence[Event]) -> List[DetectionResult]:
    detections: List[DetectionResult] = []
    detections.extend(_detect_failed_http_bursts(events))
    detections.extend(_detect_repeated_syslog_failures(events))
    detections.extend(_detect_windows_logon_failures(events))
    detections.extend(_detect_high_request_volume(events))
    return detections


def _detect_failed_http_bursts(events: Sequence[Event]) -> List[DetectionResult]:
    grouped: Dict[str, List[Event]] = defaultdict(list)
    for event in events:
        if event.get("source") not in {"apache", "nginx"}:
            continue
        status = event.get("status")
        if isinstance(status, int) and status in FAILED_HTTP_STATUSES:
            grouped[event.get("ip", "unknown")].append(event)
    detections: List[DetectionResult] = []
    for ip, items in grouped.items():
        if len(items) >= 5:
            suspicious_endpoints = [
                e for e in items if any(keyword in str(e.get("request", "")).lower() for keyword in SUSPICIOUS_ENDPOINT_KEYWORDS)
            ]
            description = f"{len(items)} failed HTTP requests from {ip}"
            if suspicious_endpoints:
                description += ", targeting admin endpoints"
            detections.append(
                DetectionResult(
                    rule="HTTP_FAILED_BURST",
                    severity="medium" if not suspicious_endpoints else "high",
                    description=description,
                    events=items,
                )
            )
    return detections


def _detect_repeated_syslog_failures(events: Sequence[Event]) -> List[DetectionResult]:
    failures: Dict[str, List[Event]] = defaultdict(list)
    for event in events:
        if event.get("source") != "syslog":
            continue
        message = str(event.get("message", "")).lower()
        if any(keyword in message for keyword in ("failed password", "authentication failure", "error")):
            host = str(event.get("host", "unknown"))
            failures[host].append(event)
    detections: List[DetectionResult] = []
    for host, items in failures.items():
        if len(items) >= 3:
            detections.append(
                DetectionResult(
                    rule="SYSLOG_AUTH_FAILURE",
                    severity="high",
                    description=f"Repeated authentication failures on {host}",
                    events=items,
                )
            )
    return detections


def _detect_windows_logon_failures(events: Sequence[Event]) -> List[DetectionResult]:
    grouped: Dict[str, List[Event]] = defaultdict(list)
    for event in events:
        if event.get("source") != "windows":
            continue
        if str(event.get("event_id")) == "4625":  # Failed logon
            grouped[event.get("account", "unknown")].append(event)
    detections: List[DetectionResult] = []
    for account, items in grouped.items():
        if len(items) >= 3:
            detections.append(
                DetectionResult(
                    rule="WINDOWS_FAILED_LOGON",
                    severity="high",
                    description=f"Multiple failed logons for account {account}",
                    events=items,
                )
            )
    return detections


def _detect_high_request_volume(events: Sequence[Event]) -> List[DetectionResult]:
    http_events = [e for e in events if e.get("source") in {"apache", "nginx"}]
    grouped: Dict[str, List[Event]] = defaultdict(list)
    for event in http_events:
        grouped[event.get("ip", "unknown")].append(event)
    detections: List[DetectionResult] = []
    for ip, items in grouped.items():
        timestamps = sorted(
            [e.get("timestamp") for e in items if isinstance(e.get("timestamp"), datetime)]
        )
        if len(timestamps) < 10:
            continue
        window_start = timestamps[0]
        count = 0
        for ts in timestamps:
            if ts - window_start <= timedelta(minutes=1):
                count += 1
            else:
                window_start = ts
                count = 1
            if count >= 10:
                events_subset = [e for e in items if isinstance(e.get("timestamp"), datetime) and window_start <= e["timestamp"] <= ts]
                detections.append(
                    DetectionResult(
                        rule="HTTP_HIGH_VOLUME",
                        severity="medium",
                        description=f"High request volume from {ip} within a minute",
                        events=events_subset,
                    )
                )
                break
    return detections
