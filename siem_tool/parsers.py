"""Log parsers for common log formats."""
from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Callable, Dict, Iterable, List

__all__ = [
    "parse_logs",
    "PARSERS",
]

DatetimeParser = Callable[[str], datetime]

APACHE_LOG_PATTERN = re.compile(
    r"(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+\"(?P<request>[A-Z]+\s+[^\s]+\s+HTTP/[^\"]+)\"\s+(?P<status>\d{3})\s+(?P<size>\S+)\s+\"(?P<referrer>[^\"]*)\"\s+\"(?P<user_agent>[^\"]*)\""
)

NGINX_LOG_PATTERN = re.compile(
    r"(?P<ip>\S+)\s+-\s+-\s+\[(?P<time>[^\]]+)\]\s+\"(?P<request>[A-Z]+\s+[^\s]+\s+HTTP/[^\"]+)\"\s+(?P<status>\d{3})\s+(?P<size>\S+)\s+\"(?P<referrer>[^\"]*)\"\s+\"(?P<user_agent>[^\"]*)\""
)

SYSLOG_PATTERN = re.compile(
    r"(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<process>[\w/.-]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<message>.*)"
)

WINDOWS_TIME_FORMAT = "%Y-%m-%dT%H:%M:%S"

MONTHS = {
    "Jan": 1,
    "Feb": 2,
    "Mar": 3,
    "Apr": 4,
    "May": 5,
    "Jun": 6,
    "Jul": 7,
    "Aug": 8,
    "Sep": 9,
    "Oct": 10,
    "Nov": 11,
    "Dec": 12,
}


def parse_apache_log(lines: Iterable[str]) -> List[Dict[str, object]]:
    events = []
    for line in lines:
        match = APACHE_LOG_PATTERN.match(line.strip())
        if not match:
            continue
        data = match.groupdict()
        events.append(
            {
                "source": "apache",
                "ip": data["ip"],
                "timestamp": _parse_apache_time(data["time"]),
                "request": data["request"],
                "status": int(data["status"]),
                "size": int(data["size"]) if data["size"].isdigit() else 0,
                "referrer": data["referrer"],
                "user_agent": data["user_agent"],
            }
        )
    return events


def parse_nginx_log(lines: Iterable[str]) -> List[Dict[str, object]]:
    events = []
    for line in lines:
        match = NGINX_LOG_PATTERN.match(line.strip())
        if not match:
            continue
        data = match.groupdict()
        events.append(
            {
                "source": "nginx",
                "ip": data["ip"],
                "timestamp": _parse_apache_time(data["time"]),
                "request": data["request"],
                "status": int(data["status"]),
                "size": int(data["size"]) if data["size"].isdigit() else 0,
                "referrer": data["referrer"],
                "user_agent": data["user_agent"],
            }
        )
    return events


def parse_syslog(lines: Iterable[str]) -> List[Dict[str, object]]:
    events = []
    current_year = datetime.utcnow().year
    for line in lines:
        match = SYSLOG_PATTERN.match(line.strip())
        if not match:
            continue
        data = match.groupdict()
        month = MONTHS[data["month"]]
        timestamp = datetime(
            year=current_year,
            month=month,
            day=int(data["day"]),
            hour=int(data["time"][0:2]),
            minute=int(data["time"][3:5]),
            second=int(data["time"][6:8]),
        )
        events.append(
            {
                "source": "syslog",
                "host": data["host"],
                "process": data["process"],
                "pid": int(data["pid"]) if data["pid"] else None,
                "message": data["message"],
                "timestamp": timestamp,
            }
        )
    return events


def parse_windows_eventlog(lines: Iterable[str]) -> List[Dict[str, object]]:
    events = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        record = json.loads(line)
        timestamp = datetime.strptime(record["time_created"], WINDOWS_TIME_FORMAT)
        record.update({"source": "windows", "timestamp": timestamp})
        events.append(record)
    return events


PARSERS: Dict[str, Callable[[Iterable[str]], List[Dict[str, object]]]] = {
    "apache": parse_apache_log,
    "nginx": parse_nginx_log,
    "syslog": parse_syslog,
    "windows": parse_windows_eventlog,
}


def parse_logs(path: Path, source: str) -> List[Dict[str, object]]:
    """Parse logs from ``path`` according to ``source`` type."""
    parser = PARSERS.get(source.lower())
    if parser is None:
        raise ValueError(f"Unsupported log source: {source}")
    with Path(path).open("r", encoding="utf-8") as handle:
        return parser(handle)


def _parse_apache_time(value: str) -> datetime:
    # Example: 10/Oct/2000:13:55:36 -0700
    dt_str, _, offset = value.partition(" ")
    timestamp = datetime.strptime(dt_str, "%d/%b/%Y:%H:%M:%S")
    return timestamp
