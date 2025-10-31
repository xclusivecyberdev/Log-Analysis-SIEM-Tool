"""Command line interface for the SIEM tool."""
from __future__ import annotations

import argparse
from pathlib import Path
from .engine import AnalysisResults, DEFAULT_SOURCES, ingest_logs, run_analysis, save_results
from .reporting import generate_markdown_report
from .dashboard import create_dashboard


__version__ = "0.1.0"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Security log analysis tool")
    parser.add_argument("--version", action="version", version=f"siem-tool {__version__}")

    sub = parser.add_subparsers(dest="command")

    analyze = sub.add_parser("analyze", help="Run the analysis pipeline")
    analyze.add_argument("--output", type=Path, default=Path("outputs"), help="Directory for structured results")
    analyze.add_argument(
        "--report", type=Path, default=Path("reports/security_report.md"), help="Path for generated markdown report"
    )
    analyze.add_argument("--no-save", action="store_true", help="Do not persist structured JSON outputs")

    dashboard = sub.add_parser("dashboard", help="Launch the interactive dashboard")
    dashboard.add_argument(
        "--reuse", action="store_true", help="Reuse cached results from the output directory if available"
    )
    dashboard.add_argument("--output", type=Path, default=Path("outputs"))

    return parser


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return

    if args.command == "analyze":
        _run_analyze_command(args)
    elif args.command == "dashboard":
        _run_dashboard_command(args)
    else:
        parser.error(f"Unknown command {args.command}")


def _run_analyze_command(args: argparse.Namespace) -> AnalysisResults:
    events = ingest_logs(DEFAULT_SOURCES)
    results = run_analysis(events)
    if not args.no_save:
        save_results(results, args.output)
    generate_markdown_report(args.report, results.detections, results.correlations, results.alerts)
    print(f"Analysis complete. Report written to {args.report}")
    return results


def _run_dashboard_command(args: argparse.Namespace) -> None:
    if args.reuse:
        results = _load_cached_results(args.output)
    else:
        results = run_analysis(ingest_logs(DEFAULT_SOURCES))
        save_results(results, args.output)
    app = create_dashboard(results)
    app.run_server(debug=False)


def _load_cached_results(output: Path) -> AnalysisResults:
    import json
    from datetime import datetime

    output = Path(output)
    events_path = output / "events.json"
    detections_path = output / "detections.json"
    correlations_path = output / "correlations.json"
    alerts_path = output / "alerts.json"

    def parse_timestamp(value):
        if isinstance(value, str):
            return datetime.fromisoformat(value)
        return value

    events = []
    if events_path.exists():
        events = json.loads(events_path.read_text(encoding="utf-8"))
        for event in events:
            if "timestamp" in event:
                event["timestamp"] = parse_timestamp(event["timestamp"])

    def load_list(path):
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
        return []

    raw_detections = load_list(detections_path)
    raw_correlations = load_list(correlations_path)
    raw_alerts = load_list(alerts_path)

    from .detections import DetectionResult
    from .correlation import CorrelationResult
    from .alerting import Alert

    detections = [
        DetectionResult(
            rule=item["rule"],
            severity=item["severity"],
            description=item["description"],
            events=item.get("events", []),
        )
        for item in raw_detections
    ]
    correlations = [
        CorrelationResult(
            name=item["name"],
            severity=item["severity"],
            description=item["description"],
            events=item.get("events", []),
            contributing_detections=item.get("contributing_detections", []),
        )
        for item in raw_correlations
    ]
    alerts = [
        Alert(
            id=item["id"],
            severity=item["severity"],
            title=item["title"],
            description=item["description"],
            timestamp=parse_timestamp(item["timestamp"]),
            items=item.get("items", []),
        )
        for item in raw_alerts
    ]

    return AnalysisResults(
        events=events,
        detections=detections,
        correlations=correlations,
        alerts=alerts,
    )


if __name__ == "__main__":
    main()
