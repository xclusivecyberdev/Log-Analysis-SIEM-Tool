# Security Log Analysis SIEM Tool

This project implements a small-scale Security Information and Event Management (SIEM) style workflow. It parses logs from multiple common sources, applies heuristic detections, correlates multi-stage attacks, generates alerts, and provides both reporting and dashboard visualisations.

## Features

- **Log ingestion:** Parsers for Apache HTTPD, Nginx, Syslog, and Windows Event Log (JSONL) formats with sample datasets in `data/`.
- **Detection engine:** Pattern-matching rules for failed authentication bursts, suspicious endpoint probing, and high-volume traffic anomalies.
- **Correlation:** Combines related detections across data sources to highlight potential multi-stage intrusions.
- **Alerting:** Creates structured alert objects from detections and correlated incidents.
- **Reporting:** Generates a Markdown report summarising detections, correlated incidents, and alerts.
- **Interactive dashboard:** Dash-powered web UI with Plotly charts for events, detections, and alerts.

## Project layout

```
.
├── data/                     # Sample log datasets
├── reports/                  # Report output directory (created on demand)
├── siem_tool/                # Python package with analysis modules
├── requirements.txt          # Runtime dependencies
└── README.md
```

## Getting started

1. **Install dependencies** (ideally inside a virtual environment):

   ```bash
   pip install -r requirements.txt
   ```

2. **Run the analysis pipeline** against the bundled sample data:

   ```bash
   python -m siem_tool.cli analyze
   ```

   This command parses the log files in `data/`, runs detections and correlation, writes structured JSON output into `outputs/`, and produces a Markdown report at `reports/security_report.md`.

3. **Launch the dashboard** to explore the generated data:

   ```bash
   python -m siem_tool.cli dashboard --reuse
   ```

   The `--reuse` flag reuses the cached results in `outputs/`. Omit it to rerun the analysis before starting the Dash server.

## Customising input data

You can analyse your own log files by replacing the samples in `data/` or by modifying the `DEFAULT_SOURCES` mapping in `siem_tool/engine.py` to point to alternative locations. Each log type uses the following formats:

- **Apache/Nginx:** Combined log format (space-separated, quoted request field).
- **Syslog:** RFC 3164-style entries with host, process, and message details.
- **Windows Event Logs:** JSON Lines (`.jsonl`) with a subset of Event Log fields; each line must include `time_created`, `event_id`, and optional metadata such as `account` or `ip_address`.

## Extending the tool

- Add new detection rules in `siem_tool/detections.py`.
- Implement additional correlations in `siem_tool/correlation.py`.
- Tailor alert routing (e.g., email or ticketing) by expanding `siem_tool/alerting.py`.
- Customise the dashboard layout and charts in `siem_tool/dashboard.py`.

## License

This project is provided as-is for educational and demonstration purposes.
