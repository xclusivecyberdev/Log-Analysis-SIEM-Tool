"""Interactive dashboard for exploring analysis results."""
from __future__ import annotations

from datetime import datetime
from typing import Sequence

try:  # pragma: no cover - optional dependency import guard
    import dash
    import dash_core_components as dcc
    import dash_html_components as html
    import pandas as pd
    import plotly.express as px
except ModuleNotFoundError as exc:  # pragma: no cover
    dash = None  # type: ignore[assignment]
    dcc = html = px = pd = None  # type: ignore[assignment]
    _IMPORT_ERROR = exc
else:
    _IMPORT_ERROR = None

from .engine import AnalysisResults


def create_dashboard(results: AnalysisResults) -> dash.Dash:
    if dash is None or dcc is None or html is None or pd is None or px is None:  # pragma: no cover
        raise RuntimeError(
            "Dash and Plotly dependencies are required to launch the dashboard. "
            "Install them via 'pip install -r requirements.txt'."
        ) from _IMPORT_ERROR
    app = dash.Dash(__name__)
    event_df = _events_dataframe(results)
    detection_df = _detection_dataframe(results)
    alert_df = _alert_dataframe(results)

    figures = []
    if not event_df.empty:
        timeline_fig = px.histogram(
            event_df,
            x="timestamp",
            color="source",
            nbins=50,
            title="Event volume over time",
        )
        figures.append(dcc.Graph(figure=timeline_fig))
    if not detection_df.empty:
        detection_fig = px.bar(
            detection_df,
            x="rule",
            y="count",
            color="severity",
            title="Detections by rule",
        )
        figures.append(dcc.Graph(figure=detection_fig))
    if not alert_df.empty:
        alert_fig = px.timeline(
            alert_df,
            x_start="timestamp",
            x_end="end_time",
            y="title",
            color="severity",
            title="Alerts timeline",
        )
        alert_fig.update_yaxes(autorange="reversed")
        figures.append(dcc.Graph(figure=alert_fig))

    app.layout = html.Div(
        children=[
            html.H1("Security Log Analysis Dashboard"),
            html.P(
                "Use this dashboard to explore parsed log events, detection results, "
                "and correlated security incidents."
            ),
            *figures,
        ]
    )
    return app


def _events_dataframe(results: AnalysisResults) -> pd.DataFrame:
    rows = []
    for event in results.events:
        row = dict(event)
        ts = row.get("timestamp")
        if isinstance(ts, datetime):
            row["timestamp"] = ts
        elif isinstance(ts, str):
            row["timestamp"] = datetime.fromisoformat(ts)
        rows.append(row)
    if not rows:
        return pd.DataFrame()
    return pd.DataFrame(rows)


def _detection_dataframe(results: AnalysisResults) -> pd.DataFrame:
    rows = []
    for detection in results.detections:
        rows.append(
            {
                "rule": detection.rule,
                "severity": detection.severity,
                "count": len(detection.events),
            }
        )
    return pd.DataFrame(rows)


def _alert_dataframe(results: AnalysisResults) -> pd.DataFrame:
    rows = []
    for alert in results.alerts:
        rows.append(
            {
                "id": alert.id,
                "severity": alert.severity,
                "title": alert.title,
                "timestamp": alert.timestamp,
                "end_time": alert.timestamp,
            }
        )
    return pd.DataFrame(rows)
