"""Home Assistant logs — single-page dashboard.

Source: the ha-log-poller systemd timer (pollers/ha_log_poller.py)
pulls /api/hassio/core/logs from HA every 5 min and ships
WARNING/ERROR/CRITICAL entries as GELF to Graylog.

GELF wire fields (`_foo` on wire → `foo` indexed — leading underscore
strip):
    source       ha-darknetian          (GELF `host`)
    ha_level     WARNING | ERROR | CRITICAL
    ha_logger    homeassistant.<component> | custom_components.<x> | ...
    ha_thread    MainThread | SyncWorker_N | ...
    ha_traceback (only present for entries with continuation lines)

Dedicated 'Home Assistant' stream + 'home_assistant_*' index — see
indexing/ha.py. The source-filter is kept in BASE_QUERY for clarity
even though the stream rule already does it.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))
import graylog as gl  # noqa: E402

HA_STREAM_TITLE = "Home Assistant"
SOURCE = "ha-darknetian"
BASE_QUERY = f'source:"{SOURCE}"'

TITLE = "Home Assistant — logs"
SUMMARY = "HA core warnings + errors (poller pulls /api/hassio/core/logs every 5 min)"
DESCRIPTION = (
    "Home Assistant core log warnings, errors, and tracebacks. Fields: "
    "ha_level, ha_logger, ha_thread, ha_traceback. The poller default is "
    "WARNING+, so this dashboard intentionally skips INFO/DEBUG."
)

HOUR = 3600
DAY = 86400
WEEK = 7 * DAY


def _ps(fn: str) -> dict:
    return gl.parse_series_fn(fn)


def numeric(title, query, fn, *, timerange=DAY, pos, name="value"):
    return {
        "title": title, "kind": "agg", "viz": "numeric",
        "query": query, "timerange": timerange,
        "series": [{"config": {"name": name}, "function": fn}],
        "pivot_series": [_ps(fn)],
        "pos": pos,
    }


def bar(title, query, *, field, pos, timerange=DAY, row_limit=15):
    return {
        "title": title, "kind": "agg", "viz": "bar",
        "query": query, "timerange": timerange,
        "row_field": field, "row_limit": row_limit, "pos": pos,
    }


def pie(title, query, *, field, pos, timerange=DAY, row_limit=10):
    return {
        "title": title, "kind": "agg", "viz": "pie",
        "query": query, "timerange": timerange,
        "row_field": field, "row_limit": row_limit, "pos": pos,
    }


def table(title, query, *, row_field, series, pos, timerange=DAY, row_limit=25):
    return {
        "title": title, "kind": "agg", "viz": "table",
        "query": query, "timerange": timerange,
        "row_field": row_field, "row_limit": row_limit,
        "series": [{"config": {"name": n}, "function": fn} for n, fn in series],
        "pivot_series": [_ps(fn) for _, fn in series],
        "pos": pos,
    }


def line_ts(title, query, series, *, timerange=DAY, pos, column_field=None):
    return {
        "title": title, "kind": "agg", "viz": "line",
        "query": query, "timerange": timerange,
        "row_field": "timestamp", "column_field": column_field,
        "series": [{"config": {"name": n}, "function": fn} for n, fn in series],
        "pivot_series": [_ps(fn) for _, fn in series],
        "pos": pos,
    }


def msgs(title, query, *, pos, timerange=DAY):
    return {"title": title, "kind": "messages", "query": query,
            "timerange": timerange, "pos": pos}


def page_main():
    return [
        # ── Row 1: headline numerics ────────────────────────────────
        numeric("Total entries (24h)",
                BASE_QUERY,
                "count()",
                pos={"col": 1, "row": 1, "width": 3, "height": 2}, name="evt"),
        numeric("Errors (24h)",
                f'{BASE_QUERY} AND ha_level:ERROR',
                "count()",
                pos={"col": 4, "row": 1, "width": 3, "height": 2}, name="err"),
        numeric("Criticals (24h)",
                f'{BASE_QUERY} AND ha_level:CRITICAL',
                "count()",
                pos={"col": 7, "row": 1, "width": 3, "height": 2}, name="crit"),
        numeric("Loggers seen (24h)",
                BASE_QUERY,
                "cardinality(ha_logger)",
                pos={"col": 10, "row": 1, "width": 3, "height": 2}, name="loggers"),

        # ── Row 2: level mix + over-time ────────────────────────────
        pie("Level mix (24h)",
            BASE_QUERY,
            field="ha_level",
            pos={"col": 1, "row": 3, "width": 5, "height": 4}),
        line_ts("Entries by level (24h)",
                BASE_QUERY,
                series=[("count", "count()")],
                column_field="ha_level",
                pos={"col": 6, "row": 3, "width": 7, "height": 4}),

        # ── Row 3: noisiest loggers ─────────────────────────────────
        table("Top loggers (24h)",
              BASE_QUERY,
              row_field="ha_logger", row_limit=20,
              series=[("entries",  "count()"),
                      ("errors",   "count()"),
                      ("last seen", "latest(timestamp)")],
              pos={"col": 1, "row": 7, "width": 6, "height": 6}),
        table("Loggers most often erroring (24h)",
              f'{BASE_QUERY} AND ha_level:(ERROR OR CRITICAL)',
              row_field="ha_logger", row_limit=20,
              series=[("error events", "count()"),
                      ("last seen",   "latest(timestamp)")],
              pos={"col": 7, "row": 7, "width": 6, "height": 6}),

        # ── Row 4: tracebacks (rare, high signal) ───────────────────
        msgs("Recent tracebacks (7d)",
             f'{BASE_QUERY} AND _exists_:ha_traceback',
             timerange=WEEK,
             pos={"col": 1, "row": 13, "width": 12, "height": 6}),

        # ── Row 5: full warning/error stream ────────────────────────
        msgs("All warnings + errors (24h)",
             BASE_QUERY,
             pos={"col": 1, "row": 19, "width": 12, "height": 8}),
    ]


def _resolve_stream_id(title: str) -> str:
    for s in (gl.api("GET", "streams") or {}).get("streams", []):
        if s.get("title") == title:
            return s["id"]
    raise RuntimeError(f"stream not found: {title!r} (run indexing/ha.py first)")


def build():
    qid = gl.gen_id()
    stream_id = _resolve_stream_id(HA_STREAM_TITLE)
    sts, ws, pos, ti, wm = gl.build_widgets_for_page(
        stream_id, page_main(), DAY)

    existing = gl.api("GET", "views?per_page=200") or {}
    for v in existing.get("views", []):
        if v.get("title") == TITLE and v.get("type") == "DASHBOARD":
            print(f"deleting prior dashboard id={v['id']}")
            gl.api("DELETE", f"views/{v['id']}")

    search = gl.build_search(qid, sts, timerange_s=DAY)
    sresp = gl.api("POST", "views/search", search)
    print(f"search id: {sresp['id']}")

    view = gl.build_view(
        title=TITLE, summary=SUMMARY, description=DESCRIPTION,
        search_id=sresp["id"], query_id=qid,
        widgets=ws, positions=pos, titles=ti, widget_mapping=wm,
    )
    vresp = gl.api("POST", "views", view)
    print(f"view id:   {vresp['id']}")
    import os
    print(f"open:      {os.environ['GRAYLOG_URL'].rsplit('/api', 1)[0]}/dashboards/{vresp['id']}")


if __name__ == "__main__":
    build()
