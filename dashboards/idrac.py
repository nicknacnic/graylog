"""Dell iDRAC dashboard.

Three pages, modeled on the iLO dashboard:
  1. Operational health     — what's wrong right now
  2. Physical inventory     — what's installed, what's empty
  3. Thermal & power trends — 7-day trends, charts

Driven by Redfish data emitted by pollers/idrac_redfish.py into the
"iDRAC Redfish" stream.

Run after sourcing env.sh + after indexing/idrac_redfish.py has created
the stream:
    python3 dashboards/idrac.py
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))
import graylog as gl  # noqa: E402

STREAM_TITLE = "iDRAC Redfish"
TITLE = "Dell iDRAC"
SUMMARY = "Dell server hardware health via iDRAC Redfish API"
DESCRIPTION = (
    "Polled every 60s (health snapshot) and every 5min (Lclog + Sel) by the "
    "idrac-poller systemd timer on the Graylog VM. Fields are prefixed "
    "idrac_*. Slice on idrac_event_type (system, thermal, fan, power, psu, "
    "drive, array_controller, thermal_max, lclog, sel)."
)

DAY = 86400
WEEK = 7 * DAY


def resolve_stream_id(title: str) -> str:
    streams = gl.api("GET", "streams") or {}
    for s in streams.get("streams", []):
        if s.get("title") == title:
            return s["id"]
    raise SystemExit(
        f"stream {title!r} not found — run `python3 indexing/idrac_redfish.py` first"
    )


# ── widget helpers (same shape as dashboards/ilo.py) ────────────────────────

def _pivot_series_for(fn: str) -> dict:
    return gl.parse_series_fn(fn)


def numeric(title: str, query: str, fn: str, *, timerange: int = DAY,
            pos: dict, name: str = "value") -> dict:
    return {
        "title": title, "kind": "agg", "viz": "numeric",
        "query": query, "timerange": timerange,
        "pivot_series": [_pivot_series_for(fn)],
        "series": [{"config": {"name": name}, "function": fn}],
        "pos": pos,
    }


def line_over_time(title: str, query: str, series: list[tuple[str, str]],
                   *, timerange: int = WEEK, pos: dict) -> dict:
    return {
        "title": title, "kind": "agg", "viz": "line",
        "query": query, "timerange": timerange,
        "row_field": "timestamp",
        "series": [{"config": {"name": name}, "function": fn} for name, fn in series],
        "pivot_series": [_pivot_series_for(fn) for _, fn in series],
        "pos": pos,
    }


def bar_categorical(title: str, query: str, *, field: str, pos: dict,
                    timerange: int = DAY, row_limit: int = 25) -> dict:
    return {
        "title": title, "kind": "agg", "viz": "bar",
        "query": query, "timerange": timerange,
        "row_field": field, "row_limit": row_limit,
        "pos": pos,
    }


def pie(title: str, query: str, *, field: str, pos: dict,
        timerange: int = DAY, row_limit: int = 10) -> dict:
    return {
        "title": title, "kind": "agg", "viz": "pie",
        "query": query, "timerange": timerange,
        "row_field": field, "row_limit": row_limit,
        "pos": pos,
    }


def table(title: str, query: str, *, row_field: str, series: list[tuple[str, str]],
          pos: dict, timerange: int = DAY, row_limit: int = 25) -> dict:
    return {
        "title": title, "kind": "agg", "viz": "table",
        "query": query, "timerange": timerange,
        "row_field": row_field, "row_limit": row_limit,
        "series": [{"config": {"name": name}, "function": fn} for name, fn in series],
        "pivot_series": [_pivot_series_for(fn) for _, fn in series],
        "pos": pos,
    }


def messages_list(title: str, query: str, *, pos: dict, timerange: int = DAY) -> dict:
    return {"title": title, "kind": "messages", "query": query,
            "timerange": timerange, "pos": pos}


# ── pages ────────────────────────────────────────────────────────────────────

def page_operational() -> list[dict]:
    """Page 1: what's broken right now."""
    return [
        # Row 1: status numerics
        numeric("System health",  "idrac_event_type:system", "latest(idrac_health)",
                pos={"col": 1, "row": 1, "width": 3, "height": 2}, name="health"),
        numeric("Power state",    "idrac_event_type:system", "latest(idrac_power_state)",
                pos={"col": 4, "row": 1, "width": 3, "height": 2}, name="state"),
        numeric("Watts consumed", "idrac_event_type:power",  "latest(idrac_watts_consumed)",
                pos={"col": 7, "row": 1, "width": 3, "height": 2}, name="W"),
        numeric("Max chassis °C", "idrac_event_type:thermal_max", "latest(idrac_max_temp_c)",
                pos={"col": 10, "row": 1, "width": 3, "height": 2}, name="°C"),
        # Row 2: trouble overview
        bar_categorical("Drive health (1h)", "idrac_event_type:drive",
                        field="idrac_drive_health", pos={"col": 1, "row": 3, "width": 4, "height": 4},
                        timerange=3600),
        bar_categorical("PSU health (1h)", "idrac_event_type:psu",
                        field="idrac_psu_health", pos={"col": 5, "row": 3, "width": 4, "height": 4},
                        timerange=3600),
        bar_categorical("Fan health (1h)", "idrac_event_type:fan",
                        field="idrac_fan_health", pos={"col": 9, "row": 3, "width": 4, "height": 4},
                        timerange=3600),
        # Row 3: drives needing attention
        table("Drives with non-OK health (1h)",
              'idrac_event_type:drive AND NOT idrac_drive_health:OK',
              row_field="idrac_drive_location",
              series=[
                  ("model",   "latest(idrac_drive_model)"),
                  ("health",  "latest(idrac_drive_health)"),
                  ("state",   "latest(idrac_drive_state)"),
                  ("life left %", "latest(idrac_drive_life_left_pct)"),
                  ("failure predicted", "latest(idrac_drive_failure_predicted)"),
              ],
              pos={"col": 1, "row": 7, "width": 6, "height": 4}, timerange=3600),
        # Row 3: PSU detail
        table("PSU state (1h)", "idrac_event_type:psu",
              row_field="idrac_psu_index",
              series=[
                  ("health",   "latest(idrac_psu_health)"),
                  ("state",    "latest(idrac_psu_state)"),
                  ("input V",  "latest(idrac_psu_input_voltage)"),
                  ("model",    "latest(idrac_psu_model)"),
              ],
              pos={"col": 7, "row": 7, "width": 6, "height": 4}, timerange=3600, row_limit=4),
        # Row 4: recent Lclog + Sel events
        messages_list("Recent Lclog + Sel events (24h)",
                      "idrac_event_type:lclog OR idrac_event_type:sel",
                      pos={"col": 1, "row": 11, "width": 12, "height": 6}),
    ]


def page_inventory() -> list[dict]:
    """Page 2: physical inventory — what's there, what's empty."""
    return [
        # Row 1: counts
        numeric("Total drives",  "idrac_event_type:drive",
                "cardinality(idrac_drive_location)",
                pos={"col": 1, "row": 1, "width": 3, "height": 2}, name="drives"),
        numeric("Total storage (bytes)",  "idrac_event_type:drive",
                "sum(idrac_drive_capacity_bytes)",
                pos={"col": 4, "row": 1, "width": 3, "height": 2}, name="B", timerange=120),
        numeric("Fans installed",  "idrac_event_type:fan AND idrac_fan_present:true",
                "cardinality(idrac_fan_name)",
                pos={"col": 7, "row": 1, "width": 3, "height": 2}, name="fans"),
        numeric("PSU bays installed", "idrac_event_type:psu",
                "cardinality(idrac_psu_index)",
                pos={"col": 10, "row": 1, "width": 3, "height": 2}, name="PSU"),
        # Row 2: system info
        table("System info (latest)", "idrac_event_type:system",
              row_field="idrac_hostname",
              series=[
                  ("manufacturer", "latest(idrac_manufacturer)"),
                  ("model",        "latest(idrac_model)"),
                  ("service tag",  "latest(idrac_sku)"),
                  ("serial",       "latest(idrac_serial)"),
                  ("BIOS",         "latest(idrac_bios_version)"),
                  ("CPUs",         "latest(idrac_cpu_count)"),
                  ("threads",      "latest(idrac_cpu_logical)"),
                  ("CPU model",    "latest(idrac_cpu_model)"),
                  ("RAM GiB",      "latest(idrac_mem_gib)"),
                  ("health",       "latest(idrac_health)"),
              ],
              pos={"col": 1, "row": 3, "width": 12, "height": 3}, row_limit=4),
        # Row 3: drive bay grid
        table("Drive bays (latest)", "idrac_event_type:drive",
              row_field="idrac_drive_location",
              series=[
                  ("model",      "latest(idrac_drive_model)"),
                  ("media",      "latest(idrac_drive_media)"),
                  ("protocol",   "latest(idrac_drive_protocol)"),
                  ("bytes",      "latest(idrac_drive_capacity_bytes)"),
                  ("RPM",        "latest(idrac_drive_rotational_rpm)"),
                  ("life left %", "latest(idrac_drive_life_left_pct)"),
                  ("health",     "latest(idrac_drive_health)"),
              ],
              pos={"col": 1, "row": 6, "width": 12, "height": 5}, row_limit=24),
        # Row 4: sensor slot occupancy
        table("Sensor slots (present vs absent)", "idrac_event_type:thermal",
              row_field="idrac_temp_name",
              series=[
                  ("present", "latest(idrac_temp_present)"),
                  ("state",   "latest(idrac_temp_state)"),
                  ("context", "latest(idrac_temp_physical_context)"),
                  ("°C",      "latest(idrac_temp_c)"),
              ],
              pos={"col": 1, "row": 11, "width": 12, "height": 6}, row_limit=60),
        # Row 5: distributions
        pie("Drive media split", "idrac_event_type:drive AND idrac_drive_health:OK",
            field="idrac_drive_media", pos={"col": 1, "row": 17, "width": 4, "height": 4}),
        pie("Drive protocol", "idrac_event_type:drive",
            field="idrac_drive_protocol", pos={"col": 5, "row": 17, "width": 4, "height": 4}),
        pie("Sensor presence", "idrac_event_type:thermal",
            field="idrac_temp_state", pos={"col": 9, "row": 17, "width": 4, "height": 4}),
    ]


def page_trends() -> list[dict]:
    """Page 3: 7-day thermal & power trends."""
    return [
        line_over_time("Power consumed over 7d (W)", "idrac_event_type:power",
                       series=[
                           ("watts (current)", "avg(idrac_watts_consumed)"),
                           ("watts avg",       "avg(idrac_watts_avg_interval)"),
                           ("watts max",       "max(idrac_watts_max_interval)"),
                       ],
                       pos={"col": 1, "row": 1, "width": 12, "height": 4}),
        line_over_time("Max chassis temp over 7d (°C)", "idrac_event_type:thermal_max",
                       series=[("max temp", "avg(idrac_max_temp_c)")],
                       pos={"col": 1, "row": 5, "width": 12, "height": 4}),
        line_over_time("Per-context temps over 7d (°C)",
                       "idrac_event_type:thermal AND idrac_temp_present:true",
                       series=[("avg °C", "avg(idrac_temp_c)")],
                       pos={"col": 1, "row": 9, "width": 12, "height": 4}),
        line_over_time("Fan reading over 7d", "idrac_event_type:fan AND idrac_fan_present:true",
                       series=[("avg", "avg(idrac_fan_reading)"),
                               ("max", "max(idrac_fan_reading)")],
                       pos={"col": 1, "row": 13, "width": 12, "height": 4}),
    ]


# ── build / apply ────────────────────────────────────────────────────────────

def build():
    stream_id = resolve_stream_id(STREAM_TITLE)
    page_defs = [
        ("Operational", page_operational, DAY),
        ("Physical inventory", page_inventory, 120),
        ("Trends (7d)", page_trends, WEEK),
    ]

    pages_for_search: list[dict] = []
    pages_for_view: list[dict] = []
    for title, fn, default_timerange in page_defs:
        qid = gl.gen_id()
        search_types, widgets, positions, titles, widget_mapping = gl.build_widgets_for_page(
            stream_id, fn(), default_timerange,
        )
        pages_for_search.append({
            "query_id": qid, "search_types": search_types, "timerange_s": default_timerange,
        })
        pages_for_view.append({
            "query_id": qid, "title": title,
            "widgets": widgets, "positions": positions,
            "titles": titles, "widget_mapping": widget_mapping,
        })

    existing = gl.api("GET", "views?per_page=200") or {}
    for v in existing.get("views", []):
        if v.get("title") == TITLE and v.get("type") == "DASHBOARD":
            print(f"deleting prior dashboard id={v['id']}")
            gl.api("DELETE", f"views/{v['id']}")

    search = gl.build_search_multipage(pages_for_search)
    sresp = gl.api("POST", "views/search", search)
    search_id = sresp["id"]
    print(f"search id: {search_id}")

    view = gl.build_view_multipage(
        title=TITLE, summary=SUMMARY, description=DESCRIPTION,
        search_id=search_id, pages=pages_for_view,
    )
    vresp = gl.api("POST", "views", view)
    print(f"view id:   {vresp['id']}")
    print(f"open:      {os.environ['GRAYLOG_URL'].rsplit('/api', 1)[0]}/dashboards/{vresp['id']}")


if __name__ == "__main__":
    build()
