"""HPE iLO (ProLiant DL380p Gen8) dashboard.

Three pages:
  1. Operational health     — what's wrong right now
  2. Physical inventory     — what's installed, what's empty
  3. Thermal & power trends — 7-day trends, charts

Driven by Redfish data emitted by pollers/ilo_redfish.py into the
"iLO Redfish" stream.

Run after sourcing env.sh:
    python3 dashboards/ilo.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))
import graylog as gl  # noqa: E402

STREAM_ID = "6a0168826bb644169284ed12"
TITLE = "HPE iLO — esxi2"
SUMMARY = "ProLiant DL380p Gen8 hardware health via iLO Redfish API"
DESCRIPTION = (
    "Polled every 60s (health snapshot) and every 5min (IEL log) by the "
    "ilo-poller systemd timer on the Graylog VM. Fields are prefixed "
    "ilo_*. Use the categorical ilo_event_type to slice (system, thermal, "
    "fan, power, psu, drive, array_controller, thermal_max, iel)."
)

DAY = 86400
WEEK = 7 * DAY


# ── helpers ──────────────────────────────────────────────────────────────────

def numeric(title: str, query: str, fn: str, *, timerange: int = DAY,
            pos: dict, name: str = "value") -> dict:
    return {
        "title": title, "kind": "agg", "viz": "numeric",
        "query": query, "timerange": timerange,
        "pivot_series": [_pivot_series_for(fn)],
        "series": [{"config": {"name": name}, "function": fn}],
        "pos": pos,
    }


def _pivot_series_for(fn: str) -> dict:
    return gl.parse_series_fn(fn)


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
        numeric("System health",  "ilo_event_type:system", "latest(ilo_health)",
                pos={"col": 1, "row": 1, "width": 3, "height": 2}, name="health"),
        numeric("Power state",    "ilo_event_type:system", "latest(ilo_power_state)",
                pos={"col": 4, "row": 1, "width": 3, "height": 2}, name="state"),
        numeric("Watts consumed", "ilo_event_type:power",  "latest(ilo_watts_consumed)",
                pos={"col": 7, "row": 1, "width": 3, "height": 2}, name="W"),
        numeric("Max chassis °C", "ilo_event_type:thermal_max", "latest(ilo_max_temp_c)",
                pos={"col": 10, "row": 1, "width": 3, "height": 2}, name="°C"),
        # Row 2: trouble overview
        bar_categorical("Drive health (1h)", "ilo_event_type:drive",
                        field="ilo_drive_health", pos={"col": 1, "row": 3, "width": 4, "height": 4},
                        timerange=3600),
        bar_categorical("PSU health (1h)", "ilo_event_type:psu",
                        field="ilo_psu_health", pos={"col": 5, "row": 3, "width": 4, "height": 4},
                        timerange=3600),
        bar_categorical("Fan health (1h)", "ilo_event_type:fan",
                        field="ilo_fan_health", pos={"col": 9, "row": 3, "width": 4, "height": 4},
                        timerange=3600),
        # Row 3: drives needing attention
        table("Drives with non-OK health (1h)",
              'ilo_event_type:drive AND NOT ilo_drive_health:OK',
              row_field="ilo_drive_location",
              series=[
                  ("model",  "latest(ilo_drive_model)"),
                  ("health", "latest(ilo_drive_health)"),
                  ("state",  "latest(ilo_drive_state)"),
                  ("temp °C", "latest(ilo_drive_temp_c)"),
              ],
              pos={"col": 1, "row": 7, "width": 6, "height": 4}, timerange=3600),
        # Row 3: PSU detail
        table("PSU state (1h)", "ilo_event_type:psu",
              row_field="ilo_psu_index",
              series=[
                  ("health",   "latest(ilo_psu_health)"),
                  ("state",    "latest(ilo_psu_state)"),
                  ("input V",  "latest(ilo_psu_input_voltage)"),
                  ("model",    "latest(ilo_psu_model)"),
              ],
              pos={"col": 7, "row": 7, "width": 6, "height": 4}, timerange=3600, row_limit=4),
        # Row 4: recent IEL events
        messages_list("Recent IEL events (24h)", "ilo_event_type:iel",
                      pos={"col": 1, "row": 11, "width": 12, "height": 6}),
    ]


def page_inventory() -> list[dict]:
    """Page 2: physical inventory — what's there, what's empty."""
    return [
        # Row 1: counts
        numeric("Total drives",  "ilo_event_type:drive",
                "cardinality(ilo_drive_location)",
                pos={"col": 1, "row": 1, "width": 3, "height": 2}, name="drives"),
        numeric("Total storage (GB)",  "ilo_event_type:drive",
                "sum(ilo_drive_capacity_gb)",  # 1 cycle worth, divide by samples later if needed
                pos={"col": 4, "row": 1, "width": 3, "height": 2}, name="GB", timerange=120),
        numeric("Fans installed",  "ilo_event_type:fan AND ilo_fan_present:true",
                "cardinality(ilo_fan_name)",
                pos={"col": 7, "row": 1, "width": 3, "height": 2}, name="fans"),
        numeric("PSU bays installed", "ilo_event_type:psu",
                "cardinality(ilo_psu_index)",
                pos={"col": 10, "row": 1, "width": 3, "height": 2}, name="PSU"),
        # Row 2: system info
        table("System info (latest)", "ilo_event_type:system",
              row_field="ilo_hostname",
              series=[
                  ("model",      "latest(ilo_model)"),
                  ("BIOS",       "latest(ilo_bios_version)"),
                  ("CPUs",       "latest(ilo_cpu_count)"),
                  ("CPU model",  "latest(ilo_cpu_model)"),
                  ("RAM GiB",    "latest(ilo_mem_gib)"),
                  ("health",     "latest(ilo_health)"),
              ],
              pos={"col": 1, "row": 3, "width": 12, "height": 3}, row_limit=4),
        # Row 3: drive bay grid
        table("Drive bays (latest)", "ilo_event_type:drive",
              row_field="ilo_drive_location",
              series=[
                  ("model",     "latest(ilo_drive_model)"),
                  ("media",     "latest(ilo_drive_media)"),
                  ("interface", "latest(ilo_drive_interface)"),
                  ("GB",        "latest(ilo_drive_capacity_gb)"),
                  ("RPM",       "latest(ilo_drive_rotational_rpm)"),
                  ("temp °C",   "latest(ilo_drive_temp_c)"),
                  ("max °C",    "latest(ilo_drive_temp_max_c)"),
                  ("health",    "latest(ilo_drive_health)"),
              ],
              pos={"col": 1, "row": 6, "width": 12, "height": 5}, row_limit=24),
        # Row 4: PCI / sensor slot occupancy
        table("Sensor slots (present vs absent)", "ilo_event_type:thermal",
              row_field="ilo_temp_name",
              series=[
                  ("present", "latest(ilo_temp_present)"),
                  ("state",   "latest(ilo_temp_state)"),
                  ("context", "latest(ilo_temp_physical_context)"),
                  ("°C",      "latest(ilo_temp_c)"),
              ],
              pos={"col": 1, "row": 11, "width": 12, "height": 6}, row_limit=60),
        # Row 5: distributions
        pie("Drive media split", "ilo_event_type:drive AND ilo_drive_health:OK",
            field="ilo_drive_media", pos={"col": 1, "row": 17, "width": 4, "height": 4}),
        pie("Drive interface", "ilo_event_type:drive",
            field="ilo_drive_interface", pos={"col": 5, "row": 17, "width": 4, "height": 4}),
        pie("Sensor presence", "ilo_event_type:thermal",
            field="ilo_temp_state", pos={"col": 9, "row": 17, "width": 4, "height": 4}),
    ]


def page_trends() -> list[dict]:
    """Page 3: 7-day thermal & power trends."""
    return [
        line_over_time("Power consumed over 7d (W)", "ilo_event_type:power",
                       series=[
                           ("watts (current)", "avg(ilo_watts_consumed)"),
                           ("watts avg",       "avg(ilo_watts_avg_interval)"),
                           ("watts max",       "max(ilo_watts_max_interval)"),
                       ],
                       pos={"col": 1, "row": 1, "width": 12, "height": 4}),
        line_over_time("Max chassis temp over 7d (°C)", "ilo_event_type:thermal_max",
                       series=[("max temp", "avg(ilo_max_temp_c)")],
                       pos={"col": 1, "row": 5, "width": 12, "height": 4}),
        line_over_time("Per-context temps over 7d (°C)",
                       "ilo_event_type:thermal AND ilo_temp_present:true",
                       series=[("avg °C", "avg(ilo_temp_c)")],
                       pos={"col": 1, "row": 9, "width": 12, "height": 4}),
        line_over_time("Fan speed % over 7d", "ilo_event_type:fan AND ilo_fan_present:true",
                       series=[("avg %", "avg(ilo_fan_reading)"),
                               ("max %", "max(ilo_fan_reading)")],
                       pos={"col": 1, "row": 13, "width": 12, "height": 4}),
        line_over_time("Drive temps over 7d (°C)", "ilo_event_type:drive",
                       series=[("avg °C", "avg(ilo_drive_temp_c)"),
                               ("max °C", "max(ilo_drive_temp_c)")],
                       pos={"col": 1, "row": 17, "width": 12, "height": 4}),
    ]


# ── build / apply ────────────────────────────────────────────────────────────

def build():
    page_defs = [
        ("Operational", page_operational, DAY),
        ("Physical inventory", page_inventory, 120),
        ("Trends (7d)", page_trends, WEEK),
    ]

    pages_for_search: list[dict] = []
    pages_for_view: list[dict] = []
    for title, fn, default_timerange in page_defs:
        qid = gl.gen_id()
        search_types, widgets, positions, titles, widget_mapping = gl.build_widgets_for_page(STREAM_ID, fn(), default_timerange)
        pages_for_search.append({
            "query_id": qid, "search_types": search_types, "timerange_s": default_timerange,
        })
        pages_for_view.append({
            "query_id": qid, "title": title,
            "widgets": widgets, "positions": positions,
            "titles": titles, "widget_mapping": widget_mapping,
        })

    # Delete prior view of same title to keep re-runs idempotent
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
    import os
    print(f"open:      {os.environ['GRAYLOG_URL'].rsplit('/api', 1)[0]}/dashboards/{vresp['id']}")


if __name__ == "__main__":
    build()
