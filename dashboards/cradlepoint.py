"""Cradlepoint E300 dashboard.

Run after sourcing env.sh:
    source env.sh && python3 dashboards/cradlepoint.py

Builds the search + view payloads and POSTs them to Graylog. Prints the
created view id so you can confirm in the UI.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))
import graylog as gl  # noqa: E402

STREAM_ID = "697ef3beeeb15b769f441ed4"
TITLE = "Cradlepoint E300"
SUMMARY = "LTE router health, cellular signal, connected clients, WAN state"
DESCRIPTION = (
    "Built from the Cradlepoint syslog feed (UDP :515). Numeric fields "
    "(cp_signal_strength, cp_rssi, cp_sinr, cp_rsrp, cp_rsrq, cp_rfband, "
    "cp_client_count, cp_gps_lat/lng) are extracted by the 'Cradlepoint' "
    "pipeline rules. Categorical fields use cp_event_type."
)

DAY = 86400
WEEK = 7 * DAY


# Each spec produces one widget; the build function below converts it into the
# paired (search_type, widget) JSON and accumulates positions.
def specs() -> list[dict]:
    """Declarative widget list. Edit me to change the dashboard."""
    return [
        # Row 1 (height 2): four numerics
        {
            "title": "Messages (24h)",
            "kind": "agg", "viz": "numeric",
            "query": "", "timerange": DAY,
            "series": [{"config": {"name": "count"}, "function": "count()"}],
            "pos": {"col": 1, "row": 1, "width": 3, "height": 2},
            "pivot_series": [{"type": "count", "id": "count()"}],
        },
        {
            "title": "Connected clients (latest)",
            "kind": "agg", "viz": "numeric",
            "query": "cp_event_type:new_client", "timerange": DAY,
            "series": [{"config": {"name": "clients"}, "function": "latest(cp_client_count)"}],
            "pivot_series": [{"type": "latest", "id": "latest(cp_client_count)", "field": "cp_client_count"}],
            "pos": {"col": 4, "row": 1, "width": 3, "height": 2},
        },
        {
            "title": "GPS lock (latest)",
            "kind": "agg", "viz": "numeric",
            "query": "cp_event_type:gps_status", "timerange": DAY,
            "series": [{"config": {"name": "lock"}, "function": "latest(cp_gps_lock)"}],
            "pivot_series": [{"type": "latest", "id": "latest(cp_gps_lock)", "field": "cp_gps_lock"}],
            "pos": {"col": 7, "row": 1, "width": 3, "height": 2},
        },
        {
            "title": "Cellular service (latest)",
            "kind": "agg", "viz": "numeric",
            "query": "cp_event_type:signal_report", "timerange": DAY,
            "series": [{"config": {"name": "service"}, "function": "latest(cp_service)"}],
            "pivot_series": [{"type": "latest", "id": "latest(cp_service)", "field": "cp_service"}],
            "pos": {"col": 10, "row": 1, "width": 3, "height": 2},
        },
        # Row 2: signal strength trend (full width, 7d)
        {
            "title": "Signal strength % over 7d",
            "kind": "agg", "viz": "line",
            "query": "cp_event_type:signal_report", "timerange": WEEK,
            "row_field": "timestamp",
            "series": [{"config": {"name": "SS %"}, "function": "avg(cp_signal_strength)"}],
            "pivot_series": [{"type": "avg", "id": "avg(cp_signal_strength)", "field": "cp_signal_strength"}],
            "pos": {"col": 1, "row": 3, "width": 12, "height": 4},
        },
        # Row 3: RSSI/SINR/RSRP/RSRQ trends
        {
            "title": "RSSI / SINR / RSRP / RSRQ over 7d (dBm/dB)",
            "kind": "agg", "viz": "line",
            "query": "cp_event_type:signal_report", "timerange": WEEK,
            "row_field": "timestamp",
            "series": [
                {"config": {"name": "RSSI (dBm)"}, "function": "avg(cp_rssi)"},
                {"config": {"name": "SINR (dB)"}, "function": "avg(cp_sinr)"},
                {"config": {"name": "RSRP (dBm)"}, "function": "avg(cp_rsrp)"},
                {"config": {"name": "RSRQ (dB)"}, "function": "avg(cp_rsrq)"},
            ],
            "pivot_series": [
                {"type": "avg", "id": "avg(cp_rssi)", "field": "cp_rssi"},
                {"type": "avg", "id": "avg(cp_sinr)", "field": "cp_sinr"},
                {"type": "avg", "id": "avg(cp_rsrp)", "field": "cp_rsrp"},
                {"type": "avg", "id": "avg(cp_rsrq)", "field": "cp_rsrq"},
            ],
            "pos": {"col": 1, "row": 7, "width": 12, "height": 4},
        },
        # Row 4: client count over time + recent clients table
        {
            "title": "Connected clients over 7d",
            "kind": "agg", "viz": "line",
            "query": "cp_event_type:new_client", "timerange": WEEK,
            "row_field": "timestamp",
            "series": [{"config": {"name": "max clients"}, "function": "max(cp_client_count)"}],
            "pivot_series": [{"type": "max", "id": "max(cp_client_count)", "field": "cp_client_count"}],
            "pos": {"col": 1, "row": 11, "width": 6, "height": 4},
        },
        {
            "title": "Recent new clients (7d)",
            "kind": "agg", "viz": "table",
            "query": "cp_event_type:new_client", "timerange": WEEK,
            "row_field": "cp_new_client_mac",
            "row_limit": 25,
            "series": [
                {"config": {"name": "hostname"}, "function": "latest(client_hostname)"},
                {"config": {"name": "latest IP"}, "function": "latest(cp_new_client_ip)"},
                {"config": {"name": "client_fqdn (PTR)"}, "function": "latest(client_fqdn)"},
                {"config": {"name": "connect events"}, "function": "count()"},
            ],
            "pivot_series": [
                {"type": "latest", "id": "latest(client_hostname)", "field": "client_hostname"},
                {"type": "latest", "id": "latest(cp_new_client_ip)", "field": "cp_new_client_ip"},
                {"type": "latest", "id": "latest(client_fqdn)", "field": "client_fqdn"},
                {"type": "count", "id": "count()"},
            ],
            "pos": {"col": 7, "row": 11, "width": 6, "height": 4},
        },
        # Row 5: cell id changes / RFBAND / WAN DHCP
        {
            "title": "Cell-ID transitions (7d)",
            "kind": "agg", "viz": "bar",
            "query": "cp_event_type:cell_id", "timerange": WEEK,
            "row_field": "timestamp",
            "column_field": "cp_cell_id",
            "column_limit": 10,
            "pos": {"col": 1, "row": 15, "width": 4, "height": 4},
        },
        {
            "title": "RFBAND distribution (7d)",
            "kind": "agg", "viz": "pie",
            "query": "cp_event_type:signal_report", "timerange": WEEK,
            "row_field": "cp_rfband",
            "row_limit": 10,
            "pos": {"col": 5, "row": 15, "width": 4, "height": 4},
        },
        {
            "title": "WAN DHCP leases (7d)",
            "kind": "agg", "viz": "table",
            "query": "cp_event_type:wan_dhcp", "timerange": WEEK,
            "row_field": "cp_wan_ip",
            "row_limit": 10,
            "series": [
                {"config": {"name": "gateway"}, "function": "latest(cp_wan_gateway)"},
                {"config": {"name": "events"}, "function": "count()"},
            ],
            "pivot_series": [
                {"type": "latest", "id": "latest(cp_wan_gateway)", "field": "cp_wan_gateway"},
                {"type": "count", "id": "count()"},
            ],
            "pos": {"col": 9, "row": 15, "width": 4, "height": 4},
        },
        # Row 6: diagnostics — message list, excluding noisy signal reports
        {
            "title": "Recent events (non-signal-report)",
            "kind": "messages",
            "query": "NOT cp_event_type:signal_report",
            "timerange": DAY,
            "pos": {"col": 1, "row": 19, "width": 12, "height": 6},
        },
    ]


def build():
    query_id = gl.gen_id()
    search_types: list[dict] = []
    widgets: list[dict] = []
    positions: dict[str, dict] = {}
    titles: dict[str, str] = {}
    widget_mapping: dict[str, list[str]] = {}

    for s in specs():
        wid = gl.gen_id()
        stid = gl.gen_id()
        if s["kind"] == "agg":
            ps = gl.align_pivot_ids(s.get("series", []), s.get("pivot_series", []))
            search_types.append(gl.pivot(
                search_type_id=stid,
                stream_id=STREAM_ID,
                query=s.get("query", ""),
                timerange_s=s.get("timerange", DAY),
                row_field=s.get("row_field"),
                column_field=s.get("column_field"),
                series=ps,
                row_limit=s.get("row_limit", 25),
                column_limit=s.get("column_limit", 25),
            ))
            widgets.append(gl.widget_aggregation(
                widget_id=wid,
                stream_id=STREAM_ID,
                query=s.get("query", ""),
                timerange_s=s.get("timerange", DAY),
                row_field=s.get("row_field"),
                column_field=s.get("column_field"),
                series=s.get("series"),
                visualization=s["viz"],
                row_limit=s.get("row_limit", 25),
                column_limit=s.get("column_limit", 25),
            ))
        elif s["kind"] == "messages":
            search_types.append(gl.messages_searchtype(
                search_type_id=stid,
                stream_id=STREAM_ID,
                query=s.get("query", ""),
                timerange_s=s.get("timerange", DAY),
            ))
            widgets.append(gl.widget_messages(
                widget_id=wid,
                stream_id=STREAM_ID,
                query=s.get("query", ""),
                timerange_s=s.get("timerange", DAY),
            ))
        else:
            raise ValueError(f"unknown widget kind: {s['kind']}")

        positions[wid] = s["pos"]
        titles[wid] = s["title"]
        widget_mapping[wid] = [stid]

    # Delete any prior view with the same title so re-runs don't duplicate
    existing = gl.api("GET", "views?per_page=200") or {}
    for v in existing.get("views", []):
        if v.get("title") == TITLE and v.get("type") == "DASHBOARD":
            print(f"deleting prior dashboard id={v['id']}")
            gl.api("DELETE", f"views/{v['id']}")

    search = gl.build_search(query_id, search_types)
    search_resp = gl.api("POST", "views/search", search)
    search_id = search_resp["id"]
    print(f"search id: {search_id}")

    view = gl.build_view(
        title=TITLE,
        summary=SUMMARY,
        description=DESCRIPTION,
        search_id=search_id,
        query_id=query_id,
        widgets=widgets,
        positions=positions,
        titles=titles,
        widget_mapping=widget_mapping,
    )
    view_resp = gl.api("POST", "views", view)
    view_id = view_resp["id"]
    print(f"view id:   {view_id}")
    print(f"open:      {gl.os.environ['GRAYLOG_URL'].rsplit('/api', 1)[0]}/dashboards/{view_id}")


if __name__ == "__main__":
    build()
