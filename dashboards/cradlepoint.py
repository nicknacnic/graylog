"""Cradlepoint E300 dashboard — multi-page.

Pages:
  - Overview: original single-page widgets (signal trends, clients,
    cell-id, RFBAND, WAN DHCP, recent events)
  - WAN Perf: speedtest + canary pings + DNS timing + external IP,
    fed by pollers/wan_perf_poller.py every 30 min

Run after sourcing env.sh:
    source env.sh && python3 dashboards/cradlepoint.py

Builds the search + view payloads and POSTs them to Graylog. Prints the
created view id so you can confirm in the UI.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))
import graylog as gl  # noqa: E402

STREAM_ID = "697ef3beeeb15b769f441ed4"
TITLE = "Cradlepoint E300"
SUMMARY = "LTE router health, cellular signal, connected clients, WAN state + WAN perf"
DESCRIPTION = (
    "Built from the Cradlepoint syslog feed (UDP :515) plus the "
    "wan-perf-poller (Ookla speedtest + canary pings + DNS timing + "
    "external-IP probe, every 30 min, emitted with source=e300.darknetian.com "
    "so it lands in the same stream). Cradlepoint pipeline rules extract "
    "the cp_* signal/cell/wan fields; the poller adds cp_speedtest_*, "
    "cp_canary_*, cp_dns_*, cp_wan_external_ip."
)

DAY = 86400
WEEK = 7 * DAY
MONTH = 30 * DAY


# ── overview page (original single-page widgets) ──────────────────────────
def page_overview() -> list[dict]:
    return [
        # Row 1: numerics
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


# ── WAN perf page (speedtest + external IP) ───────────────────────────────
def page_wan_perf() -> list[dict]:
    return [
        # Row 1 — latest speedtest results (banner numerics)
        {
            "title": "Down Mbps (latest)",
            "kind": "agg", "viz": "numeric",
            "query": "cp_event_type:speedtest", "timerange": WEEK,
            "series": [{"config": {"name": "down"}, "function": "latest(cp_speedtest_down_mbps)"}],
            "pivot_series": [{"type": "latest", "id": "latest(cp_speedtest_down_mbps)", "field": "cp_speedtest_down_mbps"}],
            "pos": {"col": 1, "row": 1, "width": 3, "height": 2},
        },
        {
            "title": "Up Mbps (latest)",
            "kind": "agg", "viz": "numeric",
            "query": "cp_event_type:speedtest", "timerange": WEEK,
            "series": [{"config": {"name": "up"}, "function": "latest(cp_speedtest_up_mbps)"}],
            "pivot_series": [{"type": "latest", "id": "latest(cp_speedtest_up_mbps)", "field": "cp_speedtest_up_mbps"}],
            "pos": {"col": 4, "row": 1, "width": 3, "height": 2},
        },
        {
            "title": "Latency ms (latest)",
            "kind": "agg", "viz": "numeric",
            "query": "cp_event_type:speedtest", "timerange": WEEK,
            "series": [{"config": {"name": "ms"}, "function": "latest(cp_speedtest_latency_ms)"}],
            "pivot_series": [{"type": "latest", "id": "latest(cp_speedtest_latency_ms)", "field": "cp_speedtest_latency_ms"}],
            "pos": {"col": 7, "row": 1, "width": 3, "height": 2},
        },
        {
            "title": "Jitter ms (latest)",
            "kind": "agg", "viz": "numeric",
            "query": "cp_event_type:speedtest", "timerange": WEEK,
            "series": [{"config": {"name": "ms"}, "function": "latest(cp_speedtest_jitter_ms)"}],
            "pivot_series": [{"type": "latest", "id": "latest(cp_speedtest_jitter_ms)", "field": "cp_speedtest_jitter_ms"}],
            "pos": {"col": 10, "row": 1, "width": 3, "height": 2},
        },

        # Row 2 — recent speedtest runs (most-recent at top)
        {
            "title": "Recent speedtests (24h, newest first)",
            "kind": "messages",
            "query": "cp_event_type:speedtest",
            "timerange": DAY,
            "pos": {"col": 1, "row": 3, "width": 12, "height": 5},
        },

        # Row 3 — 30d bandwidth trendlines
        {
            "title": "Down Mbps over 30d",
            "kind": "agg", "viz": "line",
            "query": "cp_event_type:speedtest", "timerange": MONTH,
            "row_field": "timestamp",
            "series": [{"config": {"name": "down Mbps"}, "function": "avg(cp_speedtest_down_mbps)"}],
            "pivot_series": [{"type": "avg", "id": "avg(cp_speedtest_down_mbps)", "field": "cp_speedtest_down_mbps"}],
            "pos": {"col": 1, "row": 8, "width": 6, "height": 4},
        },
        {
            "title": "Up Mbps over 30d",
            "kind": "agg", "viz": "line",
            "query": "cp_event_type:speedtest", "timerange": MONTH,
            "row_field": "timestamp",
            "series": [{"config": {"name": "up Mbps"}, "function": "avg(cp_speedtest_up_mbps)"}],
            "pivot_series": [{"type": "avg", "id": "avg(cp_speedtest_up_mbps)", "field": "cp_speedtest_up_mbps"}],
            "pos": {"col": 7, "row": 8, "width": 6, "height": 4},
        },

        # Row 4 — latency / jitter / loss over 30d
        {
            "title": "Latency + jitter ms over 30d",
            "kind": "agg", "viz": "line",
            "query": "cp_event_type:speedtest", "timerange": MONTH,
            "row_field": "timestamp",
            "series": [
                {"config": {"name": "latency ms"}, "function": "avg(cp_speedtest_latency_ms)"},
                {"config": {"name": "jitter ms"}, "function": "avg(cp_speedtest_jitter_ms)"},
            ],
            "pivot_series": [
                {"type": "avg", "id": "avg(cp_speedtest_latency_ms)", "field": "cp_speedtest_latency_ms"},
                {"type": "avg", "id": "avg(cp_speedtest_jitter_ms)", "field": "cp_speedtest_jitter_ms"},
            ],
            "pos": {"col": 1, "row": 12, "width": 6, "height": 4},
        },
        {
            "title": "Speedtest packet loss % over 30d",
            "kind": "agg", "viz": "line",
            "query": "cp_event_type:speedtest", "timerange": MONTH,
            "row_field": "timestamp",
            "series": [{"config": {"name": "loss %"}, "function": "avg(cp_speedtest_loss_pct)"}],
            "pivot_series": [{"type": "avg", "id": "avg(cp_speedtest_loss_pct)", "field": "cp_speedtest_loss_pct"}],
            "pos": {"col": 7, "row": 12, "width": 6, "height": 4},
        },

        # Row 5 — external IP
        {
            "title": "WAN external IP (latest)",
            "kind": "agg", "viz": "numeric",
            "query": "cp_event_type:wan_ip", "timerange": DAY,
            "series": [{"config": {"name": "ip"}, "function": "latest(cp_wan_external_ip)"}],
            "pivot_series": [{"type": "latest", "id": "latest(cp_wan_external_ip)", "field": "cp_wan_external_ip"}],
            "pos": {"col": 1, "row": 16, "width": 4, "height": 2},
        },
        {
            "title": "WAN external IP changes (30d)",
            "kind": "agg", "viz": "numeric",
            "query": "cp_event_type:wan_ip", "timerange": MONTH,
            "series": [{"config": {"name": "ips"}, "function": "cardinality(cp_wan_external_ip)"}],
            "pivot_series": [{"type": "card", "id": "cardinality(cp_wan_external_ip)", "field": "cp_wan_external_ip"}],
            "pos": {"col": 5, "row": 16, "width": 4, "height": 2},
        },
        {
            "title": "Distinct external IPs seen (30d)",
            "kind": "agg", "viz": "table",
            "query": "cp_event_type:wan_ip", "timerange": MONTH,
            "row_field": "cp_wan_external_ip", "row_limit": 25,
            "series": [
                {"config": {"name": "last seen"}, "function": "latest(timestamp)"},
                {"config": {"name": "samples"}, "function": "count()"},
            ],
            "pivot_series": [
                {"type": "latest", "id": "latest(timestamp)", "field": "timestamp"},
                {"type": "count", "id": "count()"},
            ],
            "pos": {"col": 1, "row": 18, "width": 12, "height": 4},
        },
    ]


# ── Canary page (ICMP pings + DNS resolver timing) ────────────────────────
def page_canary() -> list[dict]:
    return [
        # Row 1 — canary ping summary table
        {
            "title": "Canary ping summary (7d)",
            "kind": "agg", "viz": "table",
            "query": "cp_event_type:ping_canary", "timerange": WEEK,
            "row_field": "cp_canary_target", "row_limit": 10,
            "series": [
                {"config": {"name": "avg RTT ms"}, "function": "avg(cp_canary_rtt_avg_ms)"},
                {"config": {"name": "max RTT ms"}, "function": "max(cp_canary_rtt_max_ms)"},
                {"config": {"name": "avg jitter (mdev) ms"}, "function": "avg(cp_canary_rtt_mdev_ms)"},
                {"config": {"name": "avg loss %"}, "function": "avg(cp_canary_loss_pct)"},
                {"config": {"name": "samples"}, "function": "count()"},
            ],
            "pivot_series": [
                {"type": "avg", "id": "avg(cp_canary_rtt_avg_ms)", "field": "cp_canary_rtt_avg_ms"},
                {"type": "max", "id": "max(cp_canary_rtt_max_ms)", "field": "cp_canary_rtt_max_ms"},
                {"type": "avg", "id": "avg(cp_canary_rtt_mdev_ms)", "field": "cp_canary_rtt_mdev_ms"},
                {"type": "avg", "id": "avg(cp_canary_loss_pct)", "field": "cp_canary_loss_pct"},
                {"type": "count", "id": "count()"},
            ],
            "pos": {"col": 1, "row": 1, "width": 12, "height": 4},
        },

        # Row 2 — RTT + loss over 7d, per target
        {
            "title": "Canary RTT ms over 7d, per target",
            "kind": "agg", "viz": "line",
            "query": "cp_event_type:ping_canary", "timerange": WEEK,
            "row_field": "timestamp",
            "column_field": "cp_canary_target",
            "series": [{"config": {"name": "avg RTT"}, "function": "avg(cp_canary_rtt_avg_ms)"}],
            "pivot_series": [{"type": "avg", "id": "avg(cp_canary_rtt_avg_ms)", "field": "cp_canary_rtt_avg_ms"}],
            "column_limit": 10,
            "pos": {"col": 1, "row": 5, "width": 6, "height": 4},
        },
        {
            "title": "Canary packet loss % over 7d, per target",
            "kind": "agg", "viz": "line",
            "query": "cp_event_type:ping_canary", "timerange": WEEK,
            "row_field": "timestamp",
            "column_field": "cp_canary_target",
            "series": [{"config": {"name": "loss %"}, "function": "avg(cp_canary_loss_pct)"}],
            "pivot_series": [{"type": "avg", "id": "avg(cp_canary_loss_pct)", "field": "cp_canary_loss_pct"}],
            "column_limit": 10,
            "pos": {"col": 7, "row": 5, "width": 6, "height": 4},
        },

        # Row 3 — DNS resolver timing
        {
            "title": "DNS resolver timing summary (7d)",
            "kind": "agg", "viz": "table",
            "query": "cp_event_type:dns_timing", "timerange": WEEK,
            "row_field": "cp_dns_resolver", "row_limit": 10,
            "series": [
                {"config": {"name": "avg ms"}, "function": "avg(cp_dns_query_ms)"},
                {"config": {"name": "max ms"}, "function": "max(cp_dns_query_ms)"},
                {"config": {"name": "samples"}, "function": "count()"},
            ],
            "pivot_series": [
                {"type": "avg", "id": "avg(cp_dns_query_ms)", "field": "cp_dns_query_ms"},
                {"type": "max", "id": "max(cp_dns_query_ms)", "field": "cp_dns_query_ms"},
                {"type": "count", "id": "count()"},
            ],
            "pos": {"col": 1, "row": 9, "width": 6, "height": 4},
        },
        {
            "title": "DNS resolver latency over 7d, per resolver",
            "kind": "agg", "viz": "line",
            "query": "cp_event_type:dns_timing", "timerange": WEEK,
            "row_field": "timestamp",
            "column_field": "cp_dns_resolver",
            "series": [{"config": {"name": "avg ms"}, "function": "avg(cp_dns_query_ms)"}],
            "pivot_series": [{"type": "avg", "id": "avg(cp_dns_query_ms)", "field": "cp_dns_query_ms"}],
            "column_limit": 10,
            "pos": {"col": 7, "row": 9, "width": 6, "height": 4},
        },

        # Row 4 — recent canary + DNS events (newest first)
        {
            "title": "Recent canary + DNS events (24h)",
            "kind": "messages",
            "query": "cp_event_type:(ping_canary OR dns_timing)",
            "timerange": DAY,
            "pos": {"col": 1, "row": 13, "width": 12, "height": 6},
        },
    ]


def build():
    page_defs = [
        ("Overview", page_overview, DAY),
        ("WAN Perf", page_wan_perf,  WEEK),
        ("Canary",   page_canary,    WEEK),
    ]
    pages_for_search: list[dict] = []
    pages_for_view: list[dict] = []
    for title, fn, default_timerange in page_defs:
        qid = gl.gen_id()
        search_types, widgets, positions, titles, widget_mapping = gl.build_widgets_for_page(
            STREAM_ID, fn(), default_timerange,
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
