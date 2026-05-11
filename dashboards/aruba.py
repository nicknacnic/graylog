"""Aruba AP225 dashboard.

Single page for now — homelab has one AP and message volume is bursty/low.
Once we observe more patterns we can split into multiple pages.

Fields populated by pipelines/aruba.json:
  aruba_event_type    client_assoc | station_update | station_online | drt_version
  aruba_severity      INFO | WARN | NOTI | ERR
  aruba_process       cli | stm
  aruba_ap_name, aruba_ap_ip, aruba_ap_mac
  aruba_client_mac, aruba_bssid, aruba_essid    (when message references them)
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))
import graylog as gl  # noqa: E402

STREAM_ID = "6a020a676bb644169285d513"  # Aruba AP stream
TITLE = "Aruba — AP225"
SUMMARY = "Single AP (40:E3:D6:C6:F3:2A) at 10.10.0.172, IAP mode"
DESCRIPTION = (
    "Native syslog from the Aruba AP225 in Instant mode. Fields prefixed "
    "aruba_* are extracted by the Aruba pipeline. The AP is silent until "
    "client activity happens — expect bursts during associations, roams, "
    "and reauths, otherwise empty widgets are normal."
)

HOUR = 3600
DAY = 86400
WEEK = 7 * DAY


def _pivot_series_for(fn: str) -> dict:
    return gl.parse_series_fn(fn)


def numeric(title, query, fn, *, timerange=HOUR, pos, name="value"):
    return {
        "title": title, "kind": "agg", "viz": "numeric",
        "query": query, "timerange": timerange,
        "series": [{"config": {"name": name}, "function": fn}],
        "pivot_series": [_pivot_series_for(fn)],
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
        "pivot_series": [_pivot_series_for(fn) for _, fn in series],
        "pos": pos,
    }


def line_ts(title, query, series, *, timerange=DAY, pos, column_field=None):
    return {
        "title": title, "kind": "agg", "viz": "line",
        "query": query, "timerange": timerange,
        "row_field": "timestamp", "column_field": column_field,
        "series": [{"config": {"name": n}, "function": fn} for n, fn in series],
        "pivot_series": [_pivot_series_for(fn) for _, fn in series],
        "pos": pos,
    }


def msgs(title, query, *, pos, timerange=DAY):
    return {"title": title, "kind": "messages", "query": query,
            "timerange": timerange, "pos": pos}


def page_main():
    return [
        # Row 1: headline numerics
        numeric("Msgs (24h)",       "*", "count()", timerange=DAY,
                pos={"col": 1, "row": 1, "width": 3, "height": 2}),
        numeric("Client assocs (24h)", "aruba_event_type:client_assoc", "count()",
                timerange=DAY, pos={"col": 4, "row": 1, "width": 3, "height": 2}, name="assocs"),
        numeric("Unique clients (24h)", "_exists_:aruba_client_mac", "cardinality(aruba_client_mac)",
                timerange=DAY, pos={"col": 7, "row": 1, "width": 3, "height": 2}, name="clients"),
        numeric("Warnings+ (24h)",  "aruba_severity:WARN OR aruba_severity:ERR OR aruba_severity:CRIT",
                "count()", timerange=DAY,
                pos={"col": 10, "row": 1, "width": 3, "height": 2}, name="warn"),
        # Row 2: distribution donuts
        pie("Event type (24h)", "_exists_:aruba_event_type",
            field="aruba_event_type", pos={"col": 1, "row": 3, "width": 4, "height": 4}),
        pie("Severity (24h)", "_exists_:aruba_severity",
            field="aruba_severity", pos={"col": 5, "row": 3, "width": 4, "height": 4}),
        pie("ESSID (24h)", "_exists_:aruba_essid",
            field="aruba_essid", pos={"col": 9, "row": 3, "width": 4, "height": 4}),
        # Row 3: volume trend
        line_ts("Messages per event type (24h)",
                "_exists_:aruba_event_type",
                series=[("count", "count()")],
                column_field="aruba_event_type",
                pos={"col": 1, "row": 7, "width": 12, "height": 4}),
        # Row 4: top clients — DHCP hostname (from infoblox-nios-mac lookup)
        # is the most-readable identifier; PTR (client_fqdn) fills in for
        # clients NIOS doesn't know about by MAC but does know by IP.
        table("Top wifi clients (24h, by MAC)",
              "_exists_:aruba_client_mac",
              row_field="aruba_client_mac", row_limit=20,
              series=[
                  ("hostname (DHCP)", "latest(client_hostname)"),
                  ("client_fqdn (PTR)", "latest(client_fqdn)"),
                  ("essid",    "latest(aruba_essid)"),
                  ("events",   "count()"),
              ],
              timerange=DAY,
              pos={"col": 1, "row": 11, "width": 12, "height": 5}),
        # Row 5: recent associations (the operationally-interesting cut)
        msgs("Recent association events (24h)",
             "aruba_event_type:client_assoc",
             timerange=DAY, pos={"col": 1, "row": 16, "width": 12, "height": 6}),
        # Row 6: everything else (excluding DRT noise)
        msgs("Recent events (24h, excl. DRT noise)",
             "NOT aruba_event_type:drt_version",
             timerange=DAY, pos={"col": 1, "row": 22, "width": 12, "height": 6}),
    ]




def build():
    qid = gl.gen_id()
    sts, ws, pos, ti, wm = gl.build_widgets_for_page(STREAM_ID, page_main(), DAY)

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
