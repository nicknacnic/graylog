"""VMware (ESXi + vCenter) dashboard.

Four pages:
  1. Operational     — what's broken, error rate, top error apps
  2. ESXi hosts      — per-host activity, Hostd auth events, vmkernel
  3. vCenter         — vpxd-main, wcpsvc, vsan-health, eam-api
  4. Inventory       — sources seen, app distribution

Built against the dedicated 'VMware' index set (esxi/vcenter syslog,
firehose volume — ~2.2M msgs/day).
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))
import graylog as gl  # noqa: E402

STREAM_ID = "697e9e92eeb15b769f43098c"  # ESXi stream (now writes to vmware_*)
TITLE = "VMware — vCenter & ESXi"
SUMMARY = "vSphere syslog: hosts esxi1/esxi2 and vcenter.darknetian.com"
DESCRIPTION = (
    "Multi-page view of the VMware/vSphere syslog feed. Hosts: esxi1, "
    "esxi2 (ProLiant DL380p Gen8). vCenter: vcenter.darknetian.com. "
    "All routed through the existing UDP :514 syslog input and indexed in "
    "the dedicated 'vmware_*' index set."
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


def line_ts(title, query, series, *, timerange=DAY, pos, column_field=None):
    return {
        "title": title, "kind": "agg", "viz": "line",
        "query": query, "timerange": timerange,
        "row_field": "timestamp",
        "column_field": column_field,
        "series": [{"config": {"name": n}, "function": fn} for n, fn in series],
        "pivot_series": [_pivot_series_for(fn) for _, fn in series],
        "pos": pos,
    }


def bar(title, query, *, field, pos, timerange=HOUR, row_limit=15, column_field=None):
    return {
        "title": title, "kind": "agg", "viz": "bar",
        "query": query, "timerange": timerange,
        "row_field": field, "row_limit": row_limit,
        "column_field": column_field,
        "pos": pos,
    }


def pie(title, query, *, field, pos, timerange=DAY, row_limit=10):
    return {
        "title": title, "kind": "agg", "viz": "pie",
        "query": query, "timerange": timerange,
        "row_field": field, "row_limit": row_limit, "pos": pos,
    }


def table(title, query, *, row_field, series, pos, timerange=HOUR, row_limit=25):
    return {
        "title": title, "kind": "agg", "viz": "table",
        "query": query, "timerange": timerange,
        "row_field": row_field, "row_limit": row_limit,
        "series": [{"config": {"name": n}, "function": fn} for n, fn in series],
        "pivot_series": [_pivot_series_for(fn) for _, fn in series],
        "pos": pos,
    }


def msgs(title, query, *, pos, timerange=HOUR):
    return {"title": title, "kind": "messages", "query": query,
            "timerange": timerange, "pos": pos}


# ── pages ────────────────────────────────────────────────────────────────────

def page_operational():
    return [
        # Row 1: headline numerics
        numeric("Msgs (1h)",            "*", "count()", pos={"col": 1,  "row": 1, "width": 3, "height": 2}),
        numeric("Errors / fatals (24h)", "level:[0 TO 3]", "count()", timerange=DAY,
                pos={"col": 4,  "row": 1, "width": 3, "height": 2}, name="err"),
        numeric("Distinct sources (24h)", "*", "cardinality(source)", timerange=DAY,
                pos={"col": 7,  "row": 1, "width": 3, "height": 2}, name="sources"),
        numeric("Distinct apps (24h)",  "*", "cardinality(vmware_app)", timerange=DAY,
                pos={"col": 10, "row": 1, "width": 3, "height": 2}, name="apps"),
        # Row 2: volume per source
        line_ts("Messages per source (24h)", "*",
                series=[("count", "count()")],
                column_field="source",
                pos={"col": 1, "row": 3, "width": 12, "height": 4}),
        # Row 3: errors detail
        bar("Top apps by error count (1h, level≤3)", "level:[0 TO 3]",
            field="vmware_app", pos={"col": 1, "row": 7, "width": 6, "height": 4}),
        bar("Top sources by error count (1h, level≤3)", "level:[0 TO 3]",
            field="source", pos={"col": 7, "row": 7, "width": 6, "height": 4}),
        # Row 4: recent errors
        msgs("Recent errors+ (24h, level≤3)", "level:[0 TO 3]",
             timerange=DAY, pos={"col": 1, "row": 11, "width": 12, "height": 6}),
    ]


def page_hosts():
    return [
        # Row 1: per-host heartbeat + per-daemon activity (uses vmware_app)
        numeric("esxi1 msgs (5min)",     "source:esxi1.darknetian.com", "count()", timerange=300,
                pos={"col": 1, "row": 1, "width": 3, "height": 2}, name="msgs"),
        numeric("esxi2 msgs (5min)",     "source:esxi2.darknetian.com", "count()", timerange=300,
                pos={"col": 4, "row": 1, "width": 3, "height": 2}, name="msgs"),
        numeric("Hostd events (1h)",     "vmware_app:Hostd",  "count()",
                pos={"col": 7, "row": 1, "width": 3, "height": 2}, name="Hostd"),
        numeric("Vpxa events (1h)",      "vmware_app:Vpxa",   "count()",
                pos={"col": 10, "row": 1, "width": 3, "height": 2}, name="Vpxa"),
        # Row 2: per-host trend
        line_ts("Per-host msg rate (24h)",
                "source:esxi1.darknetian.com OR source:esxi2.darknetian.com",
                series=[("count", "count()")],
                column_field="source",
                pos={"col": 1, "row": 3, "width": 12, "height": 4}),
        # Row 3: per-daemon trend on the host-class apps
        line_ts("Per-daemon msg rate (24h, host syslog)",
                "source:esxi1.darknetian.com OR source:esxi2.darknetian.com",
                series=[("count", "count()")],
                column_field="vmware_app",
                pos={"col": 1, "row": 7, "width": 12, "height": 4}),
        # Row 4: ESXi user logins (extracted from Hostd "Event N : User" pattern)
        msgs("Hostd auth events (User logged in/out, 24h)",
             'vmware_app:Hostd AND (message:"logged in" OR message:"logged out")',
             timerange=DAY, pos={"col": 1, "row": 11, "width": 12, "height": 6}),
        # Row 5: SNMP / LLDP noise (the persistent low-impact errors)
        msgs("Host warnings (24h, level≤4, host sources)",
             "(source:esxi1.darknetian.com OR source:esxi2.darknetian.com) AND level:[0 TO 4]",
             timerange=DAY, pos={"col": 1, "row": 17, "width": 12, "height": 6}),
    ]


def page_vcenter():
    return [
        # Row 1: vCenter subsystem activity (now via vmware_app)
        numeric("vpxd-main (1h)",         "vmware_app:vpxd-main", "count()",
                pos={"col": 1,  "row": 1, "width": 3, "height": 2}),
        numeric("eam-api (1h)",           "vmware_app:eam-api", "count()",
                pos={"col": 4,  "row": 1, "width": 3, "height": 2}),
        numeric("wcpsvc (1h)",            "vmware_app:wcpsvc", "count()",
                pos={"col": 7,  "row": 1, "width": 3, "height": 2}),
        numeric("vsan-health-main (1h)",  "vmware_app:vsan-health-main", "count()",
                pos={"col": 10, "row": 1, "width": 3, "height": 2}),
        # Row 2: top vCenter apps over time
        line_ts("vCenter subsystems over 24h",
                "source:vcenter.darknetian.com",
                series=[("count", "count()")],
                column_field="vmware_app",
                pos={"col": 1, "row": 3, "width": 12, "height": 4}),
        # Row 3: messages
        msgs("vCenter errors+ (24h)",
             "source:vcenter.darknetian.com AND level:[0 TO 4]",
             timerange=DAY, pos={"col": 1, "row": 7, "width": 12, "height": 6}),
        # Row 4: vSAN-specific
        msgs("vSAN health (24h)",
             "vmware_app:vsan-health-main",
             timerange=DAY, pos={"col": 1, "row": 13, "width": 12, "height": 6}),
    ]


def page_inventory():
    return [
        # Row 1: header numbers
        numeric("Sources (24h)",   "*", "cardinality(source)", timerange=DAY,
                pos={"col": 1, "row": 1, "width": 3, "height": 2}, name="sources"),
        numeric("Apps (24h)",      "*", "cardinality(vmware_app)", timerange=DAY,
                pos={"col": 4, "row": 1, "width": 3, "height": 2}, name="apps"),
        numeric("Total msgs (24h)", "*", "count()", timerange=DAY,
                pos={"col": 7, "row": 1, "width": 3, "height": 2}, name="msgs"),
        numeric("Distinct facilities (24h)", "*", "cardinality(facility)", timerange=DAY,
                pos={"col": 10, "row": 1, "width": 3, "height": 2}, name="facilities"),
        # Row 2: source distribution
        pie("Messages by source (24h)", "*", field="source", timerange=DAY,
            pos={"col": 1, "row": 3, "width": 6, "height": 4}),
        pie("Messages by facility (24h)", "*", field="facility", timerange=DAY,
            pos={"col": 7, "row": 3, "width": 6, "height": 4}),
        # Row 3: top apps — now unified across ESXi-host syslog tags + vCenter app names
        table("Top 30 apps (24h, vmware_app)", "*",
              row_field="vmware_app", row_limit=30,
              series=[("count", "count()")],
              timerange=DAY,
              pos={"col": 1, "row": 7, "width": 12, "height": 6}),
        # Row 4: source listing
        table("All sources (24h)", "*",
              row_field="source", row_limit=20,
              series=[
                  ("messages", "count()"),
                  ("apps",     "cardinality(vmware_app)"),
                  ("max level", "max(level)"),
              ],
              timerange=DAY,
              pos={"col": 1, "row": 13, "width": 12, "height": 4}),
    ]


# ── build / apply ────────────────────────────────────────────────────────────



def build():
    page_defs = [
        ("Operational",      page_operational, DAY),
        ("ESXi hosts",       page_hosts,       DAY),
        ("vCenter",          page_vcenter,     DAY),
        ("Inventory",        page_inventory,   DAY),
    ]
    pages_for_search, pages_for_view = [], []
    for title, fn, default_tr in page_defs:
        qid = gl.gen_id()
        sts, ws, pos, ti, wm = gl.build_widgets_for_page(STREAM_ID, fn(), default_tr)
        pages_for_search.append({"query_id": qid, "search_types": sts, "timerange_s": default_tr})
        pages_for_view.append({
            "query_id": qid, "title": title,
            "widgets": ws, "positions": pos, "titles": ti, "widget_mapping": wm,
        })

    existing = gl.api("GET", "views?per_page=200") or {}
    for v in existing.get("views", []):
        if v.get("title") == TITLE and v.get("type") == "DASHBOARD":
            print(f"deleting prior dashboard id={v['id']}")
            gl.api("DELETE", f"views/{v['id']}")

    search = gl.build_search_multipage(pages_for_search)
    sresp = gl.api("POST", "views/search", search)
    print(f"search id: {sresp['id']}")

    view = gl.build_view_multipage(
        title=TITLE, summary=SUMMARY, description=DESCRIPTION,
        search_id=sresp["id"], pages=pages_for_view,
    )
    vresp = gl.api("POST", "views", view)
    print(f"view id:   {vresp['id']}")
    import os
    print(f"open:      {os.environ['GRAYLOG_URL'].rsplit('/api', 1)[0]}/dashboards/{vresp['id']}")


if __name__ == "__main__":
    build()
