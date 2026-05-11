"""Palo Alto Networks dashboard.

Five pages tuned for the homelab's PA topology:
  - PA-3020 (9.1.13), HA PA-220 pair (10.1.0), PA-440 (11.0.0), PRA (11.1.0)
  - Almost all data is event_log_name=TRAFFIC with vendor_event_action=allow
    (single 'L2' rule, single 'lan' zone) — flat-router-style setup. So this
    leans heavily on app/destination visibility rather than blocked-traffic
    forensics that wouldn't have anything to show.

Replaces the user's previous sparse 'Palo Alto Networks' dashboard.

Pages:
  1. Traffic           — what's flowing right now, top apps, bytes, geo
  2. Sessions          — session lifecycle, incomplete count, durations, ports
  3. Security          — actions / rules / URL categories / any non-allow
  4. System & Panorama — SYSTEM events, per-device heartbeat, Panorama msgs
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))
import graylog as gl  # noqa: E402

# Both PANOS streams — widgets pull from both via the search-type stream list.
PANOS_9_STREAM = "697e6ba3eeb15b769f425397"
PANOS_11_STREAM = "697e6ac9eeb15b769f424e8c"
STREAM_ID = PANOS_9_STREAM  # used as the "primary" by build_widgets_for_page

TITLE = "Palo Alto Networks"
SUMMARY = "NGFW — traffic, sessions, security, Panorama"
DESCRIPTION = (
    "Multi-page view of the PA-OS firewall fleet. Driven by the Graylog "
    "PA-OS plugins (PANOS 9+ and PANOS 11+ inputs). Field names come "
    "directly from the plugin: application_name, vendor_event_action, "
    "pan_log_subtype, source_zone, destination_zone, rule_name, "
    "http_uri_category, event_observer_hostname, network_bytes, "
    "destination_geo_country, etc."
)

HOUR = 3600
DAY = 86400
WEEK = 7 * DAY


def _ps(fn: str) -> dict:
    return gl.parse_series_fn(fn)


def numeric(title, query, fn, *, timerange=HOUR, pos, name="value"):
    return {
        "title": title, "kind": "agg", "viz": "numeric",
        "query": query, "timerange": timerange,
        "series": [{"config": {"name": name}, "function": fn}],
        "pivot_series": [_ps(fn)],
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


def msgs(title, query, *, pos, timerange=DAY):
    return {"title": title, "kind": "messages", "query": query,
            "timerange": timerange, "pos": pos}


# ── pages ────────────────────────────────────────────────────────────────────

def page_traffic():
    return [
        # Row 1: headline numerics
        numeric("Sessions (1h)", "event_log_name:TRAFFIC", "count()",
                pos={"col": 1, "row": 1, "width": 3, "height": 2}, name="sessions"),
        numeric("Distinct apps (1h)", "event_log_name:TRAFFIC",
                "cardinality(application_name)",
                pos={"col": 4, "row": 1, "width": 3, "height": 2}, name="apps"),
        numeric("Incomplete (1h, count)", 'application_name:incomplete',
                "count()", pos={"col": 7, "row": 1, "width": 3, "height": 2}, name="count"),
        numeric("Total bytes (1h)", "event_log_name:TRAFFIC",
                "sum(network_bytes)",
                pos={"col": 10, "row": 1, "width": 3, "height": 2}, name="bytes"),
        # Row 2: session rate over time (column-pivoted by device)
        line_ts("Sessions over 24h, per firewall",
                "event_log_name:TRAFFIC",
                series=[("count", "count()")],
                column_field="event_observer_hostname",
                pos={"col": 1, "row": 3, "width": 12, "height": 4}),
        # Row 3: apps — count + bytes, side by side
        bar("Top apps (24h, sessions, excl. noise)",
            "event_log_name:TRAFFIC AND NOT application_name:incomplete "
            "AND NOT application_name:\"insufficient-data\" "
            "AND NOT application_name:\"unknown-udp\"",
            field="application_name",
            pos={"col": 1, "row": 7, "width": 6, "height": 4}),
        table("Top apps (24h, by bytes)",
              "event_log_name:TRAFFIC AND _exists_:network_bytes",
              row_field="application_name", row_limit=15,
              series=[
                  ("sessions", "count()"),
                  ("bytes",    "sum(network_bytes)"),
                  ("avg dur s", "avg(event_duration)"),
              ],
              pos={"col": 7, "row": 7, "width": 6, "height": 4}),
        # Row 4: destinations — enriched with the names you actually want to see.
        # destination_fqdn is populated by the Enrichment pipeline rule
        # 'ipam enrich destination_ip to destination_fqdn' (NIOS PTR lookup,
        # covers internal 10.10.0.0/24). destination_as_organization +
        # destination_geo_* are set by the PA-OS plugin for internet-bound IPs.
        table("Top destinations (24h, by IP, named)",
              "event_log_name:TRAFFIC",
              row_field="destination_ip", row_limit=20,
              series=[
                  ("destination_fqdn", "latest(destination_fqdn)"),
                  ("AS org",    "latest(destination_as_organization)"),
                  ("country",   "latest(destination_geo_country)"),
                  ("city",      "latest(destination_geo_city)"),
                  ("sessions",  "count()"),
                  ("bytes",     "sum(network_bytes)"),
              ],
              pos={"col": 1, "row": 11, "width": 12, "height": 5}),
        # Row 4b: group destinations by AS org — the "who runs the other end"
        # view that's far more readable than raw IPs for internet-bound traffic
        table("Top AS organizations (24h, internet-bound)",
              "_exists_:destination_as_organization",
              row_field="destination_as_organization", row_limit=15,
              series=[
                  ("sessions", "count()"),
                  ("uniq IPs", "cardinality(destination_ip)"),
                  ("country",  "latest(destination_geo_country)"),
                  ("bytes",    "sum(network_bytes)"),
              ],
              pos={"col": 1, "row": 16, "width": 6, "height": 5}),
        table("Top destination countries (24h)",
              "_exists_:destination_geo_country",
              row_field="destination_geo_country", row_limit=15,
              series=[
                  ("sessions", "count()"),
                  ("AS orgs",  "cardinality(destination_as_organization)"),
                  ("bytes",    "sum(network_bytes)"),
              ],
              pos={"col": 7, "row": 16, "width": 6, "height": 5}),
        # Row 5: app pie + transport pie
        pie("Apps share (24h)",
            "event_log_name:TRAFFIC AND NOT application_name:incomplete",
            field="application_name",
            pos={"col": 1, "row": 21, "width": 6, "height": 4}),
        pie("Transport (24h)",
            "event_log_name:TRAFFIC",
            field="network_transport",
            pos={"col": 7, "row": 21, "width": 6, "height": 4}),
    ]


def page_sessions():
    return [
        numeric("Starts (1h)", 'pan_log_subtype:start', "count()",
                pos={"col": 1, "row": 1, "width": 3, "height": 2}, name="starts"),
        numeric("Ends (1h)", 'pan_log_subtype:end', "count()",
                pos={"col": 4, "row": 1, "width": 3, "height": 2}, name="ends"),
        # Raw count. Graylog pivots can't compute cross-series percentages —
        # eyeball this against Starts to gauge the share.
        numeric("Incomplete (1h, count)", 'application_name:incomplete', "count()",
                pos={"col": 7, "row": 1, "width": 3, "height": 2}, name="count"),
        numeric("Avg session sec (1h)",
                "event_log_name:TRAFFIC AND _exists_:event_duration",
                "avg(event_duration)",
                pos={"col": 10, "row": 1, "width": 3, "height": 2}, name="sec"),
        # Row 2: start vs end ratio over time
        line_ts("Start vs End sessions over 24h",
                "event_log_name:TRAFFIC",
                series=[("count", "count()")],
                column_field="pan_log_subtype",
                pos={"col": 1, "row": 3, "width": 12, "height": 4}),
        # Row 3: longest-running sessions and session-end reasons
        table("Top destination ports (24h)",
              "event_log_name:TRAFFIC AND _exists_:destination_port",
              row_field="destination_port", row_limit=20,
              series=[
                  ("sessions", "count()"),
                  ("apps",     "cardinality(application_name)"),
              ],
              pos={"col": 1, "row": 7, "width": 6, "height": 5}),
        bar("Session-end reasons (24h)",
            "_exists_:pan_session_end_reason",
            field="pan_session_end_reason",
            pos={"col": 7, "row": 7, "width": 6, "height": 5}),
        # Row 4: top sources — IP-keyed but display the enriched names
        # alongside (client_fqdn comes from your IPAM pipeline's PTR lookup,
        # client_display is PA-OS's own "hostname (IP)" enrichment).
        table("Top source IPs (24h, named)",
              "event_log_name:TRAFFIC",
              row_field="source_ip", row_limit=20,
              series=[
                  ("client_fqdn (PTR)", "latest(client_fqdn)"),
                  ("client_display",    "latest(client_display)"),
                  ("sessions",          "count()"),
                  ("apps",              "cardinality(application_name)"),
                  ("bytes_out",         "sum(source_bytes_sent)"),
              ],
              pos={"col": 1, "row": 12, "width": 12, "height": 5}),
        # Row 5: same data pivoted by client_display — easier for humans to
        # find a specific host, complements the IP-keyed view above.
        table("Top sources (24h, by client_display)",
              'event_log_name:TRAFFIC AND _exists_:client_display',
              row_field="client_display", row_limit=20,
              series=[
                  ("sessions", "count()"),
                  ("apps",     "cardinality(application_name)"),
                  ("bytes_out", "sum(source_bytes_sent)"),
                  ("uniq dests", "cardinality(destination_ip)"),
              ],
              pos={"col": 1, "row": 17, "width": 12, "height": 5}),
    ]


def page_security():
    return [
        # Row 1: action header
        numeric("Allow (1h)", 'vendor_event_action:allow', "count()",
                pos={"col": 1, "row": 1, "width": 3, "height": 2}, name="allow"),
        numeric("Deny (1h)", 'vendor_event_action:deny OR vendor_event_action:drop',
                "count()", pos={"col": 4, "row": 1, "width": 3, "height": 2}, name="deny"),
        numeric("THREAT events (24h)", "event_log_name:THREAT", "count()",
                timerange=DAY, pos={"col": 7, "row": 1, "width": 3, "height": 2}, name="threats"),
        numeric("URL events (24h)", "event_log_name:URL", "count()",
                timerange=DAY, pos={"col": 10, "row": 1, "width": 3, "height": 2}, name="url"),
        # Row 2: actions / rules
        bar("vendor_event_action distribution (24h)",
            "event_log_name:TRAFFIC",
            field="vendor_event_action",
            pos={"col": 1, "row": 3, "width": 6, "height": 4}),
        bar("Top rule hits (24h)",
            "event_log_name:TRAFFIC",
            field="rule_name",
            pos={"col": 7, "row": 3, "width": 6, "height": 4}),
        # Row 3: URL categories
        bar("URL categories (24h)",
            "_exists_:http_uri_category AND NOT http_uri_category:any",
            field="http_uri_category",
            pos={"col": 1, "row": 7, "width": 6, "height": 4}),
        bar("Source / destination zone pairs (24h)",
            "event_log_name:TRAFFIC",
            field="source_zone",
            pos={"col": 7, "row": 7, "width": 6, "height": 4}),
        # Row 4: non-allow events (would surface anything blocked if it existed)
        msgs("Non-allow events (24h)",
             'event_log_name:TRAFFIC AND NOT vendor_event_action:allow',
             timerange=DAY, pos={"col": 1, "row": 11, "width": 12, "height": 6}),
    ]


def page_system():
    return [
        # Row 1: counters
        numeric("SYSTEM events (24h)", "event_log_name:SYSTEM", "count()",
                timerange=DAY, pos={"col": 1, "row": 1, "width": 3, "height": 2}, name="sys"),
        numeric("CONFIG events (24h)", "event_log_name:CONFIG", "count()",
                timerange=DAY, pos={"col": 4, "row": 1, "width": 3, "height": 2}, name="cfg"),
        numeric("Distinct firewalls (24h)", "*",
                "cardinality(event_observer_hostname)",
                timerange=DAY, pos={"col": 7, "row": 1, "width": 3, "height": 2}, name="fw"),
        numeric("Panorama-source msgs (24h)",
                "source:panorama.darknetian.com",
                "count()", timerange=DAY,
                pos={"col": 10, "row": 1, "width": 3, "height": 2}, name="msgs"),
        # Row 2: per-firewall heartbeat
        line_ts("Per-firewall message rate (24h)",
                "*",
                series=[("count", "count()")],
                column_field="event_observer_hostname",
                pos={"col": 1, "row": 3, "width": 12, "height": 4}),
        # Row 3: distinct devices
        table("Firewall inventory (last seen, 24h)",
              "*",
              row_field="event_observer_hostname", row_limit=20,
              series=[
                  ("messages",  "count()"),
                  ("source",    "latest(source)"),
                  ("device_id", "latest(event_observer_id)"),
                  ("vsys",      "latest(host_virtfw_hostname)"),
              ],
              pos={"col": 1, "row": 7, "width": 12, "height": 4}),
        # Row 4: recent system events
        msgs("Recent SYSTEM events (24h)",
             "event_log_name:SYSTEM",
             timerange=DAY, pos={"col": 1, "row": 11, "width": 12, "height": 6}),
        # Row 5: recent Panorama-source messages
        msgs("Recent Panorama-source messages (24h)",
             "source:panorama.darknetian.com",
             timerange=DAY, pos={"col": 1, "row": 17, "width": 12, "height": 6}),
    ]


# ── build / apply ────────────────────────────────────────────────────────────

# Override the lib's stream filtering to query BOTH PANOS streams in one shot.
def build_pages_for_panos(specs, default_timerange_s):
    """Like gl.build_widgets_for_page but with multi-stream search_types so
    each widget covers both PANOS 9+ and PANOS 11+."""
    search_types: list[dict] = []
    widgets: list[dict] = []
    positions: dict[str, dict] = {}
    titles: dict[str, str] = {}
    widget_mapping: dict[str, list[str]] = {}
    for s in specs:
        wid, stid = gl.gen_id(), gl.gen_id()
        timerange = s.get("timerange", default_timerange_s)
        query = s.get("query", "")
        if s["kind"] == "agg":
            ps = gl.align_pivot_ids(s.get("series", []), s.get("pivot_series", []))
            search_type = gl.pivot(
                search_type_id=stid, stream_id=PANOS_9_STREAM,
                query=query, timerange_s=timerange,
                row_field=s.get("row_field"),
                column_field=s.get("column_field"),
                series=ps,
                row_limit=s.get("row_limit", 25),
                column_limit=s.get("column_limit", 25),
            )
            search_type["streams"] = [PANOS_9_STREAM, PANOS_11_STREAM]
            search_types.append(search_type)

            widget = gl.widget_aggregation(
                widget_id=wid, stream_id=PANOS_9_STREAM,
                query=query, timerange_s=timerange,
                row_field=s.get("row_field"),
                column_field=s.get("column_field"),
                series=s.get("series"),
                visualization=s["viz"],
                row_limit=s.get("row_limit", 25),
                column_limit=s.get("column_limit", 25),
            )
            widget["streams"] = [PANOS_9_STREAM, PANOS_11_STREAM]
            widgets.append(widget)
        elif s["kind"] == "messages":
            mst = gl.messages_searchtype(
                search_type_id=stid, stream_id=PANOS_9_STREAM,
                query=query, timerange_s=timerange,
            )
            mst["streams"] = [PANOS_9_STREAM, PANOS_11_STREAM]
            search_types.append(mst)
            mw = gl.widget_messages(
                widget_id=wid, stream_id=PANOS_9_STREAM,
                query=query, timerange_s=timerange,
            )
            mw["streams"] = [PANOS_9_STREAM, PANOS_11_STREAM]
            widgets.append(mw)
        else:
            raise ValueError(f"unknown widget kind: {s['kind']}")
        positions[wid] = s["pos"]
        titles[wid] = s["title"]
        widget_mapping[wid] = [stid]
    return search_types, widgets, positions, titles, widget_mapping


def build():
    page_defs = [
        ("Traffic",            page_traffic,  DAY),
        ("Sessions",           page_sessions, DAY),
        ("Security",           page_security, DAY),
        ("System & Panorama",  page_system,   DAY),
    ]

    pages_for_search, pages_for_view = [], []
    for title, fn, default_tr in page_defs:
        qid = gl.gen_id()
        sts, ws, pos, ti, wm = build_pages_for_panos(fn(), default_tr)
        pages_for_search.append({
            "query_id": qid, "search_types": sts, "timerange_s": default_tr,
        })
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
