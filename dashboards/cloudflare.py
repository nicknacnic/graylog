"""Cloudflare dashboard.

Three pages, modeled on dashboards/idrac.py and dashboards/palo_alto.py:
  1. Traffic        — requests/bytes per zone, status-code mix, top countries
  2. Threats        — firewall events: actions, rules, attacker IPs, paths
  3. DNS & Audit    — DNS query analytics + account-level config-change audit

Driven by GELF emissions from pollers/cloudflare_poller.py into the
"Cloudflare" stream (sources match cloudflare-*).

Run after sourcing env.sh + after indexing/cloudflare.py:
    python3 dashboards/cloudflare.py
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))
import graylog as gl  # noqa: E402

STREAM_TITLE = "Cloudflare"
TITLE = "Cloudflare"
SUMMARY = "Cloudflare zone traffic, firewall events, DNS analytics, and account audit logs"
DESCRIPTION = (
    "Polled every 5 min by cf-poller systemd timer. Fields are prefixed "
    "cf_*. Slice on cf_event_type (zone_info | requests_5m | requests_by_status "
    "| firewall_event | dns_summary | audit_log) and cf_zone_name. Coverage is "
    "aggregated 5-min buckets for traffic/DNS, per-event for firewall + audit."
)

HOUR = 3600
DAY = 86400
WEEK = 7 * DAY


def resolve_stream_id(title: str) -> str:
    streams = gl.api("GET", "streams") or {}
    for s in streams.get("streams", []):
        if s.get("title") == title:
            return s["id"]
    raise SystemExit(
        f"stream {title!r} not found — run `python3 indexing/cloudflare.py` first"
    )


# ── widget helpers (same shape as dashboards/idrac.py) ──────────────────────

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

def page_traffic() -> list[dict]:
    """Page 1: 24h traffic shape across all zones."""
    return [
        # Row 1: headline numbers
        numeric("Total requests (24h)", "cf_event_type:requests_5m",
                "sum(cf_requests)",
                pos={"col": 1, "row": 1, "width": 3, "height": 2}, name="req"),
        numeric("Unique visits (24h)", "cf_event_type:requests_5m",
                "sum(cf_visits)",
                pos={"col": 4, "row": 1, "width": 3, "height": 2}, name="visits"),
        numeric("Response bytes (24h)", "cf_event_type:requests_5m",
                "sum(cf_response_bytes)",
                pos={"col": 7, "row": 1, "width": 3, "height": 2}, name="B"),
        numeric("Request bytes (24h)", "cf_event_type:requests_5m",
                "sum(cf_request_bytes)",
                pos={"col": 10, "row": 1, "width": 3, "height": 2}, name="B"),
        # Row 2: requests over time (with cache split via cf_cache_status grouping)
        line_over_time("Requests over 24h (5-min buckets)",
                       "cf_event_type:requests_5m",
                       series=[("requests", "sum(cf_requests)"),
                               ("visits",   "sum(cf_visits)")],
                       pos={"col": 1, "row": 3, "width": 12, "height": 4},
                       timerange=DAY),
        # Row 3: per-zone breakdown + cache hit/miss
        table("Requests by zone (24h)",
              "cf_event_type:requests_5m",
              row_field="cf_zone_name",
              series=[("requests",  "sum(cf_requests)"),
                      ("visits",    "sum(cf_visits)"),
                      ("resp bytes","sum(cf_response_bytes)"),
                      ("req bytes", "sum(cf_request_bytes)")],
              pos={"col": 1, "row": 7, "width": 6, "height": 4}, row_limit=10),
        pie("Cache status (24h)",
            "cf_event_type:requests_5m",
            field="cf_cache_status",
            pos={"col": 7, "row": 7, "width": 3, "height": 4}),
        # Status code mix
        pie("Status codes (24h)",
            "cf_event_type:requests_by_status",
            field="cf_status",
            pos={"col": 10, "row": 7, "width": 3, "height": 4}),
        # Row 4: top countries + top hosts
        bar_categorical("Top countries by request count (24h)",
                        "cf_event_type:requests_by_status",
                        field="cf_country",
                        pos={"col": 1, "row": 11, "width": 6, "height": 4},
                        row_limit=15),
        bar_categorical("Top hosts (24h)",
                        "cf_event_type:requests_by_status",
                        field="cf_host",
                        pos={"col": 7, "row": 11, "width": 6, "height": 4},
                        row_limit=10),
    ]


def page_threats() -> list[dict]:
    """Page 2: firewall events — what's getting blocked or challenged."""
    return [
        # Row 1: headline action numbers
        numeric("Firewall events (24h)", "cf_event_type:firewall_event",
                "count()", pos={"col": 1, "row": 1, "width": 3, "height": 2}, name="ev"),
        numeric("Blocks (24h)", "cf_event_type:firewall_event AND cf_fw_action:block",
                "count()", pos={"col": 4, "row": 1, "width": 3, "height": 2}, name="ev"),
        numeric("Challenges (24h)",
                'cf_event_type:firewall_event AND (cf_fw_action:challenge OR cf_fw_action:managed_challenge OR cf_fw_action:jschallenge)',
                "count()", pos={"col": 7, "row": 1, "width": 3, "height": 2}, name="ev"),
        numeric("Unique attacker IPs (24h)",
                "cf_event_type:firewall_event",
                "cardinality(cf_client_ip)",
                pos={"col": 10, "row": 1, "width": 3, "height": 2}, name="IPs"),
        # Row 2: action breakdown over time
        pie("Action breakdown (24h)",
            "cf_event_type:firewall_event",
            field="cf_fw_action",
            pos={"col": 1, "row": 3, "width": 4, "height": 4}),
        pie("Threat source (24h)",
            "cf_event_type:firewall_event",
            field="cf_fw_source",
            pos={"col": 5, "row": 3, "width": 4, "height": 4}),
        pie("Country of origin (24h)",
            "cf_event_type:firewall_event",
            field="cf_client_country",
            pos={"col": 9, "row": 3, "width": 4, "height": 4}),
        # Row 3: tables of attacker behavior
        table("Top attacker IPs (24h)",
              "cf_event_type:firewall_event",
              row_field="cf_client_ip",
              series=[("events",   "count()"),
                      ("country",  "latest(cf_client_country)"),
                      ("last action", "latest(cf_fw_action)")],
              pos={"col": 1, "row": 7, "width": 6, "height": 4}, row_limit=15),
        table("Top attacked paths (24h)",
              "cf_event_type:firewall_event",
              row_field="cf_fw_path",
              series=[("events",  "count()"),
                      ("host",    "latest(cf_fw_host)"),
                      ("action",  "latest(cf_fw_action)")],
              pos={"col": 7, "row": 7, "width": 6, "height": 4}, row_limit=15),
        # Row 4: rule attribution
        table("Most-fired rules (24h)",
              "cf_event_type:firewall_event",
              row_field="cf_fw_rule_id",
              series=[("events", "count()"),
                      ("source", "latest(cf_fw_source)"),
                      ("kind",   "latest(cf_fw_kind)")],
              pos={"col": 1, "row": 11, "width": 12, "height": 4}, row_limit=20),
        # Row 5: raw event list
        messages_list("Recent firewall events", "cf_event_type:firewall_event",
                      pos={"col": 1, "row": 15, "width": 12, "height": 6}),
    ]


def page_dns_audit() -> list[dict]:
    """Page 3: DNS analytics + account-level audit log."""
    return [
        # DNS Row 1: headline numbers
        numeric("DNS queries (24h)", "cf_event_type:dns_summary",
                "sum(cf_dns_queries)",
                pos={"col": 1, "row": 1, "width": 3, "height": 2}, name="q"),
        numeric("Unique qtypes (24h)", "cf_event_type:dns_summary",
                "cardinality(cf_dns_query_type)",
                pos={"col": 4, "row": 1, "width": 3, "height": 2}, name="types"),
        numeric("NXDOMAINs (24h)",
                "cf_event_type:dns_summary AND cf_dns_response_code:NXDOMAIN",
                "sum(cf_dns_queries)",
                pos={"col": 7, "row": 1, "width": 3, "height": 2}, name="q"),
        numeric("SERVFAILs (24h)",
                "cf_event_type:dns_summary AND cf_dns_response_code:SERVFAIL",
                "sum(cf_dns_queries)",
                pos={"col": 10, "row": 1, "width": 3, "height": 2}, name="q"),
        # DNS Row 2: trend
        line_over_time("DNS queries over 24h",
                       "cf_event_type:dns_summary",
                       series=[("queries", "sum(cf_dns_queries)")],
                       pos={"col": 1, "row": 3, "width": 12, "height": 3},
                       timerange=DAY),
        # DNS Row 3: distributions
        pie("Query type mix (24h)",
            "cf_event_type:dns_summary",
            field="cf_dns_query_type",
            pos={"col": 1, "row": 6, "width": 6, "height": 4}),
        pie("Response code mix (24h)",
            "cf_event_type:dns_summary",
            field="cf_dns_response_code",
            pos={"col": 7, "row": 6, "width": 6, "height": 4}),
        # Audit Row 1: numbers
        numeric("Audit events (7d)", "cf_event_type:audit_log",
                "count()", pos={"col": 1, "row": 10, "width": 3, "height": 2}, name="ev"),
        numeric("Distinct actors (7d)", "cf_event_type:audit_log",
                "cardinality(cf_audit_actor)",
                pos={"col": 4, "row": 10, "width": 3, "height": 2}, name="actors"),
        numeric("Distinct action types (7d)", "cf_event_type:audit_log",
                "cardinality(cf_audit_action)",
                pos={"col": 7, "row": 10, "width": 3, "height": 2}, name="types"),
        # Audit Row 2: tables
        bar_categorical("Actions (7d)",
                        "cf_event_type:audit_log",
                        field="cf_audit_action",
                        pos={"col": 1, "row": 12, "width": 6, "height": 4},
                        timerange=WEEK, row_limit=15),
        bar_categorical("Resource types touched (7d)",
                        "cf_event_type:audit_log",
                        field="cf_audit_resource_type",
                        pos={"col": 7, "row": 12, "width": 6, "height": 4},
                        timerange=WEEK, row_limit=15),
        # Recent audit events
        messages_list("Recent audit events (7d)", "cf_event_type:audit_log",
                      pos={"col": 1, "row": 16, "width": 12, "height": 6},
                      timerange=WEEK),
    ]


def page_agents() -> list[dict]:
    """Page 4: DNS query volume + unique-resolver count for the five
    fake DNS-AID agents published on darknetian.com.

    Source records (per src/posts/2026-05-14-five-fake-agents-real-dns.md):
      search, bookings, threat-intel, dns-audit, morpheus —
      each with flat SVCB, walkable AliasMode SVCB, and TLSA pin,
      plus shared endpoint.darknetian.com and index._agents.

    cf_dns_agent groups all variants of one agent (flat + _agents +
    _443._tcp) into a single name. cf_dns_query_name is the literal
    FQDN if you need to slice finer.

    'Unique visitors' here is the cardinality of cf_dns_source_ip,
    which on authoritative DNS analytics is the unique recursive
    resolver IP — NOT the end-user IP. CF only sees the recursive
    in the middle. Useful as a relative signal of breadth (more
    distinct resolvers = more dispersed audience), not literal user count.
    """
    return [
        # Row 1: headline numbers
        numeric("Total agent queries (24h)",
                "cf_event_type:dns_agent",
                "sum(cf_dns_queries)",
                pos={"col": 1, "row": 1, "width": 3, "height": 2}, name="q"),
        numeric("Unique resolvers (24h)",
                "cf_event_type:dns_agent",
                "cardinality(cf_dns_source_ip)",
                pos={"col": 4, "row": 1, "width": 3, "height": 2}, name="IPs"),
        numeric("Distinct agent records (24h)",
                "cf_event_type:dns_agent",
                "cardinality(cf_dns_query_name)",
                pos={"col": 7, "row": 1, "width": 3, "height": 2}, name="names"),
        numeric("NXDOMAINs on agents (24h)",
                "cf_event_type:dns_agent AND cf_dns_response_code:NXDOMAIN",
                "sum(cf_dns_queries)",
                pos={"col": 10, "row": 1, "width": 3, "height": 2}, name="q"),
        # Row 2: per-agent breakdown table
        table("Per-agent query volume + unique resolvers (24h)",
              "cf_event_type:dns_agent",
              row_field="cf_dns_agent",
              series=[("queries",          "sum(cf_dns_queries)"),
                      ("unique resolvers", "cardinality(cf_dns_source_ip)"),
                      ("query types",      "cardinality(cf_dns_query_type)"),
                      ("distinct records", "cardinality(cf_dns_query_name)")],
              pos={"col": 1, "row": 3, "width": 12, "height": 4}, row_limit=10),
        # Row 3: distributions
        pie("Queries by agent (24h)",
            "cf_event_type:dns_agent",
            field="cf_dns_agent",
            pos={"col": 1, "row": 7, "width": 6, "height": 4}),
        pie("Query type mix on agents (24h)",
            "cf_event_type:dns_agent",
            field="cf_dns_query_type",
            pos={"col": 7, "row": 7, "width": 6, "height": 4}),
        # Row 4: per-record table — finer than per-agent
        table("Per-record query volume (24h)",
              "cf_event_type:dns_agent",
              row_field="cf_dns_query_name",
              series=[("queries",         "sum(cf_dns_queries)"),
                      ("unique resolvers","cardinality(cf_dns_source_ip)"),
                      ("agent",           "latest(cf_dns_agent)")],
              pos={"col": 1, "row": 11, "width": 12, "height": 5}, row_limit=25),
        # Row 5: top resolvers (recursive IPs hitting the agents)
        table("Top recursive resolvers asking about agents (24h)",
              "cf_event_type:dns_agent",
              row_field="cf_dns_source_ip",
              series=[("queries",         "sum(cf_dns_queries)"),
                      ("distinct agents", "cardinality(cf_dns_agent)"),
                      ("records hit",     "cardinality(cf_dns_query_name)")],
              pos={"col": 1, "row": 16, "width": 12, "height": 5}, row_limit=25),
    ]


# ── build / apply ────────────────────────────────────────────────────────────

def build():
    stream_id = resolve_stream_id(STREAM_TITLE)
    page_defs = [
        ("Traffic", page_traffic, DAY),
        ("Threats", page_threats, DAY),
        ("DNS & Audit", page_dns_audit, WEEK),
        ("Agents", page_agents, DAY),
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
