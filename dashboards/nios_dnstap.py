"""NIOS dnstap dashboard.

Source: every grid member with dnstap-output enabled forwards
fstrm-framed dnstap events to dnscollector on graylog.darknetian.com:6000;
the bridge reshapes to GELF and they land in the dedicated "NIOS dnstap"
stream with these fields:

  source            'nios-dnstap'
  dnstap_operation  CLIENT_QUERY | CLIENT_RESPONSE |
                    FORWARDER_QUERY | FORWARDER_RESPONSE
  dnstap_identity   ns1.darknetian.com | ddi.darknetian.com | …
  dnstap_latency_ms response latency (responses only)
  dns_qname, dns_qtype, dns_qclass, dns_rcode, dns_id
  dns_client_ip     stub client (CLIENT_*) or upstream (FORWARDER_*)
  dns_server_ip     NIOS member IP

Three pages:
  - Overview: rate, mix, top names/clients
  - Forwarders: what NIOS asks upstream + latency
  - Errors: NXDOMAIN / SERVFAIL / REFUSED only
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))
import graylog as gl  # noqa: E402

STREAM_TITLE = "NIOS dnstap"
TITLE = "NIOS dnstap"
SUMMARY = "Per-query DNS visibility across the grid (queries, responses, forwarders, latency)"
DESCRIPTION = (
    "dnstap output from every grid member with dnstap-output enabled. "
    "Source label is `nios-dnstap`; per-member identity in `dnstap_identity`. "
    "Use this to spot top talkers, anomalous qnames, NXDOMAIN/SERVFAIL spikes, "
    "and slow upstream forwarders."
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


# ── Overview ──────────────────────────────────────────────────────────────
def page_overview():
    CR = "dnstap_operation:CLIENT_RESPONSE"
    CQ = "dnstap_operation:CLIENT_QUERY"
    return [
        # Row 1 — headline numerics
        numeric("Queries (1h)", CQ, "count()", timerange=HOUR,
                pos={"col": 1, "row": 1, "width": 3, "height": 2}, name="q"),
        numeric("Responses (1h)", CR, "count()", timerange=HOUR,
                pos={"col": 4, "row": 1, "width": 3, "height": 2}, name="r"),
        numeric("Distinct clients (1h)", CQ, "cardinality(dns_client_ip)",
                timerange=HOUR,
                pos={"col": 7, "row": 1, "width": 3, "height": 2}, name="clients"),
        numeric("Distinct qnames (1h)", CQ, "cardinality(dns_qname)",
                timerange=HOUR,
                pos={"col": 10, "row": 1, "width": 3, "height": 2}, name="qnames"),

        # Row 2 — volume over time, per member
        line_ts("Queries over 24h, per grid member",
                CQ, series=[("count", "count()")],
                column_field="dnstap_identity",
                pos={"col": 1, "row": 3, "width": 12, "height": 4}),

        # Row 3 — qtype + rcode pies
        pie("Query types (24h)", CQ, field="dns_qtype",
            pos={"col": 1, "row": 7, "width": 4, "height": 4}),
        pie("Response codes (24h)", CR, field="dns_rcode",
            pos={"col": 5, "row": 7, "width": 4, "height": 4}),
        pie("Grid member mix (24h)", CQ, field="dnstap_identity",
            pos={"col": 9, "row": 7, "width": 4, "height": 4}),

        # Row 4 — top qnames + top clients (24h tables)
        table("Top qnames (24h)", CQ,
              row_field="dns_qname", row_limit=25,
              series=[("queries", "count()"),
                      ("clients", "cardinality(dns_client_ip)"),
                      ("qtypes",  "cardinality(dns_qtype)")],
              pos={"col": 1, "row": 11, "width": 6, "height": 6}),
        table("Top clients (24h)", CQ,
              row_field="dns_client_ip", row_limit=25,
              series=[("queries", "count()"),
                      ("qnames",  "cardinality(dns_qname)"),
                      ("members", "cardinality(dnstap_identity)")],
              pos={"col": 7, "row": 11, "width": 6, "height": 6}),

        # Row 5 — recent activity (newest first)
        msgs("Recent queries (1h, newest first)", CQ,
             timerange=HOUR,
             pos={"col": 1, "row": 17, "width": 12, "height": 6}),
    ]


# ── Forwarders ─────────────────────────────────────────────────────────────
def page_forwarders():
    FQ = "dnstap_operation:FORWARDER_QUERY"
    FR = "dnstap_operation:FORWARDER_RESPONSE"
    return [
        # Row 1 — headline
        numeric("Forwarder queries (1h)", FQ, "count()", timerange=HOUR,
                pos={"col": 1, "row": 1, "width": 3, "height": 2}, name="fq"),
        numeric("Forwarder responses (1h)", FR, "count()", timerange=HOUR,
                pos={"col": 4, "row": 1, "width": 3, "height": 2}, name="fr"),
        numeric("Distinct upstreams (1h)", FQ,
                "cardinality(dns_server_ip)", timerange=HOUR,
                pos={"col": 7, "row": 1, "width": 3, "height": 2}, name="up"),
        numeric("Avg upstream latency ms (1h)", FR,
                "avg(dnstap_latency_ms)", timerange=HOUR,
                pos={"col": 10, "row": 1, "width": 3, "height": 2}, name="ms"),

        # Row 2 — volume over time per upstream
        line_ts("Forwarded queries over 24h, per upstream",
                FQ, series=[("count", "count()")],
                column_field="dns_server_ip",
                pos={"col": 1, "row": 3, "width": 12, "height": 4}),

        # Row 3 — top upstreams + top forwarded qnames
        table("Top upstreams (24h)", FQ,
              row_field="dns_server_ip", row_limit=15,
              series=[("queries", "count()"),
                      ("qnames",  "cardinality(dns_qname)"),
                      ("avg ms",  "avg(dnstap_latency_ms)"),
                      ("max ms",  "max(dnstap_latency_ms)")],
              pos={"col": 1, "row": 7, "width": 6, "height": 6}),
        table("Top forwarded qnames (24h)", FQ,
              row_field="dns_qname", row_limit=25,
              series=[("queries",   "count()"),
                      ("upstreams", "cardinality(dns_server_ip)")],
              pos={"col": 7, "row": 7, "width": 6, "height": 6}),

        # Row 4 — latency line over time per upstream
        line_ts("Upstream latency ms over 24h",
                FR, series=[("avg ms", "avg(dnstap_latency_ms)")],
                column_field="dns_server_ip",
                pos={"col": 1, "row": 13, "width": 12, "height": 4}),

        # Row 5 — slowest individual responses
        msgs("Slowest forwarder responses (1h)",
             FR + " AND dnstap_latency_ms:>=50",
             timerange=HOUR,
             pos={"col": 1, "row": 17, "width": 12, "height": 5}),
    ]


# ── Errors ─────────────────────────────────────────────────────────────────
def page_errors():
    ERRS = ('dnstap_operation:CLIENT_RESPONSE AND dns_rcode:('
            'NXDOMAIN OR SERVFAIL OR REFUSED OR FORMERR OR NOTIMPL)')
    return [
        # Row 1 — counts per rcode
        numeric("NXDOMAIN (1h)",
                "dnstap_operation:CLIENT_RESPONSE AND dns_rcode:NXDOMAIN",
                "count()", timerange=HOUR,
                pos={"col": 1, "row": 1, "width": 3, "height": 2}, name="nx"),
        numeric("SERVFAIL (1h)",
                "dnstap_operation:CLIENT_RESPONSE AND dns_rcode:SERVFAIL",
                "count()", timerange=HOUR,
                pos={"col": 4, "row": 1, "width": 3, "height": 2}, name="sf"),
        numeric("REFUSED (1h)",
                "dnstap_operation:CLIENT_RESPONSE AND dns_rcode:REFUSED",
                "count()", timerange=HOUR,
                pos={"col": 7, "row": 1, "width": 3, "height": 2}, name="rf"),
        numeric("Other errors (1h)",
                "dnstap_operation:CLIENT_RESPONSE AND dns_rcode:(FORMERR OR NOTIMPL OR BADVERS OR NOTAUTH)",
                "count()", timerange=HOUR,
                pos={"col": 10, "row": 1, "width": 3, "height": 2}, name="other"),

        # Row 2 — errors over time, broken out by rcode
        line_ts("Errors over 24h, per rcode",
                ERRS, series=[("count", "count()")],
                column_field="dns_rcode",
                pos={"col": 1, "row": 3, "width": 12, "height": 4}),

        # Row 3 — top NXDOMAIN qnames + top NXDOMAIN clients
        table("Top NXDOMAIN qnames (24h)",
              "dnstap_operation:CLIENT_RESPONSE AND dns_rcode:NXDOMAIN",
              row_field="dns_qname", row_limit=25,
              series=[("count",   "count()"),
                      ("clients", "cardinality(dns_client_ip)")],
              pos={"col": 1, "row": 7, "width": 6, "height": 6}),
        table("Top NXDOMAIN-producing clients (24h)",
              "dnstap_operation:CLIENT_RESPONSE AND dns_rcode:NXDOMAIN",
              row_field="dns_client_ip", row_limit=25,
              series=[("count",  "count()"),
                      ("qnames", "cardinality(dns_qname)")],
              pos={"col": 7, "row": 7, "width": 6, "height": 6}),

        # Row 4 — top SERVFAIL qnames
        table("Top SERVFAIL qnames (24h)",
              "dnstap_operation:CLIENT_RESPONSE AND dns_rcode:SERVFAIL",
              row_field="dns_qname", row_limit=15,
              series=[("count",   "count()"),
                      ("clients", "cardinality(dns_client_ip)")],
              pos={"col": 1, "row": 13, "width": 12, "height": 5}),

        # Row 5 — recent errors
        msgs("Recent errors (1h, newest first)", ERRS, timerange=HOUR,
             pos={"col": 1, "row": 18, "width": 12, "height": 5}),
    ]


def _resolve_stream_id() -> str:
    streams = (gl.api("GET", "streams") or {}).get("streams", [])
    for s in streams:
        if s["title"] == STREAM_TITLE:
            return s["id"]
    print(f"ERROR: stream {STREAM_TITLE!r} not found — run indexing/nios_dnstap.py first",
          file=sys.stderr)
    sys.exit(2)


def build():
    stream_id = _resolve_stream_id()
    page_defs = [
        ("Overview",   page_overview,   DAY),
        ("Forwarders", page_forwarders, DAY),
        ("Errors",     page_errors,     DAY),
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
    print(f"search id: {sresp['id']}")

    view = gl.build_view_multipage(
        title=TITLE, summary=SUMMARY, description=DESCRIPTION,
        search_id=sresp["id"], pages=pages_for_view,
    )
    vresp = gl.api("POST", "views", view)
    print(f"view id:   {vresp['id']}")
    print(f"open:      {os.environ['GRAYLOG_URL'].rsplit('/api', 1)[0]}/dashboards/{vresp['id']}")


if __name__ == "__main__":
    build()
