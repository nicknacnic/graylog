"""Agents dashboard — DNS discovery + per-agent worker telemetry.

Pulled out of the Cloudflare dashboard so the agent fabric has its
own home. Three pages:

  Agents — what's on the wire: per-agent DNS queries on
            darknetian.com (search/bookings/threat-intel/dns-audit/
            morpheus/ans/index), record-type breakdown (SVCB / TXT /
            TLSA), top resolvers walking the discovery chain.

  Bookings — darknetian-bookings worker. Invocations, per-call AE
            detail (model, surface, tool, tokens, latency, est. spend,
            budget remaining). Filtered to ant_worker:bookings.

  Morpheus — darknetian-morpheus worker. Same shape as Bookings,
            filtered to ant_worker:morpheus. Until the worker adopts
            env.AE.writeDataPoint(), only the invocation widgets
            populate; AE-driven widgets stay empty.

Source streams: same Cloudflare stream as before
  (source starts with cloudflare-) — both DNS analytics events and
  workersInvocations / AE events have cloudflare- prefixed source
  labels and so get routed there.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))
import graylog as gl  # noqa: E402

STREAM_TITLE = "Cloudflare"
TITLE = "Agents"
SUMMARY = "DNS-AID discovery on the wire + per-worker AE telemetry"
DESCRIPTION = (
    "Per-agent DNS query breakdowns from the Cloudflare DNS analytics "
    "feed (Agents page), plus per-call AE detail for the two real "
    "managed-agent workers (darknetian-bookings and darknetian-morpheus, "
    "split by the ant_worker field). All three pages share the "
    "Cloudflare stream."
)

HOUR = 3600
DAY = 86400
WEEK = 7 * DAY
MONTH = 30 * DAY


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


def pie(title, query, *, field, pos, timerange=DAY, row_limit=10):
    return {
        "title": title, "kind": "agg", "viz": "pie",
        "query": query, "timerange": timerange,
        "row_field": field, "row_limit": row_limit, "pos": pos,
    }


def table(title, query, *, row_field, series, pos, timerange=DAY,
          row_limit=25, column_field=None, column_limit=10):
    spec = {
        "title": title, "kind": "agg", "viz": "table",
        "query": query, "timerange": timerange,
        "row_field": row_field, "row_limit": row_limit,
        "series": [{"config": {"name": n}, "function": fn} for n, fn in series],
        "pivot_series": [_ps(fn) for _, fn in series],
        "pos": pos,
    }
    if column_field:
        spec["column_field"] = column_field
        spec["column_limit"] = column_limit
    return spec


def line_ts(title, query, series, *, timerange=DAY, pos, column_field=None,
            column_limit=10):
    spec = {
        "title": title, "kind": "agg", "viz": "line",
        "query": query, "timerange": timerange,
        "row_field": "timestamp", "column_field": column_field,
        "series": [{"config": {"name": n}, "function": fn} for n, fn in series],
        "pivot_series": [_ps(fn) for _, fn in series],
        "pos": pos,
    }
    if column_field:
        spec["column_limit"] = column_limit
    return spec


# ── Page 1: Agents (DNS-side) ─────────────────────────────────────────────
def page_agents():
    """Per-agent DNS query stats. cf_dns_agent is the normalized agent
    name (search/bookings/threat-intel/dns-audit/morpheus/ans/index)
    across flat + _agents + _443._tcp variants. cf_dns_query_type
    splits SVCB vs TXT vs TLSA vs A/AAAA so the discovery walk pattern
    is directly visible per agent."""
    Q = "cf_event_type:dns_agent"
    return [
        # Row 1: headline tiles
        numeric("Total agent queries (24h)", Q, "sum(cf_dns_queries)",
                pos={"col": 1, "row": 1, "width": 3, "height": 2}, name="q"),
        numeric("Unique resolvers (24h)", Q,
                "cardinality(cf_dns_source_ip)",
                pos={"col": 4, "row": 1, "width": 3, "height": 2}, name="IPs"),
        numeric("Distinct agent records (24h)", Q,
                "cardinality(cf_dns_query_name)",
                pos={"col": 7, "row": 1, "width": 3, "height": 2}, name="names"),
        numeric("NXDOMAINs on agents (24h)",
                f"{Q} AND cf_dns_response_code:NXDOMAIN",
                "sum(cf_dns_queries)",
                pos={"col": 10, "row": 1, "width": 3, "height": 2}, name="q"),

        # Row 2: per-agent × record-type matrix
        table("Per-agent query volume by record type (24h)",
              Q, row_field="cf_dns_agent",
              column_field="cf_dns_query_type", column_limit=8,
              series=[("queries",          "sum(cf_dns_queries)"),
                      ("unique resolvers", "cardinality(cf_dns_source_ip)")],
              pos={"col": 1, "row": 3, "width": 12, "height": 4}, row_limit=10),

        # Row 3: distributions
        pie("Queries by agent (24h)", Q, field="cf_dns_agent",
            pos={"col": 1, "row": 7, "width": 6, "height": 4}),
        pie("Query type mix on agents (24h)", Q, field="cf_dns_query_type",
            pos={"col": 7, "row": 7, "width": 6, "height": 4}),

        # Row 4: per-record table (finer-grained than per-agent)
        table("Per-record query volume by record type (24h)",
              Q, row_field="cf_dns_query_name",
              column_field="cf_dns_query_type", column_limit=8,
              series=[("queries",          "sum(cf_dns_queries)"),
                      ("unique resolvers", "cardinality(cf_dns_source_ip)")],
              pos={"col": 1, "row": 11, "width": 12, "height": 5}, row_limit=25),

        # Row 5: top resolvers
        table("Top recursive resolvers asking about agents (24h)",
              Q, row_field="cf_dns_source_ip",
              column_field="cf_dns_query_type", column_limit=8,
              series=[("queries",         "sum(cf_dns_queries)"),
                      ("distinct agents", "cardinality(cf_dns_agent)")],
              pos={"col": 1, "row": 16, "width": 12, "height": 5}, row_limit=25),

        # Row 6: ANS-specific lookups
        table("ANS lookups — TL host + path-2 index (24h)",
              f"{Q} AND cf_dns_agent:(ans OR index)",
              row_field="cf_dns_query_name",
              column_field="cf_dns_query_type", column_limit=8,
              series=[("queries",          "sum(cf_dns_queries)"),
                      ("unique resolvers", "cardinality(cf_dns_source_ip)")],
              pos={"col": 1, "row": 21, "width": 12, "height": 5}, row_limit=10),
    ]


# ── Pages 2 + 3: Per-worker (Bookings, Morpheus) — same shape ─────────────
def _worker_page(worker: str):
    """Builds an AE-detail + invocations page scoped to a single worker.

    Filter strategy:
      ant_worker: explicit field on AE events (set by the worker's
                  blob6 in writeDataPoint). For backward compat with
                  bookings events written before blob6 was added, the
                  poller defaults blob6 → "bookings", so bookings rows
                  are tagged correctly even without retrofitting the
                  bookings worker.
      cf_worker_script: cf_worker_invocations rows, named
                  "darknetian-<worker>" exactly.
    """
    INV  = f'cf_event_type:worker_invocations AND cf_worker_script:darknetian-{worker}'
    AE   = f'cf_event_type:anthropic_call AND ant_worker:{worker}'
    BG   = 'cf_event_type:anthropic_budget'  # budget is org-wide
    BOOK = (f'{AE} AND ant_tool:propose_meeting'
            if worker == "bookings" else "")
    return [
        # ─── Row 1: headline tiles ─────────────────────────────────────
        *([numeric("Meetings proposed (24h)", BOOK,
                   "cardinality(ant_session_id)",
                   pos={"col": 1, "row": 1, "width": 2, "height": 2},
                   name="book")]
          if worker == "bookings" else
          [numeric("Verifications (24h)",
                   f'{AE} AND ant_tool:(dcv OR tlsa OR tls_handshake_audit OR dnssec_chain OR did_web_resolve OR well_known_agent_card)',
                   "cardinality(ant_session_id)",
                   pos={"col": 1, "row": 1, "width": 2, "height": 2},
                   name="verify")]),
        numeric("Worker invocations (24h)", INV, "sum(cf_worker_requests)",
                pos={"col": 3, "row": 1, "width": 2, "height": 2}, name="req"),
        numeric("Sessions (24h)", AE, "cardinality(ant_session_id)",
                pos={"col": 5, "row": 1, "width": 2, "height": 2}, name="sess"),
        numeric("Est. spend (24h)", AE, "sum(ant_usd_delta)",
                pos={"col": 7, "row": 1, "width": 2, "height": 2}, name="$"),
        numeric("Budget remaining", BG, "latest(ant_budget_remaining_usd)",
                pos={"col": 9, "row": 1, "width": 2, "height": 2}, name="$"),
        numeric("Errors (24h)", INV, "sum(cf_worker_errors)",
                pos={"col": 11, "row": 1, "width": 2, "height": 2}, name="err"),

        # ─── Row 2: spend + tokens over 7d ─────────────────────────────
        line_ts("Estimated spend over 7d ($)", AE,
                series=[("$", "sum(ant_usd_delta)")],
                pos={"col": 1, "row": 3, "width": 6, "height": 3},
                timerange=WEEK),
        line_ts("Token volume over 7d", AE,
                series=[("in",         "sum(ant_input_tokens_delta)"),
                        ("out",        "sum(ant_output_tokens_delta)"),
                        ("cache read", "sum(ant_cache_read_tokens_delta)")],
                pos={"col": 7, "row": 3, "width": 6, "height": 3},
                timerange=WEEK),

        # ─── Row 3: surface / stop-reason / tool mix ───────────────────
        pie("Calls by surface (24h)", AE, field="ant_surface",
            pos={"col": 1, "row": 6, "width": 4, "height": 3}),
        pie("Stop-reason mix (24h)",  AE, field="ant_stop_reason",
            pos={"col": 5, "row": 6, "width": 4, "height": 3}),
        pie("Tools fired (24h)",
            f'{AE} AND NOT ant_tool:"(none)"', field="ant_tool",
            pos={"col": 9, "row": 6, "width": 4, "height": 3}),

        # ─── Row 4: per-surface + per-model side-by-side ───────────────
        table("Per-surface usage (24h)", AE,
              row_field="ant_surface",
              series=[("sessions", "cardinality(ant_session_id)"),
                      ("in",       "sum(ant_input_tokens_delta)"),
                      ("out",      "sum(ant_output_tokens_delta)"),
                      ("$",        "sum(ant_usd_delta)"),
                      ("avg ms",   "avg(ant_avg_latency_ms)")],
              pos={"col": 1, "row": 9, "width": 6, "height": 4}, row_limit=10),
        table("Per-tool usage (24h)", AE,
              row_field="ant_tool",
              series=[("calls",  "cardinality(ant_session_id)"),
                      ("in",     "sum(ant_input_tokens_delta)"),
                      ("out",    "sum(ant_output_tokens_delta)"),
                      ("$",      "sum(ant_usd_delta)"),
                      ("avg ms", "avg(ant_avg_latency_ms)")],
              pos={"col": 7, "row": 9, "width": 6, "height": 4}, row_limit=15),

        # ─── Row 5: requests + subrequests over 7d ─────────────────────
        line_ts("Requests + subrequests over 7d", INV,
                series=[("requests",    "sum(cf_worker_requests)"),
                        ("subrequests", "sum(cf_worker_subrequests)")],
                pos={"col": 1, "row": 13, "width": 12, "height": 3},
                timerange=WEEK),

        # ─── Row 6: latency p50/p99 ────────────────────────────────────
        line_ts("Wall-time p50/p99 over 7d (µs)", INV,
                series=[("p50", "avg(cf_worker_wall_p50_us)"),
                        ("p99", "avg(cf_worker_wall_p99_us)")],
                pos={"col": 1, "row": 16, "width": 6, "height": 3},
                timerange=WEEK),
        line_ts("CPU p50/p99 over 7d (µs)", INV,
                series=[("p50", "avg(cf_worker_cpu_p50_us)"),
                        ("p99", "avg(cf_worker_cpu_p99_us)")],
                pos={"col": 7, "row": 16, "width": 6, "height": 3},
                timerange=WEEK),

        # ─── Row 7: top sessions detail ────────────────────────────────
        table("Top sessions by output tokens (24h)", AE,
              row_field="ant_session_id",
              series=[("model",      "latest(ant_model)"),
                      ("surface",    "latest(ant_surface)"),
                      ("tool",       "latest(ant_tool)"),
                      ("in",         "latest(ant_input_tokens)"),
                      ("out",        "latest(ant_output_tokens)"),
                      ("cache read", "latest(ant_cache_read_tokens)"),
                      ("$",          "sum(ant_usd_delta)"),
                      ("stop",       "latest(ant_stop_reason)"),
                      ("ms",         "latest(ant_avg_latency_ms)")],
              pos={"col": 1, "row": 19, "width": 12, "height": 6},
              row_limit=20),

        # ─── Row 8: non-success outcomes ───────────────────────────────
        line_ts("Non-success worker outcomes over 7d, per status",
                f'{INV} AND NOT cf_worker_status:success',
                series=[("requests", "sum(cf_worker_requests)")],
                column_field="cf_worker_status", column_limit=8,
                pos={"col": 1, "row": 25, "width": 12, "height": 3},
                timerange=WEEK),

        # ─── Row 9 (morpheus only): DCV-verified domains ───────────────
        # Each row = one (domain, result) combo from morpheus's
        # runDcvVerifyChallenge. 'pass' rows are zones the caller has
        # proven they control via the _agents-challenge TXT — anyone
        # who's gotten through can read the gated per-finding fix
        # detail for that domain in their session.
        *(_dcv_widgets() if worker == "morpheus" else []),

        # ─── Row 10 (morpheus only): every domain audited ──────────────
        # One row per probe invocation, blob2 carries the input domain
        # (dns_aid_index({zone}), tls_handshake_audit({host}), etc.).
        *(_audit_target_widgets() if worker == "morpheus" else []),
    ]


def _audit_target_widgets() -> list[dict]:
    """Which domains has morpheus audited? Sourced from per-probe AE
    writes (cf_event_type:morpheus_probe). Each probe tool emits one
    datapoint per invocation with the domain it was called against,
    so this section is independent of the regular per-call telemetry."""
    P = "cf_event_type:morpheus_probe"
    return [
        numeric("Distinct domains audited (24h)", P,
                "cardinality(morpheus_probe_domain)",
                pos={"col": 1, "row": 36, "width": 3, "height": 2},
                name="domains"),
        numeric("Total probes fired (24h)", P,
                "sum(morpheus_probe_count)",
                pos={"col": 4, "row": 36, "width": 3, "height": 2},
                name="probes"),
        numeric("Probes with failures (24h)",
                f'{P} AND morpheus_probe_result:fail',
                "count()",
                pos={"col": 7, "row": 36, "width": 3, "height": 2},
                name="fail"),
        numeric("Avg probe latency ms (24h)", P,
                "avg(morpheus_probe_latency_ms)",
                pos={"col": 10, "row": 36, "width": 3, "height": 2},
                name="ms"),

        # The headline — every domain morpheus has been pointed at.
        table("Audited domains (24h)", P,
              row_field="morpheus_probe_domain",
              series=[("probes",   "sum(morpheus_probe_count)"),
                      ("sessions", "cardinality(ant_session_id)"),
                      ("✓ pass",   "sum(morpheus_findings_pass)"),
                      ("⚠ warn",   "sum(morpheus_findings_warn)"),
                      ("✗ fail",   "sum(morpheus_findings_fail)"),
                      ("⨯ error",  "sum(morpheus_findings_error)"),
                      ("avg ms",   "avg(morpheus_probe_latency_ms)"),
                      ("last seen","latest(ant_last_seen)")],
              pos={"col": 1, "row": 38, "width": 12, "height": 6},
              row_limit=50),

        # Per-domain × per-probe matrix — see which probes ran against
        # each domain (column_limit=12 covers the morpheus probe set).
        table("Per-domain probe coverage (24h)", P,
              row_field="morpheus_probe_domain",
              column_field="morpheus_probe_name", column_limit=15,
              series=[("invocations", "sum(morpheus_probe_count)")],
              pos={"col": 1, "row": 44, "width": 12, "height": 6},
              row_limit=25),

        # Outcome distribution per probe — how often each probe lands
        # on pass / warn / fail / error across all domains.
        table("Per-probe outcome mix (24h)", P,
              row_field="morpheus_probe_name",
              column_field="morpheus_probe_result", column_limit=6,
              series=[("invocations", "sum(morpheus_probe_count)")],
              pos={"col": 1, "row": 50, "width": 12, "height": 5},
              row_limit=20),

        # Recent audits as a message list — chronological feed.
        {"title": "Recent audits (24h, newest first)",
         "kind": "messages",
         "query": P,
         "timerange": DAY,
         "pos": {"col": 1, "row": 55, "width": 12, "height": 5}},
    ]


def _dcv_widgets() -> list[dict]:
    DCV = "cf_event_type:morpheus_dcv_verify"
    return [
        numeric("DCV verifies — passed (24h)",
                f"{DCV} AND morpheus_dcv_result:pass",
                "cardinality(morpheus_dcv_domain)",
                pos={"col": 1, "row": 28, "width": 3, "height": 2},
                name="domains"),
        numeric("DCV verifies — total attempts (24h)", DCV, "count()",
                pos={"col": 4, "row": 28, "width": 3, "height": 2},
                name="attempts"),
        numeric("DCV failures (24h)",
                f"{DCV} AND NOT morpheus_dcv_result:pass",
                "count()",
                pos={"col": 7, "row": 28, "width": 3, "height": 2},
                name="fail"),
        numeric("Avg verify latency ms (24h)", DCV,
                "avg(ant_avg_latency_ms)",
                pos={"col": 10, "row": 28, "width": 3, "height": 2},
                name="ms"),
        # The headline widget — exact domains that have passed DCV.
        table("Domains that passed DCV (24h)",
              f"{DCV} AND morpheus_dcv_result:pass",
              row_field="morpheus_dcv_domain",
              series=[("verifications", "count()"),
                      ("sessions",      "cardinality(ant_session_id)"),
                      ("last seen",     "latest(ant_last_seen)"),
                      ("avg ms",        "avg(ant_avg_latency_ms)")],
              pos={"col": 1, "row": 30, "width": 6, "height": 6},
              row_limit=50),
        # Failure breakdown — why DCV didn't pass for someone trying.
        table("DCV failures by reason (24h)",
              f"{DCV} AND NOT morpheus_dcv_result:pass",
              row_field="morpheus_dcv_result",
              column_field="morpheus_dcv_domain", column_limit=8,
              series=[("attempts", "count()")],
              pos={"col": 7, "row": 30, "width": 6, "height": 6},
              row_limit=15),
    ]


def page_bookings():
    return _worker_page("bookings")


def page_morpheus():
    return _worker_page("morpheus")


def _resolve_stream_id() -> str:
    streams = (gl.api("GET", "streams") or {}).get("streams", [])
    for s in streams:
        if s["title"] == STREAM_TITLE:
            return s["id"]
    print(f"ERROR: stream {STREAM_TITLE!r} not found", file=sys.stderr)
    sys.exit(2)


def build():
    stream_id = _resolve_stream_id()
    page_defs = [
        ("Agents",   page_agents,   DAY),
        ("Bookings", page_bookings, WEEK),
        ("Morpheus", page_morpheus, WEEK),
    ]
    pages_for_search: list[dict] = []
    pages_for_view: list[dict] = []
    for title, fn, default_timerange in page_defs:
        qid = gl.gen_id()
        sts, ws, pos, ti, wm = gl.build_widgets_for_page(
            stream_id, fn(), default_timerange,
        )
        pages_for_search.append({
            "query_id": qid, "search_types": sts, "timerange_s": default_timerange,
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
    print(f"open:      {os.environ['GRAYLOG_URL'].rsplit('/api', 1)[0]}/dashboards/{vresp['id']}")


if __name__ == "__main__":
    build()
