"""vLLM Calls — single-page dashboard.

Fields emitted by benchmarks/scripts/gelf_log.py (called from
expand_preflight.py and triage_preflight.py on atlas), one GELF event
per vLLM invocation:
  vllm_caller               expand_preflight | triage_preflight
  vllm_card_id               kanban card id the call was made for
  vllm_model                 model name (qwen3-coder)
  vllm_prompt_tokens, vllm_completion_tokens
  vllm_latency_ms
  vllm_status                ok | error
  vllm_error                 (only present on status:error)

This is the per-request visibility vLLM itself doesn't provide — vllm-coder
runs with --no-enable-log-requests, so its own access log can't tell you
which workflow made a call or how many tokens it cost. This dashboard is
sourced from the caller-side instrumentation instead.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))
import graylog as gl  # noqa: E402

STREAM_TITLE = "vLLM Calls"
TITLE = "vLLM Calls"
SUMMARY = "Per-call vLLM invocation telemetry from atlas preflight scripts"
DESCRIPTION = (
    "Caller, card, tokens, latency, and status for every vLLM call made by "
    "expand_preflight.py and triage_preflight.py on atlas. vLLM's own access "
    "log is payload-blind (--no-enable-log-requests), so this is the only "
    "per-request view — which workflow called it, how many tokens, how long "
    "it took, and whether it succeeded."
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


def page_main():
    return [
        # ── Row 1: headline tiles ───────────────────────────────────
        numeric("Total calls (24h)", "*", "count()",
                pos={"col": 1, "row": 1, "width": 3, "height": 2}, name="calls"),
        numeric("Errors (24h)", "vllm_status:error", "count()",
                pos={"col": 4, "row": 1, "width": 3, "height": 2}, name="err"),
        numeric("Avg latency ms (24h)", "*", "avg(vllm_latency_ms)",
                pos={"col": 7, "row": 1, "width": 3, "height": 2}, name="ms"),
        numeric("Total completion tokens (24h)", "*", "sum(vllm_completion_tokens)",
                pos={"col": 10, "row": 1, "width": 3, "height": 2}, name="tok"),

        # ── Row 2: caller mix + latency over time ───────────────────
        pie("Calls by caller (24h)", "*", field="vllm_caller",
            pos={"col": 1, "row": 3, "width": 5, "height": 4}),
        line_ts("Latency p-ish over 7d (avg ms, by caller)",
                "*",
                series=[("avg ms", "avg(vllm_latency_ms)")],
                column_field="vllm_caller",
                timerange=WEEK,
                pos={"col": 6, "row": 3, "width": 7, "height": 4}),

        # ── Row 3: token volume over time ────────────────────────────
        line_ts("Token volume over 7d", "*",
                series=[("prompt",     "sum(vllm_prompt_tokens)"),
                        ("completion", "sum(vllm_completion_tokens)")],
                timerange=WEEK,
                pos={"col": 1, "row": 7, "width": 12, "height": 4}),

        # ── Row 4: per-caller breakdown ──────────────────────────────
        table("Per-caller usage (24h)", "*",
              row_field="vllm_caller", row_limit=10,
              series=[("calls",         "count()"),
                      ("errors",        "count()"),
                      ("prompt tok",    "sum(vllm_prompt_tokens)"),
                      ("completion tok","sum(vllm_completion_tokens)"),
                      ("avg ms",        "avg(vllm_latency_ms)")],
              pos={"col": 1, "row": 11, "width": 12, "height": 4}),

        # ── Row 5: per-card detail (which cards drove the most cost) ─
        table("Per-card calls (24h)", "*",
              row_field="vllm_card_id", row_limit=25,
              series=[("caller",        "latest(vllm_caller)"),
                      ("calls",         "count()"),
                      ("prompt tok",    "sum(vllm_prompt_tokens)"),
                      ("completion tok","sum(vllm_completion_tokens)"),
                      ("avg ms",        "avg(vllm_latency_ms)")],
              pos={"col": 1, "row": 15, "width": 12, "height": 6}),

        # ── Row 6: recent errors ──────────────────────────────────────
        msgs("Recent errors (7d)", "vllm_status:error",
             timerange=WEEK,
             pos={"col": 1, "row": 21, "width": 12, "height": 5}),
    ]


def _resolve_stream_id() -> str:
    streams = (gl.api("GET", "streams") or {}).get("streams", [])
    for s in streams:
        if s["title"] == STREAM_TITLE:
            return s["id"]
    print(f"ERROR: stream {STREAM_TITLE!r} not found — run indexing/vllm_calls.py first",
          file=sys.stderr)
    sys.exit(2)


def build():
    stream_id = _resolve_stream_id()
    qid = gl.gen_id()
    sts, ws, pos, ti, wm = gl.build_widgets_for_page(stream_id, page_main(), DAY)

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
    print(f"open:      {os.environ['GRAYLOG_URL'].rsplit('/api', 1)[0]}/dashboards/{vresp['id']}")


if __name__ == "__main__":
    build()
