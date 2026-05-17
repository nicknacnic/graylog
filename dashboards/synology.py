"""Synology DSM — single-page dashboard.

Fields populated by pipelines/synology.json:
  nas_category      Connection | System | MacFileService Event | SMB |
                    WebDAV | FTP | AFP | TFTP | Backup | Network Backup |
                    File Station Event | ...
  nas_detail        full body after the category prefix (for free-text msgs)
  nas_user, nas_client_ip               (Connection + AFP)
  nas_action, nas_target, nas_result,
  nas_auth_method                       (Connection)
  nas_afp_op, nas_path, nas_file_kind,
  nas_size_bytes                        (MacFileService Event / AFP)

DSM doesn't emit much on its own — figure on hundreds-to-low-thousands of
events per day with all 10 Log Center categories enabled. Volume comes in
bursts (user logins, file ops, package events). Empty widgets are normal
during quiet hours.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))
import graylog as gl  # noqa: E402

STREAM_TITLES = ["NAS", "NAS (IP-form)"]
TITLE = "Synology — DSM"
SUMMARY = "DSM syslog (10.10.0.50) — logins, file access, system events"
DESCRIPTION = (
    "Synology DSM events forwarded via Log Center → Syslog. Every message "
    "carries nas_category (Connection / MacFileService Event / System / "
    "SMB / WebDAV / FTP / Backup / …) plus per-category extracted fields. "
    "Field extraction is done by the 'Synology DSM' pipeline."
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


def page_main():
    return [
        # ── Row 1: headline tiles ───────────────────────────────────
        numeric("Total events (24h)", "*", "count()",
                pos={"col": 1, "row": 1, "width": 3, "height": 2}, name="evt"),
        numeric("Successful logins (24h)",
                'nas_category:Connection AND nas_result:successfully',
                "count()", pos={"col": 4, "row": 1, "width": 3, "height": 2}, name="logins"),
        numeric("Failed logins (24h)",
                'nas_category:Connection AND (nas_action:"failed to sign in" OR nas_action:"tried to sign in")',
                "count()", pos={"col": 7, "row": 1, "width": 3, "height": 2}, name="fails"),
        numeric("AFP file ops (24h)",
                'nas_category:"MacFileService Event"',
                "count()", pos={"col": 10, "row": 1, "width": 3, "height": 2}, name="ops"),

        # ── Row 2: category mix + over-time ─────────────────────────
        pie("Category mix (24h)",
            "_exists_:nas_category",
            field="nas_category",
            pos={"col": 1, "row": 3, "width": 5, "height": 4}),
        line_ts("Events by category (24h)",
                "_exists_:nas_category",
                series=[("count", "count()")],
                column_field="nas_category",
                pos={"col": 6, "row": 3, "width": 7, "height": 4}),

        # ── Row 3: Connection — login activity ───────────────────────
        table("Logins by user (7d)",
              "nas_category:Connection",
              row_field="nas_user", row_limit=15,
              series=[("events",         "count()"),
                      ("last seen",      "latest(timestamp)"),
                      ("auth methods",   "cardinality(nas_auth_method)"),
                      ("client IPs",     "cardinality(nas_client_ip)")],
              timerange=WEEK,
              pos={"col": 1, "row": 7, "width": 6, "height": 5}),
        table("Login client IPs (7d)",
              "nas_category:Connection",
              row_field="nas_client_ip", row_limit=15,
              series=[("events",     "count()"),
                      ("users seen", "cardinality(nas_user)"),
                      ("last seen",  "latest(timestamp)")],
              timerange=WEEK,
              pos={"col": 7, "row": 7, "width": 6, "height": 5}),

        # ── Row 4: AFP file access ──────────────────────────────────
        pie("AFP op mix (24h)",
            'nas_category:"MacFileService Event" AND _exists_:nas_afp_op',
            field="nas_afp_op",
            pos={"col": 1, "row": 12, "width": 4, "height": 4}),
        table("Top AFP users (24h)",
              'nas_category:"MacFileService Event"',
              row_field="nas_user", row_limit=10,
              series=[("ops",            "count()"),
                      ("distinct paths", "cardinality(nas_path)"),
                      ("client IPs",     "cardinality(nas_client_ip)")],
              pos={"col": 5, "row": 12, "width": 4, "height": 4}),
        table("Top AFP paths (24h)",
              'nas_category:"MacFileService Event"',
              row_field="nas_path", row_limit=10,
              series=[("ops",  "count()"),
                      ("op kinds", "cardinality(nas_afp_op)"),
                      ("users", "cardinality(nas_user)")],
              pos={"col": 9, "row": 12, "width": 4, "height": 4}),

        # ── Row 5: system + everything else (free text) ─────────────
        msgs("Recent System events (24h)",
             "nas_category:System OR nas_category:\"System SYSTEM\"",
             pos={"col": 1, "row": 16, "width": 12, "height": 5}),

        # ── Row 6: anything we don't recognize yet ──────────────────
        msgs("Recent events outside known categories (24h)",
             "NOT _exists_:nas_category",
             pos={"col": 1, "row": 21, "width": 12, "height": 4}),
    ]


def _resolve_stream_ids(titles: list[str]) -> list[str]:
    by_title = {s["title"]: s["id"]
                for s in (gl.api("GET", "streams") or {}).get("streams", [])}
    out: list[str] = []
    for t in titles:
        if t in by_title:
            out.append(by_title[t])
        else:
            print(f"  WARN: stream {t!r} not found — skipping", flush=True)
    return out


def build():
    stream_ids = _resolve_stream_ids(STREAM_TITLES)
    if not stream_ids:
        print("ERROR: no NAS streams found — run indexing/nas.py first", flush=True)
        sys.exit(2)
    primary = stream_ids[0]
    qid = gl.gen_id()
    sts, ws, pos, ti, wm = gl.build_widgets_for_page(primary, page_main(), DAY)
    # Override single-stream → multi-stream on every search_type + widget.
    for o in sts + ws:
        o["streams"] = stream_ids

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
