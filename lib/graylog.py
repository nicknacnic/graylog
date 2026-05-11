"""Tiny Graylog REST API client + dashboard-builder helpers.

Stdlib-only. Reads GRAYLOG_URL and GRAYLOG_TOKEN from the environment. Uses
HTTP Basic auth with the token as the username and the literal string
"token" as the password. TLS verification disabled by default (homelab
self-signed certs); set GRAYLOG_INSECURE=0 to enable.
"""

from __future__ import annotations

import json
import os
import ssl
import sys
import uuid
from base64 import b64encode
from typing import Any
from urllib import error, request


def _auth_header() -> str:
    token = os.environ.get("GRAYLOG_TOKEN")
    if not token:
        print("ERROR: GRAYLOG_TOKEN not set (source env.sh)", file=sys.stderr)
        sys.exit(2)
    raw = f"{token}:token".encode()
    return "Basic " + b64encode(raw).decode()


def _base_url() -> str:
    url = os.environ.get("GRAYLOG_URL")
    if not url:
        print("ERROR: GRAYLOG_URL not set", file=sys.stderr)
        sys.exit(2)
    return url.rstrip("/") + "/"


def _ssl_ctx() -> ssl.SSLContext | None:
    if os.environ.get("GRAYLOG_INSECURE", "1") == "1":
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    return None


def api(method: str, path: str, body: dict | None = None) -> Any:
    url = _base_url() + path.lstrip("/")
    headers = {
        "Authorization": _auth_header(),
        "Accept": "application/json",
        "Content-Type": "application/json",
        "X-Requested-By": "graylog-repo",
    }
    data = None
    if body is not None:
        data = json.dumps(body).encode()
    req = request.Request(url, data=data, method=method, headers=headers)
    try:
        with request.urlopen(req, context=_ssl_ctx()) as resp:
            raw = resp.read()
    except error.HTTPError as e:
        body_text = e.read().decode("utf-8", "replace")
        raise RuntimeError(f"{method} {path} -> {e.code}: {body_text[:600]}") from None
    if not raw:
        return None
    return json.loads(raw)


def gen_id() -> str:
    return str(uuid.uuid4())


# Graylog 6.x series-type names differ from the human-friendly function names
# used in widget displays. Map: function name -> pivot series type.
_SERIES_TYPE_ALIASES = {"cardinality": "card"}


def find_index_set(title: str) -> dict | None:
    for s in (api("GET", "system/indices/index_sets") or {}).get("index_sets", []):
        if s.get("title") == title:
            return s
    return None


def ensure_index_set(
    *,
    title: str,
    prefix: str,
    description: str = "",
    shards: int = 1,
    replicas: int = 0,
    retention_days: int = 30,
    rotation_age_max_days: int | None = None,
    max_indices: int = 6,
    can_be_default: bool = False,
) -> str:
    """Create the index set if it doesn't already exist; return its id."""
    existing = find_index_set(title)
    if existing:
        print(f"  index set exists: id={existing['id']} prefix={existing['index_prefix']}")
        return existing["id"]
    age_max = rotation_age_max_days or max(retention_days + 10, retention_days * 4 // 3)
    body = {
        "title": title,
        "description": description,
        "index_prefix": prefix,
        "shards": shards,
        "replicas": replicas,
        "index_analyzer": "standard",
        "index_optimization_max_num_segments": 1,
        "index_optimization_disabled": False,
        "field_type_refresh_interval": 5000,
        "rotation_strategy_class": "org.graylog2.indexer.rotation.strategies.TimeBasedSizeOptimizingStrategy",
        "rotation_strategy": {
            "type": "org.graylog2.indexer.rotation.strategies.TimeBasedSizeOptimizingStrategyConfig",
            "index_lifetime_min": f"P{retention_days}D",
            "index_lifetime_max": f"P{age_max}D",
        },
        "retention_strategy_class": "org.graylog2.indexer.retention.strategies.DeletionRetentionStrategy",
        "retention_strategy": {
            "type": "org.graylog2.indexer.retention.strategies.DeletionRetentionStrategyConfig",
            "max_number_of_indices": max_indices,
        },
        "data_tiering": {
            "type": "hot_only",
            "index_lifetime_min": f"P{retention_days}D",
            "index_lifetime_max": f"P{age_max}D",
        },
        "writable": True,
        "can_be_default": can_be_default,
    }
    resp = api("POST", "system/indices/index_sets", body)
    print(f"  created index set: id={resp['id']} prefix={resp['index_prefix']} "
          f"retention={retention_days}d shards={shards}")
    return resp["id"]


def repoint_stream_to_index_set(stream_id: str, index_set_id: str) -> None:
    """PUT the stream with index_set_id updated. No-op if already there."""
    stream = api("GET", f"streams/{stream_id}")
    if stream.get("index_set_id") == index_set_id:
        print(f"  stream {stream.get('title')!r} already on this index set")
        return
    body = {
        "title": stream["title"],
        "description": stream.get("description") or "",
        "matching_type": stream.get("matching_type", "AND"),
        "rules": [
            {k: r[k] for k in ("field", "type", "value", "inverted", "description") if k in r}
            for r in stream.get("rules", [])
        ],
        "remove_matches_from_default_stream": stream.get("remove_matches_from_default_stream", False),
        "index_set_id": index_set_id,
    }
    api("PUT", f"streams/{stream_id}", body)
    print(f"  stream {stream.get('title')!r} -> index_set {index_set_id}")


def repoint_streams_to_index_set(stream_ids: list[str], index_set_id: str) -> None:
    for sid in stream_ids:
        repoint_stream_to_index_set(sid, index_set_id)


def align_pivot_ids(widget_series: list[dict], pivot_series: list[dict]) -> list[dict] | None:
    """Set each pivot series' `id` to the matching widget series' `config.name`.

    This is the linkage Graylog's table renderer uses to map pivot result
    values back to widget columns. If `pivot.id` doesn't equal `widget.config.name`,
    rows render with row labels but empty value columns.

    Returns None when no series were provided on either side so the caller
    (pivot()) falls through to its own default count() series — otherwise an
    empty pivot.series silently bypasses the default and the widget renders
    empty even though its row pivots are populated."""
    if not widget_series and not pivot_series:
        return None
    aligned = []
    for i, ps in enumerate(pivot_series):
        if i < len(widget_series):
            name = widget_series[i].get("config", {}).get("name")
            if name:
                ps = {**ps, "id": name}
        aligned.append(ps)
    return aligned


def parse_series_fn(fn: str, name: str | None = None) -> dict:
    """Convert a human series function string into the pivot search-type dict
    Graylog expects. Pass `name` to align id with the widget series' display
    name — this is the linkage the renderer uses to map result values back to
    widget columns. Without it, table widgets show row labels with empty values.

    Handles `cardinality(field)` → type `card`.
    Bare `count()` is fine as-is — no field needed on the pivot side."""
    fn = fn.strip()
    if fn == "count()":
        out = {"type": "count", "id": fn, "field": None}
    else:
        op, rest = fn.split("(", 1)
        field = rest.rstrip(")").strip()
        pivot_type = _SERIES_TYPE_ALIASES.get(op, op)
        out = {"type": pivot_type, "id": fn, "field": field or None}
    if name is not None:
        out["id"] = name
    return out


def pivot(
    *,
    search_type_id: str,
    stream_id: str,
    query: str = "",
    timerange_s: int = 86400,
    row_field: str | None = None,
    row_time_interval: str = "auto",
    column_field: str | None = None,
    series: list[dict] | None = None,
    row_limit: int = 25,
    column_limit: int = 25,
) -> dict:
    row_groups: list[dict] = []
    if row_field == "timestamp":
        row_groups = [{
            "type": "time",
            "fields": ["timestamp"],
            "interval": {"type": "auto", "scaling": 2.0},
        }]
    elif row_field:
        row_groups = [{
            "type": "values",
            "fields": [row_field],
            "limit": row_limit,
            "skip_empty_values": True,
        }]
    column_groups: list[dict] = []
    if column_field:
        column_groups = [{
            "type": "values",
            "fields": [column_field],
            "limit": column_limit,
            "skip_empty_values": True,
        }]
    if series is None:
        series = [{"type": "count", "id": "Message Count", "field": None}]
    return {
        "id": search_type_id,
        "type": "pivot",
        "name": "chart",
        "query": {"type": "elasticsearch", "query_string": query},
        "timerange": {"type": "relative", "range": timerange_s},
        "streams": [stream_id],
        "stream_categories": [],
        "filter": None,
        "filters": [],
        "row_groups": row_groups,
        "column_groups": column_groups,
        "series": series,
        "sort": [],
        "rollup": True,
    }


def messages_searchtype(
    *,
    search_type_id: str,
    stream_id: str,
    query: str = "",
    timerange_s: int = 86400,
    limit: int = 25,
    fields: list[str] | None = None,
) -> dict:
    return {
        "id": search_type_id,
        "type": "messages",
        "name": None,
        "query": {"type": "elasticsearch", "query_string": query},
        "timerange": {"type": "relative", "range": timerange_s},
        "streams": [stream_id],
        "stream_categories": [],
        "filter": None,
        "filters": [],
        "limit": limit,
        "offset": 0,
        "sort": [{"field": "timestamp", "order": "DESC"}],
        "fields": fields or ["timestamp", "source", "message"],
        "decorators": [],
    }


def widget_aggregation(
    *,
    widget_id: str,
    stream_id: str,
    query: str = "",
    timerange_s: int = 86400,
    row_field: str | None = None,
    column_field: str | None = None,
    series: list[dict] | None = None,
    visualization: str = "bar",
    visualization_config: dict | None = None,
    row_limit: int = 25,
    column_limit: int = 25,
) -> dict:
    row_pivots: list[dict] = []
    if row_field == "timestamp":
        row_pivots = [{
            "fields": ["timestamp"],
            "type": "time",
            "config": {"interval": {"type": "auto", "scaling": 2.0}},
        }]
    elif row_field:
        # NB: do NOT include skip_empty_values on widget row_pivots — the
        # frontend table renderer treats that as a signal that values may be
        # missing and ends up rendering an empty column. The search-type's
        # row_groups can still carry it; this is only about the widget side.
        row_pivots = [{
            "fields": [row_field],
            "type": "values",
            "config": {"limit": row_limit},
        }]
    column_pivots: list[dict] = []
    if column_field:
        column_pivots = [{
            "fields": [column_field],
            "type": "values",
            "config": {"limit": column_limit},
        }]
    if series is None:
        series = [{"config": {"name": "Message Count"}, "function": "count()"}]
    if visualization_config is None:
        visualization_config = _default_viz_config(visualization)
    # Sort default to the first series, descending. Sources/Palo widgets have
    # this — empty sort sometimes leaves table widgets unable to render.
    sort = []
    if series and row_field and row_field != "timestamp":
        sort = [{
            "type": "series",
            "field": series[0]["function"],
            "direction": "Descending",
        }]
    return {
        "id": widget_id,
        "type": "aggregation",
        "filter": None,
        "filters": [],
        "timerange": {"type": "relative", "range": timerange_s},
        "query": {"type": "elasticsearch", "query_string": query},
        "streams": [stream_id],
        "stream_categories": [],
        "config": {
            "row_pivots": row_pivots,
            "column_pivots": column_pivots,
            "series": series,
            "sort": sort,
            "visualization": visualization,
            "visualization_config": visualization_config,
            "formatting_settings": None,
            "rollup": True,
            "event_annotation": False,
            "column_limit": column_limit,
            "row_limit": row_limit if row_field == "timestamp" else None,
        },
    }


def widget_messages(
    *,
    widget_id: str,
    stream_id: str,
    query: str = "",
    timerange_s: int = 86400,
    fields: list[str] | None = None,
) -> dict:
    return {
        "id": widget_id,
        "type": "messages",
        "filter": None,
        "filters": [],
        "timerange": {"type": "relative", "range": timerange_s},
        "query": {"type": "elasticsearch", "query_string": query},
        "streams": [stream_id],
        "stream_categories": [],
        "config": {
            "decorators": [],
            "fields": fields or ["timestamp", "source", "message"],
            "show_message_row": True,
            "show_summary": False,
        },
    }


def _default_viz_config(viz: str) -> dict | None:
    if viz == "bar":
        return {"barmode": "stack", "axis_type": "linear"}
    if viz == "line":
        return {"interpolation": "linear", "axis_type": "linear"}
    if viz == "numeric":
        return {"trend": False, "trend_preference": "NEUTRAL"}
    # pie, table, world_map, etc. carry no extra config in Graylog 6.x — null is correct
    return None


def build_widgets_for_page(
    stream_id: str,
    specs: list[dict],
    default_timerange_s: int = 86400,
) -> tuple[list[dict], list[dict], dict, dict, dict]:
    """Walk a list of widget specs and assemble the (search_types, widgets,
    positions, titles, widget_mapping) tuple a dashboard page needs.

    Each spec is a dict with shape:
        title, kind ('agg' | 'messages'), pos (col/row/width/height),
        query (default ''), timerange (default `default_timerange_s`),
        and for 'agg':
            viz ('bar'|'line'|'table'|'numeric'|'pie'),
            row_field, column_field (optional),
            series (widget side, list of {config.name, function}),
            pivot_series (pre-built; align_pivot_ids() runs to sync ids
                          with widget config.names),
            row_limit, column_limit (default 25 each).

    This was previously duplicated across every dashboards/*.py file —
    centralizing here so future widget-shape fixes happen in one place.
    """
    search_types: list[dict] = []
    widgets: list[dict] = []
    positions: dict[str, dict] = {}
    titles: dict[str, str] = {}
    widget_mapping: dict[str, list[str]] = {}
    for s in specs:
        wid, stid = gen_id(), gen_id()
        timerange = s.get("timerange", default_timerange_s)
        query = s.get("query", "")
        if s["kind"] == "agg":
            ps = align_pivot_ids(s.get("series", []), s.get("pivot_series", []))
            search_types.append(pivot(
                search_type_id=stid, stream_id=stream_id,
                query=query, timerange_s=timerange,
                row_field=s.get("row_field"),
                column_field=s.get("column_field"),
                series=ps,
                row_limit=s.get("row_limit", 25),
                column_limit=s.get("column_limit", 25),
            ))
            widgets.append(widget_aggregation(
                widget_id=wid, stream_id=stream_id,
                query=query, timerange_s=timerange,
                row_field=s.get("row_field"),
                column_field=s.get("column_field"),
                series=s.get("series"),
                visualization=s["viz"],
                row_limit=s.get("row_limit", 25),
                column_limit=s.get("column_limit", 25),
            ))
        elif s["kind"] == "messages":
            search_types.append(messages_searchtype(
                search_type_id=stid, stream_id=stream_id,
                query=query, timerange_s=timerange,
            ))
            widgets.append(widget_messages(
                widget_id=wid, stream_id=stream_id,
                query=query, timerange_s=timerange,
            ))
        else:
            raise ValueError(f"unknown widget kind: {s['kind']}")
        positions[wid] = s["pos"]
        titles[wid] = s["title"]
        widget_mapping[wid] = [stid]
    return search_types, widgets, positions, titles, widget_mapping


def build_search(query_id: str, search_types: list[dict], timerange_s: int = 86400) -> dict:
    """Single-page search. Use build_search_multipage for dashboards with tabs."""
    return {
        "queries": [{
            "id": query_id,
            "query": {"type": "elasticsearch", "query_string": ""},
            "timerange": {"type": "relative", "range": timerange_s},
            "filter": None,
            "filters": [],
            "search_types": search_types,
        }],
        "parameters": [],
    }


def build_search_multipage(pages: list[dict], default_timerange_s: int = 86400) -> dict:
    """Each page contributes one query to the search. Each page dict needs:
       {"query_id": str, "search_types": [...], "timerange_s": int (optional)}
    """
    return {
        "queries": [
            {
                "id": p["query_id"],
                "query": {"type": "elasticsearch", "query_string": ""},
                "timerange": {"type": "relative", "range": p.get("timerange_s", default_timerange_s)},
                "filter": None,
                "filters": [],
                "search_types": p["search_types"],
            }
            for p in pages
        ],
        "parameters": [],
    }


def build_view(
    *,
    title: str,
    summary: str,
    description: str,
    search_id: str,
    query_id: str,
    widgets: list[dict],
    positions: dict[str, dict],
    titles: dict[str, str],
    widget_mapping: dict[str, list[str]],
) -> dict:
    """Single-page view."""
    return build_view_multipage(
        title=title, summary=summary, description=description, search_id=search_id,
        pages=[{
            "query_id": query_id, "title": title,
            "widgets": widgets, "positions": positions,
            "titles": titles, "widget_mapping": widget_mapping,
        }],
    )


def build_view_multipage(
    *,
    title: str,
    summary: str,
    description: str,
    search_id: str,
    pages: list[dict],
) -> dict:
    """Multi-page view. Each page dict needs:
       {"query_id": str, "title": str (the tab label),
        "widgets": [...], "positions": {wid: {col,row,width,height}},
        "titles": {wid: "Widget title"},
        "widget_mapping": {wid: [search_type_id]}}
    """
    state = {}
    for p in pages:
        state[p["query_id"]] = {
            "selected_fields": None,
            "static_message_list_id": None,
            "titles": {"widget": p["titles"], "tab": {"title": p["title"]}},
            "widgets": p["widgets"],
            "widget_mapping": p["widget_mapping"],
            "positions": p["positions"],
            "formatting": {},
            "display_mode_settings": {"positions": {}},
        }
    return {
        "type": "DASHBOARD",
        "title": title,
        "summary": summary,
        "description": description,
        "properties": [],
        "requires": {},
        "search_id": search_id,
        "state": state,
    }
