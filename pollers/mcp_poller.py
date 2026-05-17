"""Infoblox PortunusDnsLogs → Graylog (GELF HTTP) poller.

Pulls per-DFP DNS query activity from the CSP CubeJS `PortunusDnsLogs`
cube every 5 minutes and ships aggregates as GELF events. Scoped to
the LAYER8 NIOS-X DFP (`network = "LAYER8 NIOS-X (DFP)"`) so this is
the per-host counterpart to the account-level `*_iq` metrics shipped
by csp_poller.py.

Discovered via the CSP MCP gateway catalog exploration — hence the
"IQ - MCP" page name on the Graylog dashboard. The poller itself talks
direct CubeJS REST (one urlopen per metric, easier to babysit than
SSE-over-MCP for a 5-min cron loop).

Per cycle we issue ~8 cube queries, each scoped to the last hour:
  1. dfp_requests_total      — total query count
  2. dfp_top_qname           — top 25 qnames
  3. dfp_top_qip             — top 25 client IPs
  4. dfp_top_policy_action   — block/allow/log/etc breakdown
  5. dfp_top_tclass          — threat class breakdown
  6. dfp_top_tfamily         — threat family breakdown
  7. dfp_top_feed_name       — which intel feed fired
  8. dfp_top_app_category    — app awareness breakdown
  9. dfp_top_dns_view        — which DNS view
 10. dfp_top_qtype           — A / AAAA / HTTPS / CNAME / PTR / …

Env vars:
    INFOBLOX_API_KEY   Read-scope CSP API key (Authorization: Token)
    MCP_DFP_NETWORK    DFP service name as it appears in PortunusDnsLogs
                       e.g. "LAYER8 NIOS-X (DFP)"
    CSP_BASE_URL       default https://csp.infoblox.com
    MCP_LOOKBACK_MIN   default 60  — how far back to query
    MCP_TOP_N          default 25  — top-N rows per dimension
    MCP_STATE_PATH     default /var/lib/mcp-poller/state.json
    GELF_URL           default http://127.0.0.1:12202/gelf

GELF fields:
    host           csp-infoblox-com    (routes into the same Infoblox
                                       CSP stream as csp_poller.py)
    _csp_metric    dfp_* metric name above
    _csp_scope     'dfp_host'
    _csp_value     numeric measurement (request count)
    _csp_bucket    ISO timestamp of the query window end
    _csp_network   the DFP network name being polled
    _dfp_qname / _dfp_qip / _dfp_policy_action / _dfp_tclass /
    _dfp_tfamily / _dfp_feed_name / _dfp_app_category /
    _dfp_dns_view / _dfp_qtype — populated per metric.
"""

from __future__ import annotations

import json
import os
import ssl
import sys
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib import error, parse, request


def _env(name: str, default: str | None = None) -> str:
    v = os.environ.get(name, default)
    if v is None:
        print(f"ERROR: {name} not set", file=sys.stderr)
        sys.exit(2)
    return v


CSP_API_KEY = _env("INFOBLOX_API_KEY")
DFP_NETWORK = _env("MCP_DFP_NETWORK")
CSP_BASE_URL = os.environ.get("CSP_BASE_URL", "https://csp.infoblox.com").rstrip("/")
LOOKBACK_MIN = int(os.environ.get("MCP_LOOKBACK_MIN", "60"))
TOP_N = int(os.environ.get("MCP_TOP_N", "25"))
GELF_URL = os.environ.get("GELF_URL", "http://127.0.0.1:12202/gelf")
STATE_PATH = Path(os.environ.get("MCP_STATE_PATH", "/var/lib/mcp-poller/state.json"))
INSECURE = os.environ.get("MCP_INSECURE", "0") == "1"


def _ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    if INSECURE:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")


def cube(query: dict) -> list[dict]:
    """Run a CubeJS query against PortunusDnsLogs and return data rows."""
    url = f"{CSP_BASE_URL}/api/cubejs/v1/load?" + parse.urlencode({"query": json.dumps(query)})
    req = request.Request(url, headers={
        "Authorization": f"Token {CSP_API_KEY}",
        "Accept": "application/json",
        "User-Agent": "homelab-graylog-mcp-poller/0.1",
    })
    with request.urlopen(req, context=_ctx(), timeout=90) as r:
        body = json.loads(r.read())
    if "error" in body:
        raise RuntimeError(f"cubejs error: {body['error']}")
    return ((body.get("result") or {}).get("data") or [])


def gelf(short_message: str, *, level: int = 6, **fields: Any) -> None:
    msg = {
        "version": "1.1",
        "host": "csp-infoblox-com",
        "short_message": short_message[:1024],
        "level": level,
        "timestamp": time.time(),
    }
    for k, v in fields.items():
        if v is None:
            continue
        if isinstance(v, bool):
            v = "true" if v else "false"
        key = k if k.startswith("_") else f"_{k}"
        msg[key] = v
    data = json.dumps(msg).encode()
    req = request.Request(GELF_URL, data=data, headers={"Content-Type": "application/json"})
    try:
        with request.urlopen(req, timeout=5) as r:
            r.read()
    except error.URLError as e:
        print(f"GELF POST failed: {e}", file=sys.stderr)


def load_state() -> dict:
    try:
        return json.loads(STATE_PATH.read_text())
    except FileNotFoundError:
        return {}


def save_state(state: dict) -> None:
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    STATE_PATH.write_text(json.dumps(state))


def network_filter() -> dict:
    return {"member": "PortunusDnsLogs.network", "operator": "equals",
            "values": [DFP_NETWORK]}


def fetch_total(since: str, until: str) -> int:
    rows = cube({
        "measures": ["PortunusDnsLogs.requests"],
        "filters": [network_filter()],
        "timeDimensions": [{"dimension": "PortunusDnsLogs.timestamp",
                            "dateRange": [since, until]}],
    })
    if not rows:
        return 0
    return int(rows[0].get("PortunusDnsLogs.requests") or 0)


def fetch_top(dim: str, since: str, until: str, *, limit: int = TOP_N,
              extra_filters: list[dict] | None = None) -> list[dict]:
    filters = [network_filter()] + (extra_filters or [])
    return cube({
        "measures": ["PortunusDnsLogs.requests"],
        "dimensions": [f"PortunusDnsLogs.{dim}"],
        "filters": filters,
        "timeDimensions": [{"dimension": "PortunusDnsLogs.timestamp",
                            "dateRange": [since, until]}],
        "order": {"PortunusDnsLogs.requests": "desc"},
        "limit": limit,
    })


def _safe(label: str, fn) -> None:
    try:
        fn()
    except Exception:
        print(f"[{label}] failed:", file=sys.stderr)
        traceback.print_exc()


def emit_total(value: int, bucket: str) -> None:
    gelf(
        f"PortunusDnsLogs total requests (1h): {value}",
        csp_metric="dfp_requests_total",
        csp_scope="dfp_host",
        csp_value=float(value),
        csp_bucket=bucket,
        csp_network=DFP_NETWORK,
    )


def emit_top(metric: str, gelf_field: str, dim: str,
             rows: list[dict], bucket: str) -> int:
    n = 0
    for row in rows:
        v = row.get("PortunusDnsLogs.requests")
        k = row.get(f"PortunusDnsLogs.{dim}")
        if v is None or k in (None, ""):
            continue
        gelf(
            f"PortunusDnsLogs {metric} {k}: {v}",
            csp_metric=metric,
            csp_scope="dfp_host",
            csp_value=float(v),
            csp_bucket=bucket,
            csp_network=DFP_NETWORK,
            **{gelf_field: k},
        )
        n += 1
    return n


TOP_SPECS = [
    # (metric_name,            gelf_field,           cube dimension)
    ("dfp_top_qname",          "_dfp_qname",         "qname"),
    ("dfp_top_qip",            "_dfp_qip",           "qip"),
    ("dfp_top_policy_action",  "_dfp_policy_action", "policy_action"),
    ("dfp_top_tclass",         "_dfp_tclass",        "tclass"),
    ("dfp_top_tfamily",        "_dfp_tfamily",       "tfamily"),
    ("dfp_top_feed_name",      "_dfp_feed_name",     "feed_name"),
    ("dfp_top_app_category",   "_dfp_app_category",  "app_category"),
    ("dfp_top_dns_view",       "_dfp_dns_view",      "dns_view"),
    ("dfp_top_qtype",          "_dfp_qtype",         "query_type"),
]


def main() -> None:
    state = load_state()
    now = time.time()
    until = iso(now)
    since = iso(now - LOOKBACK_MIN * 60)
    print(f"== mcp poller {since} .. {until}  network={DFP_NETWORK!r} ==")

    def go_total():
        total = fetch_total(since, until)
        emit_total(total, until)
        print(f"  total: {total}")
    _safe("total", go_total)

    for metric, field, dim in TOP_SPECS:
        def go(metric=metric, field=field, dim=dim):
            rows = fetch_top(dim, since, until)
            n = emit_top(metric, field, dim, rows, until)
            print(f"  {metric}: {n} rows")
        _safe(metric, go)

    state["last_run"] = until
    save_state(state)
    print("done.")


if __name__ == "__main__":
    main()
