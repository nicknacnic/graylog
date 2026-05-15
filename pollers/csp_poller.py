"""Infoblox CSP CubeJS → Graylog (GELF HTTP) poller.

Pulls Infoblox IQ-computed `*_iq` health metrics from the CSP CubeJS
analytics API every 5 minutes (via systemd timer) and emits each row
as a GELF event into the existing Graylog HTTP input on 127.0.0.1:12202.

Two query shapes per cycle:
  Account-level (host=''):
    cache_hit_ratio_iq, dns_qps_iq, dns_nxdomain_percent_iq,
    dns_servfail_percent_iq, dns_refused_percent_iq, dns_others_percent_iq,
    dns_latency_upstream_iq, ddns_ups_iq
  Per-host (CSP_HOST_UUID):
    host_cpu_iq, host_memory_iq

The CubeJS API requires a `metric_name` filter on every query —
HostMetrics is a high-cardinality cube and the gateway refuses
filter-less queries with 400. So we issue one query per metric_name
per cycle. With ~10 metrics, that's ~10 GETs every 5 min = well below
the gateway's per-token rate limit.

Discovery shape captured from REEF's _infoblox/reef/docs/internal/
INTERNAL-ENDPOINTS.md + iq-chat.har — these are undocumented per
public /apidoc.

Env vars:
    INFOBLOX_API_KEY    Read-scope CSP API key (Authorization: Token)
    CSP_HOST_UUID       (optional) UUID for the per-host LAYER8-NIOSX
                        cuts. If unset, per-host metrics are skipped.
    CSP_HOST_LABEL      (optional) friendly name for the host, defaults
                        to 'NIOS-X' if CSP_HOST_UUID is set
    CSP_BASE_URL        default https://csp.infoblox.com
    CSP_LOOKBACK_MIN    default 60  — how far back to query
    CSP_STATE_PATH      default /var/lib/csp-poller/state.json
    GELF_URL            default http://127.0.0.1:12202/gelf

GELF messages:
    host               'csp-infoblox-com'  (so an `infoblox-iq` stream
                       can route on this exactly)
    _csp_metric        the metric_name (cache_hit_ratio_iq, etc.)
    _csp_scope         'account' or 'host'
    _csp_host_label    when scope='host', the friendly label
    _csp_value         the numeric measurement
    _csp_bucket        ISO8601 timestamp of the cube bucket
"""

from __future__ import annotations

import json
import os
import ssl
import sys
import time
import traceback
from datetime import datetime, timedelta, timezone
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
CSP_HOST_UUID = os.environ.get("CSP_HOST_UUID", "").strip()
CSP_HOST_LABEL = os.environ.get("CSP_HOST_LABEL", "NIOS-X").strip()
CSP_BASE_URL = os.environ.get("CSP_BASE_URL", "https://csp.infoblox.com").rstrip("/")
CSP_LOOKBACK_MIN = int(os.environ.get("CSP_LOOKBACK_MIN", "60"))
GELF_URL = os.environ.get("GELF_URL", "http://127.0.0.1:12202/gelf")
STATE_PATH = Path(os.environ.get("CSP_STATE_PATH", "/var/lib/csp-poller/state.json"))
CSP_INSECURE = os.environ.get("CSP_INSECURE", "0") == "1"


# Metrics split by whether they're account-level (host='') or per-host.
ACCOUNT_METRICS = [
    "cache_hit_ratio_iq",
    "dns_qps_iq",
    "dns_nxdomain_percent_iq",
    "dns_servfail_percent_iq",
    "dns_refused_percent_iq",
    "dns_others_percent_iq",
    "dns_latency_upstream_iq",
    "ddns_ups_iq",
]
HOST_METRICS = [
    "host_cpu_iq",
    "host_memory_iq",
]


def _ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    if CSP_INSECURE:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def cube_query(query: dict) -> dict:
    """Issue a CubeJS query against the infra endpoint. Returns the parsed
    response. Raises on HTTP error."""
    payload = json.dumps(query, separators=(",", ":"))
    url = f"{CSP_BASE_URL}/api/cubejs/v1/query?query={parse.quote(payload)}"
    req = request.Request(
        url,
        headers={
            "Authorization": f"Token {CSP_API_KEY}",
            "Accept": "application/json",
            "User-Agent": "homelab-graylog-csp-poller/0.1",
        },
    )
    with request.urlopen(req, context=_ctx(), timeout=30) as r:
        return json.loads(r.read())


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


def _safe(label: str, fn) -> None:
    try:
        fn()
    except Exception:
        print(f"[{label}] failed:", file=sys.stderr)
        traceback.print_exc()


def load_state() -> dict:
    try:
        return json.loads(STATE_PATH.read_text())
    except FileNotFoundError:
        return {}


def save_state(state: dict) -> None:
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    STATE_PATH.write_text(json.dumps(state))


def iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def fetch_metric(metric_name: str, since: str, until: str,
                 *, host_uuid: str | None = None) -> list[dict]:
    """Fetch one metric_name (optionally filtered to a host UUID)
    returning the data rows."""
    and_filters: list[dict] = [
        {"member": "HostMetrics.metric_name", "operator": "equals",
         "values": [metric_name]},
    ]
    if host_uuid:
        and_filters.append(
            {"member": "HostMetrics.host", "operator": "equals",
             "values": [host_uuid]}
        )
    query = {
        "dimensions": ["HostMetrics.host", "HostMetrics.service"],
        "filters": [{"and": and_filters}],
        "measures": ["HostMetrics.avg_value", "HostMetrics.count_value"],
        "timeDimensions": [{
            "dimension": "HostMetrics.timestamp",
            "dateRange": [since, until],
            "granularity": "hour",
        }],
        "limit": 500,
    }
    resp = cube_query(query)
    if "error" in (resp.get("result") or {}) or "errors" in resp:
        raise RuntimeError(f"cubejs error for {metric_name}: "
                           f"{(resp.get('result') or {}).get('error') or resp.get('errors')}")
    return ((resp.get("result") or resp).get("data") or [])


def emit_rows(metric_name: str, rows: list[dict], scope: str) -> int:
    n = 0
    for row in rows:
        avg = row.get("HostMetrics.avg_value")
        cnt = row.get("HostMetrics.count_value")
        host = row.get("HostMetrics.host") or ""
        bucket = row.get("HostMetrics.timestamp") or ""
        if avg is None:
            continue
        gelf(
            f"CSP {metric_name} {scope}={CSP_HOST_LABEL if scope=='host' else 'account'}: {avg}",
            csp_metric=metric_name,
            csp_scope=scope,
            csp_host_uuid=host or None,
            csp_host_label=CSP_HOST_LABEL if scope == "host" else None,
            csp_value=float(avg),
            csp_count=int(cnt) if cnt is not None else None,
            csp_bucket=bucket,
        )
        n += 1
    return n


def main() -> None:
    state = load_state()
    now = time.time()
    until = iso(now)
    since = iso(now - CSP_LOOKBACK_MIN * 60)
    print(f"== csp poller {since} .. {until} ==")

    total = 0
    # Account-level metrics
    for m in ACCOUNT_METRICS:
        def go(m=m):
            global total
            rows = fetch_metric(m, since, until)
            n = emit_rows(m, rows, scope="account")
            print(f"  account {m}: {n} rows")
        _safe(f"account:{m}", go)

    # Per-host metrics
    if CSP_HOST_UUID:
        for m in HOST_METRICS:
            def go(m=m):
                rows = fetch_metric(m, since, until, host_uuid=CSP_HOST_UUID)
                n = emit_rows(m, rows, scope="host")
                print(f"  host {m}: {n} rows")
            _safe(f"host:{m}", go)
    else:
        print("  (CSP_HOST_UUID not set — skipping per-host metrics)")

    state["last_run"] = until
    save_state(state)
    print("done.")


if __name__ == "__main__":
    main()
