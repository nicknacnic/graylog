"""Cloudflare → Graylog (GELF HTTP) poller.

Pulls aggregated traffic, firewall, and DNS analytics for every zone on
the account, plus account-level audit events, and emits GELF messages
to the existing Graylog HTTP input on 127.0.0.1:12202. One systemd
timer fires this every 5 minutes.

Free-tier Cloudflare gotchas baked in:
  - Data is *aggregated*, not per-request. Time-series buckets are
    5-minutely with `httpRequests1mGroups` available but capped.
    httpRequestsAdaptiveGroups (the one Cloudflare actually keeps fresh)
    needs sampleInterval >= 60s; we ask for 5-minute windows.
  - Firewall events are per-event via `firewallEventsAdaptive`,
    available up to 30 days back on free.
  - Audit logs are account-level, per-event, via the REST endpoint.
  - Rate limit is roughly 1200 requests / 5 min per token. We make
    ~3 graphql calls per zone + 1 audit call per cycle, so we're fine
    until the user has hundreds of zones.

Env vars:
    CF_API_TOKEN        Bearer token (scoped: Zone Read + Analytics Read +
                        Firewall Services Read + Account Audit Logs Read)
    CF_ZONES            (optional) comma-separated zone-name override;
                        if unset, poller auto-discovers every zone on
                        the account via GET /zones.
    CF_LOOKBACK_S       (optional) default 360 (= 6 min, slight overlap
                        with the 5-min timer to avoid edge gaps)
    GELF_URL            default http://127.0.0.1:12202/gelf
    CF_STATE_PATH       default /var/lib/cf-poller/state.json — tracks
                        last-emitted firewall event Id + audit log
                        cursor per zone/account to dedupe across runs.
    CF_INSECURE         "1" to skip TLS verify (not needed for CF, but
                        kept for symmetry with the iLO/iDRAC pollers)

GELF messages:
    host                = "cloudflare-<zone-name>" for zone events,
                          "cloudflare-account" for account-level audits.
    _cf_event_type      categorical: requests_5m | firewall_event |
                                     dns_summary | audit_log | zone_info
    _cf_*               event-specific structured fields
"""

from __future__ import annotations

import json
import os
import ssl
import sys
import time
import traceback
from pathlib import Path
from typing import Any
from urllib import error, parse, request


def _env(name: str, default: str | None = None) -> str:
    v = os.environ.get(name, default)
    if v is None:
        print(f"ERROR: {name} not set", file=sys.stderr)
        sys.exit(2)
    return v


CF_API_TOKEN = _env("CF_API_TOKEN")
CF_ZONES_OVERRIDE = [z.strip() for z in os.environ.get("CF_ZONES", "").split(",") if z.strip()]
CF_LOOKBACK_S = int(os.environ.get("CF_LOOKBACK_S", "360"))
GELF_URL = os.environ.get("GELF_URL", "http://127.0.0.1:12202/gelf")
STATE_PATH = Path(os.environ.get("CF_STATE_PATH", "/var/lib/cf-poller/state.json"))
CF_INSECURE = os.environ.get("CF_INSECURE", "0") == "1"

CF_API = "https://api.cloudflare.com/client/v4"
CF_GQL = "https://api.cloudflare.com/client/v4/graphql"


def _ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    if CF_INSECURE:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def cf_get(path: str) -> Any:
    url = path if path.startswith("http") else CF_API + path
    req = request.Request(
        url,
        headers={
            "Authorization": f"Bearer {CF_API_TOKEN}",
            "Accept": "application/json",
        },
    )
    with request.urlopen(req, context=_ctx(), timeout=30) as r:
        return json.loads(r.read())


def cf_graphql(query: str, variables: dict | None = None) -> Any:
    body = json.dumps({"query": query, "variables": variables or {}}).encode()
    req = request.Request(
        CF_GQL, data=body, method="POST",
        headers={
            "Authorization": f"Bearer {CF_API_TOKEN}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        },
    )
    with request.urlopen(req, context=_ctx(), timeout=30) as r:
        resp = json.loads(r.read())
    if resp.get("errors"):
        # Surface the GraphQL error but don't kill the whole cycle —
        # one zone returning a permission error shouldn't take down the rest
        raise RuntimeError(f"GraphQL error: {resp['errors']}")
    return resp.get("data") or {}


def gelf(short_message: str, *, host: str, level: int = 6, **fields: Any) -> None:
    msg = {
        "version": "1.1",
        "host": host,
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


def _safe(label: str, fn):
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


def list_zones() -> list[dict]:
    if CF_ZONES_OVERRIDE:
        # Resolve each name to a zone object via the REST API
        out = []
        for name in CF_ZONES_OVERRIDE:
            resp = cf_get(f"/zones?name={parse.quote(name)}")
            for z in resp.get("result") or []:
                out.append(z)
        return out
    resp = cf_get("/zones?per_page=50")
    return resp.get("result") or []


def iso(ts: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


# ── polls ────────────────────────────────────────────────────────────────────

def poll_zone_info(zone: dict) -> None:
    """Emit one zone_info event per cycle so the dashboard inventory page
    always has fresh tenant metadata to display."""
    gelf(
        f"Zone {zone.get('name')}: status={zone.get('status')} plan={(zone.get('plan') or {}).get('name')}",
        host=f"cloudflare-{zone.get('name')}",
        cf_event_type="zone_info",
        cf_zone_id=zone.get("id"),
        cf_zone_name=zone.get("name"),
        cf_zone_status=zone.get("status"),
        cf_zone_paused=zone.get("paused"),
        cf_zone_type=zone.get("type"),
        cf_zone_plan=(zone.get("plan") or {}).get("name"),
        cf_zone_dev_mode=zone.get("development_mode"),
        cf_zone_name_servers=",".join(zone.get("name_servers") or []) or None,
    )


def poll_http_requests(zone: dict, start: str, end: str) -> None:
    """5-minute HTTP request buckets per zone via httpRequestsAdaptiveGroups.

    Emit one event per bucket. Dashboard groups on cf_zone_name +
    timestamp for trend lines, on cf_status for status-class breakdowns.
    """
    q = """
    query($zoneTag: String!, $start: Time!, $end: Time!) {
      viewer {
        zones(filter: {zoneTag: $zoneTag}) {
          httpRequestsAdaptiveGroups(
            limit: 100,
            filter: {datetime_geq: $start, datetime_lt: $end}
          ) {
            dimensions { datetime }
            sum {
              requests
              bytes
              cachedRequests
              cachedBytes
              encryptedRequests
            }
            avg { sampleInterval }
          }
        }
      }
    }
    """
    data = cf_graphql(q, {"zoneTag": zone["id"], "start": start, "end": end})
    zones = ((data.get("viewer") or {}).get("zones")) or []
    if not zones:
        return
    for g in (zones[0].get("httpRequestsAdaptiveGroups") or []):
        dim = g.get("dimensions") or {}
        s = g.get("sum") or {}
        gelf(
            f"HTTP {zone['name']} @ {dim.get('datetime')}: {s.get('requests')} req, {s.get('bytes')} B",
            host=f"cloudflare-{zone['name']}",
            cf_event_type="requests_5m",
            cf_zone_name=zone["name"],
            cf_bucket_datetime=dim.get("datetime"),
            cf_requests=s.get("requests"),
            cf_bytes=s.get("bytes"),
            cf_cached_requests=s.get("cachedRequests"),
            cf_cached_bytes=s.get("cachedBytes"),
            cf_encrypted_requests=s.get("encryptedRequests"),
            cf_sample_interval_s=(g.get("avg") or {}).get("sampleInterval"),
        )


def poll_http_by_status(zone: dict, start: str, end: str) -> None:
    """HTTP requests grouped by edge-response status — drives the
    "status code breakdown" pie + the bad-status alerting on the
    Threats page."""
    q = """
    query($zoneTag: String!, $start: Time!, $end: Time!) {
      viewer {
        zones(filter: {zoneTag: $zoneTag}) {
          httpRequestsAdaptiveGroups(
            limit: 200,
            filter: {datetime_geq: $start, datetime_lt: $end},
            orderBy: [sum_requests_DESC]
          ) {
            dimensions { edgeResponseStatus clientCountryName clientRequestHTTPHost }
            sum { requests }
          }
        }
      }
    }
    """
    data = cf_graphql(q, {"zoneTag": zone["id"], "start": start, "end": end})
    zones = ((data.get("viewer") or {}).get("zones")) or []
    if not zones:
        return
    for g in (zones[0].get("httpRequestsAdaptiveGroups") or []):
        dim = g.get("dimensions") or {}
        s = g.get("sum") or {}
        gelf(
            f"HTTP {zone['name']} {dim.get('edgeResponseStatus')} x{s.get('requests')} from {dim.get('clientCountryName')}",
            host=f"cloudflare-{zone['name']}",
            cf_event_type="requests_by_status",
            cf_zone_name=zone["name"],
            cf_status=dim.get("edgeResponseStatus"),
            cf_country=dim.get("clientCountryName"),
            cf_host=dim.get("clientRequestHTTPHost"),
            cf_requests=s.get("requests"),
        )


def poll_firewall_events(zone: dict, start: str, end: str, state: dict) -> None:
    """Per-event firewall log — the most useful "what's hitting me" feed.

    Dedupes on rayName since rayName is unique per event. Tracks the
    latest rayName per zone in state so re-fires don't re-emit.
    """
    q = """
    query($zoneTag: String!, $start: Time!, $end: Time!) {
      viewer {
        zones(filter: {zoneTag: $zoneTag}) {
          firewallEventsAdaptive(
            limit: 200,
            filter: {datetime_geq: $start, datetime_lt: $end},
            orderBy: [datetime_DESC]
          ) {
            action
            clientCountryName
            clientIP
            clientRequestHTTPHost
            clientRequestPath
            clientRequestQuery
            datetime
            rayName
            source
            userAgent
            ruleId
            kind
          }
        }
      }
    }
    """
    data = cf_graphql(q, {"zoneTag": zone["id"], "start": start, "end": end})
    zones = ((data.get("viewer") or {}).get("zones")) or []
    if not zones:
        return
    seen_key = f"fw_last_ray_{zone['id']}"
    last_seen = state.get(seen_key)
    new_max = last_seen
    events = sorted(zones[0].get("firewallEventsAdaptive") or [],
                    key=lambda e: e.get("datetime") or "")
    for ev in events:
        ray = ev.get("rayName")
        ts = ev.get("datetime")
        # Dedupe — Cloudflare gives no monotonic Id, so use (datetime, ray)
        # We track the latest datetime+ray combo as the high-water mark.
        marker = f"{ts}|{ray}"
        if last_seen and marker <= last_seen:
            continue
        action = ev.get("action") or "unknown"
        gelf(
            f"FW {zone['name']} {action} {ev.get('clientIP')} → {ev.get('clientRequestPath')}",
            host=f"cloudflare-{zone['name']}",
            level={"block": 4, "challenge": 5, "managed_challenge": 5,
                   "jschallenge": 5, "log": 6, "skip": 6, "allow": 6}.get(action, 6),
            cf_event_type="firewall_event",
            cf_zone_name=zone["name"],
            cf_fw_action=action,
            cf_fw_source=ev.get("source"),
            cf_fw_kind=ev.get("kind"),
            cf_fw_rule_id=ev.get("ruleId"),
            cf_fw_ray=ray,
            cf_fw_datetime=ts,
            cf_client_ip=ev.get("clientIP"),
            cf_client_country=ev.get("clientCountryName"),
            cf_fw_host=ev.get("clientRequestHTTPHost"),
            cf_fw_path=ev.get("clientRequestPath"),
            cf_fw_query=ev.get("clientRequestQuery"),
            cf_user_agent=ev.get("userAgent"),
        )
        if not new_max or marker > new_max:
            new_max = marker
    if new_max and new_max != last_seen:
        state[seen_key] = new_max


def poll_dns(zone: dict, start: str, end: str) -> None:
    """DNS query analytics. Only available if the zone is on
    Cloudflare's DNS (i.e. you've delegated NS records). Free."""
    q = """
    query($zoneTag: String!, $start: Time!, $end: Time!) {
      viewer {
        zones(filter: {zoneTag: $zoneTag}) {
          dnsAnalyticsAdaptiveGroups(
            limit: 200,
            filter: {datetime_geq: $start, datetime_lt: $end}
          ) {
            dimensions { datetime queryType responseCode }
            sum { queries }
          }
        }
      }
    }
    """
    try:
        data = cf_graphql(q, {"zoneTag": zone["id"], "start": start, "end": end})
    except RuntimeError as e:
        # Common when the zone isn't using CF DNS — fail soft
        msg = str(e)
        if "dnsAnalyticsAdaptiveGroups" in msg or "not authorized" in msg.lower():
            return
        raise
    zones = ((data.get("viewer") or {}).get("zones")) or []
    if not zones:
        return
    for g in (zones[0].get("dnsAnalyticsAdaptiveGroups") or []):
        dim = g.get("dimensions") or {}
        s = g.get("sum") or {}
        gelf(
            f"DNS {zone['name']} {dim.get('queryType')} {dim.get('responseCode')} x{s.get('queries')}",
            host=f"cloudflare-{zone['name']}",
            cf_event_type="dns_summary",
            cf_zone_name=zone["name"],
            cf_bucket_datetime=dim.get("datetime"),
            cf_dns_query_type=dim.get("queryType"),
            cf_dns_response_code=dim.get("responseCode"),
            cf_dns_queries=s.get("queries"),
        )


def poll_audit_logs(start: str, state: dict) -> None:
    """Account-level audit events (config changes). Dedupes on event Id.

    Uses the REST API — there's a GraphQL endpoint for this too but the
    REST one returns more fields and is easier to page."""
    # Get list of accounts the token can see
    try:
        accounts = (cf_get("/accounts") or {}).get("result") or []
    except error.HTTPError as e:
        if e.code in (401, 403):
            return  # token doesn't have Account scope — that's fine, audit is optional
        raise
    for acc in accounts:
        acc_id = acc["id"]
        last_seen_key = f"audit_last_id_{acc_id}"
        last_seen = state.get(last_seen_key)
        # Filter by since=start; CF returns up to 25 per page
        path = f"/accounts/{acc_id}/audit_logs?since={parse.quote(start)}&per_page=25"
        try:
            resp = cf_get(path)
        except error.HTTPError as e:
            if e.code in (401, 403):
                continue
            raise
        new_max = last_seen
        for ev in reversed(resp.get("result") or []):  # oldest first
            eid = ev.get("id")
            if last_seen and eid == last_seen:
                # We've caught up
                break
            actor = (ev.get("actor") or {}).get("email")
            resource = (ev.get("resource") or {}).get("type")
            action = (ev.get("action") or {}).get("type")
            gelf(
                f"AUDIT {actor} {action} {resource}",
                host="cloudflare-account",
                level=5,
                cf_event_type="audit_log",
                cf_account_id=acc_id,
                cf_account_name=acc.get("name"),
                cf_audit_id=eid,
                cf_audit_when=ev.get("when"),
                cf_audit_actor=actor,
                cf_audit_actor_type=(ev.get("actor") or {}).get("type"),
                cf_audit_actor_ip=(ev.get("actor") or {}).get("ip"),
                cf_audit_action=action,
                cf_audit_resource_type=resource,
                cf_audit_resource_id=(ev.get("resource") or {}).get("id"),
            )
            if not new_max:
                new_max = eid
        # Mark the newest event we saw as the watermark (CF returns newest-first)
        first_event = (resp.get("result") or [{}])[0]
        if first_event.get("id"):
            state[last_seen_key] = first_event["id"]


# ── entry point ─────────────────────────────────────────────────────────────

def main() -> None:
    now = time.time()
    start_ts = now - CF_LOOKBACK_S
    start = iso(start_ts)
    end = iso(now)
    state = load_state()

    print(f"== cloudflare poller {start} .. {end} ==")
    zones = list_zones()
    print(f"  zones: {[z['name'] for z in zones]}")

    for zone in zones:
        _safe(f"{zone['name']}:zone_info",    lambda z=zone: poll_zone_info(z))
        _safe(f"{zone['name']}:http",         lambda z=zone: poll_http_requests(z, start, end))
        _safe(f"{zone['name']}:http_status",  lambda z=zone: poll_http_by_status(z, start, end))
        _safe(f"{zone['name']}:firewall",     lambda z=zone: poll_firewall_events(z, start, end, state))
        _safe(f"{zone['name']}:dns",          lambda z=zone: poll_dns(z, start, end))

    _safe("audit_logs", lambda: poll_audit_logs(start, state))
    save_state(state)
    print("done.")


if __name__ == "__main__":
    main()
