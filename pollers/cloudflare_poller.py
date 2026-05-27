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


def gelf(short_message: str, *, host: str, level: int = 6,
         timestamp: float | None = None, **fields: Any) -> None:
    msg = {
        "version": "1.1",
        "host": host,
        "short_message": short_message[:1024],
        "level": level,
        "timestamp": timestamp if timestamp is not None else time.time(),
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

    Schema gotcha (introspected against live CF 2026-05 schema): the
    request total is the top-level `count` field, NOT `sum.requests`
    (which doesn't exist). `sum` holds `edgeRequestBytes`,
    `edgeResponseBytes`, `visits`, and various detection arrays.
    `cacheStatus` is a dimension; we get cache breakdown via grouping
    on it rather than as a sum.
    """
    q = """
    query($zoneTag: String!, $start: Time!, $end: Time!) {
      viewer {
        zones(filter: {zoneTag: $zoneTag}) {
          httpRequestsAdaptiveGroups(
            limit: 100,
            filter: {datetime_geq: $start, datetime_lt: $end}
          ) {
            dimensions { datetime cacheStatus }
            count
            sum {
              visits
              edgeRequestBytes
              edgeResponseBytes
            }
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
            f"HTTP {zone['name']} @ {dim.get('datetime')} {dim.get('cacheStatus')}: {g.get('count')} req, {s.get('edgeResponseBytes')} B",
            host=f"cloudflare-{zone['name']}",
            cf_event_type="requests_5m",
            cf_zone_name=zone["name"],
            cf_bucket_datetime=dim.get("datetime"),
            cf_cache_status=dim.get("cacheStatus"),
            cf_requests=g.get("count"),
            cf_visits=s.get("visits"),
            cf_request_bytes=s.get("edgeRequestBytes"),
            cf_response_bytes=s.get("edgeResponseBytes"),
        )


def poll_http_by_host(zone: dict, start: str, end: str) -> None:
    """5-minute HTTP request buckets broken out by hostname.

    Same shape as poll_http_requests but adds clientRequestHTTPHost as
    a dimension so the dashboard's Traffic page can split www vs ans
    vs apex etc. Emits cf_event_type=requests_host_5m with
    cf_request_host so the per-host events live alongside the
    aggregate requests_5m events without interleaving on `cf_requests`
    sums (queries on the page filter on the event_type).
    """
    q = """
    query($zoneTag: String!, $start: Time!, $end: Time!) {
      viewer {
        zones(filter: {zoneTag: $zoneTag}) {
          httpRequestsAdaptiveGroups(
            limit: 200,
            filter: {datetime_geq: $start, datetime_lt: $end},
            orderBy: [count_DESC]
          ) {
            dimensions { datetime clientRequestHTTPHost }
            count
            sum {
              visits
              edgeRequestBytes
              edgeResponseBytes
            }
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
        host = (dim.get("clientRequestHTTPHost") or "").lower() or "-"
        gelf(
            f"HTTP-HOST {zone['name']} {host} @ {dim.get('datetime')}: {g.get('count')} req",
            host=f"cloudflare-{zone['name']}",
            cf_event_type="requests_host_5m",
            cf_zone_name=zone["name"],
            cf_request_host=host,
            cf_bucket_datetime=dim.get("datetime"),
            cf_requests=g.get("count"),
            cf_visits=s.get("visits"),
            cf_request_bytes=s.get("edgeRequestBytes"),
            cf_response_bytes=s.get("edgeResponseBytes"),
        )


def poll_http_by_status(zone: dict, start: str, end: str) -> None:
    """HTTP requests grouped by edge-response status — drives the
    "status code breakdown" pie + the bad-status alerting on the
    Threats page.

    orderBy uses count_DESC (the request-count aggregator), not
    sum_requests_DESC (which isn't a valid enum value on this schema)."""
    q = """
    query($zoneTag: String!, $start: Time!, $end: Time!) {
      viewer {
        zones(filter: {zoneTag: $zoneTag}) {
          httpRequestsAdaptiveGroups(
            limit: 200,
            filter: {datetime_geq: $start, datetime_lt: $end},
            orderBy: [count_DESC]
          ) {
            dimensions { edgeResponseStatus clientCountryName clientRequestHTTPHost }
            count
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
        gelf(
            f"HTTP {zone['name']} {dim.get('edgeResponseStatus')} x{g.get('count')} from {dim.get('clientCountryName')}",
            host=f"cloudflare-{zone['name']}",
            cf_event_type="requests_by_status",
            cf_zone_name=zone["name"],
            cf_status=dim.get("edgeResponseStatus"),
            cf_country=dim.get("clientCountryName"),
            cf_host=dim.get("clientRequestHTTPHost"),
            cf_requests=g.get("count"),
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
    try:
        data = cf_graphql(q, {"zoneTag": zone["id"], "start": start, "end": end})
    except RuntimeError as e:
        # CF gates firewallEventsAdaptive behind a different token
        # permission than httpRequestsAdaptiveGroups — effectively
        # "Account Analytics: Read" rather than just "Zone Analytics: Read".
        # Fail soft so the rest of the cycle still emits.
        if "not authorized" in str(e).lower() or "does not have permission" in str(e).lower():
            return
        raise
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
    Cloudflare's DNS (i.e. you've delegated NS records). Free.

    Schema gotcha: like httpRequestsAdaptiveGroups, the query total is
    the top-level `count` field, not `sum.queries` (which doesn't exist).
    `sum` only carries `countNotCachedAndNotStale` and `countStale`."""
    q = """
    query($zoneTag: String!, $start: Time!, $end: Time!) {
      viewer {
        zones(filter: {zoneTag: $zoneTag}) {
          dnsAnalyticsAdaptiveGroups(
            limit: 200,
            filter: {datetime_geq: $start, datetime_lt: $end}
          ) {
            dimensions { datetime queryType responseCode }
            count
            sum {
              countNotCachedAndNotStale
              countStale
            }
          }
        }
      }
    }
    """
    try:
        data = cf_graphql(q, {"zoneTag": zone["id"], "start": start, "end": end})
    except RuntimeError as e:
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
            f"DNS {zone['name']} {dim.get('queryType')} {dim.get('responseCode')} x{g.get('count')}",
            host=f"cloudflare-{zone['name']}",
            cf_event_type="dns_summary",
            cf_zone_name=zone["name"],
            cf_bucket_datetime=dim.get("datetime"),
            cf_dns_query_type=dim.get("queryType"),
            cf_dns_response_code=dim.get("responseCode"),
            cf_dns_queries=g.get("count"),
            cf_dns_uncached=s.get("countNotCachedAndNotStale"),
            cf_dns_stale=s.get("countStale"),
        )


# Agents to track separately on the dashboard. Each entry's flat FQDN
# is the canonical owner; the poller groups DNS analytics by queryName
# (which CF stores without the trailing dot, lowercased) so we get per-
# agent + per-resolver query counts.
#
# The set comes from src/posts/2026-05-14-five-fake-agents-real-dns.md:
# 5 agents × (flat SVCB + walkable _agents AliasMode + _443._tcp TLSA),
# plus endpoint A and index._agents TXT.
AGENT_FQDNS = [
    # flat ServiceMode SVCB owners
    "search.darknetian.com",
    "bookings.darknetian.com",
    "threat-intel.darknetian.com",
    "dns-audit.darknetian.com",
    "morpheus.darknetian.com",
    # walkable AliasMode SVCB
    "search._agents.darknetian.com",
    "bookings._agents.darknetian.com",
    "threat-intel._agents.darknetian.com",
    "dns-audit._agents.darknetian.com",
    "morpheus._agents.darknetian.com",
    # TLSA DANE pins
    "_443._tcp.search.darknetian.com",
    "_443._tcp.bookings.darknetian.com",
    "_443._tcp.threat-intel.darknetian.com",
    "_443._tcp.dns-audit.darknetian.com",
    "_443._tcp.morpheus.darknetian.com",
    # org index + canonical endpoint. Both forms of the index leaf are
    # in DNS — `_index._agents` is the canonical -02 name (leading
    # underscore per the IANA underscored-node-names registration);
    # `index._agents` is kept as a back-compat alias for clients on
    # earlier drafts. _agent_name_from_qname() collapses both to
    # cf_dns_agent="index".
    "_index._agents.darknetian.com",
    "index._agents.darknetian.com",
    "endpoint.darknetian.com",
    # ANS (Agent Name Service) transparency-log records — added 2026-05-15
    # per src/posts/2026-05-15-the-thing-the-index-points-to.md. The TL
    # host is queried by anything resolving the path-2 index leaf above
    # (which targets it via SVCB).
    "ans.darknetian.com",
]


def _agent_name_from_qname(qname: str) -> str | None:
    """Extract the agent name from a query name. Returns one of
    'search', 'bookings', 'threat-intel', 'dns-audit', 'morpheus',
    'ans' (the transparency-log host), 'index' (the path-2 index
    SVCB leaf — broken out separately so the dashboard's per-agent
    table shows index discovery distinctly from ans-host hits), or
    None if the qname is unrelated."""
    q = (qname or "").lower().rstrip(".")
    if not q.endswith(".darknetian.com"):
        return None
    if q == "ans.darknetian.com":
        return "ans"
    if q == "index._agents.darknetian.com" or q == "_index._agents.darknetian.com":
        return "index"
    for agent in ("search", "bookings", "threat-intel", "dns-audit", "morpheus"):
        # Matches: <agent>.darknetian.com, <agent>._agents.darknetian.com,
        # _443._tcp.<agent>.darknetian.com
        if q == f"{agent}.darknetian.com" \
           or q == f"{agent}._agents.darknetian.com" \
           or q == f"_443._tcp.{agent}.darknetian.com":
            return agent
    return None


def poll_dns_nxdomain(zone: dict, start: str, end: str) -> None:
    """NXDOMAIN-only DNS analytics with queryName included. Kept as a
    separate poll so the main `poll_dns` summary stays low-cardinality
    (no queryName), while this one — gated to responseCode=NXDOMAIN —
    is naturally narrow (failing names are typically a small set)."""
    q = """
    query($zoneTag: String!, $start: Time!, $end: Time!) {
      viewer {
        zones(filter: {zoneTag: $zoneTag}) {
          dnsAnalyticsAdaptiveGroups(
            limit: 200,
            filter: {datetime_geq: $start, datetime_lt: $end,
                     responseCode: "NXDOMAIN"},
            orderBy: [count_DESC]
          ) {
            dimensions { queryName queryType }
            count
          }
        }
      }
    }
    """
    try:
        data = cf_graphql(q, {"zoneTag": zone["id"], "start": start, "end": end})
    except RuntimeError as e:
        if "not authorized" in str(e).lower():
            return
        raise
    zones = ((data.get("viewer") or {}).get("zones")) or []
    if not zones:
        return
    for g in (zones[0].get("dnsAnalyticsAdaptiveGroups") or []):
        dim = g.get("dimensions") or {}
        gelf(
            f"DNS-NX {zone['name']} {dim.get('queryName')} {dim.get('queryType')} x{g.get('count')}",
            host=f"cloudflare-{zone['name']}",
            cf_event_type="dns_nxdomain",
            cf_zone_name=zone["name"],
            cf_dns_query_name=dim.get("queryName"),
            cf_dns_query_type=dim.get("queryType"),
            cf_dns_response_code="NXDOMAIN",
            cf_dns_queries=g.get("count"),
        )


def poll_dns_agents(zone: dict, start: str, end: str) -> None:
    """Per-(queryName, sourceIP) DNS analytics filtered to the 17 agent
    records on darknetian.com. Drives the 'Agents' dashboard page —
    query volume per agent + per-resolver tables, plus cardinality of
    resolvers as a proxy for unique-visitor count.

    Caveat: sourceIP on authoritative DNS is the *recursive resolver*,
    not the end-user. So 'unique visitor count' here is really 'unique
    recursive resolver count' — useful as a relative signal but not
    a literal user count. This is documented on the dashboard.

    Only fires on the darknetian.com zone; bails for any other zone."""
    if zone.get("name") != "darknetian.com":
        return
    q = """
    query($zoneTag: String!, $start: Time!, $end: Time!, $names: [String!]) {
      viewer {
        zones(filter: {zoneTag: $zoneTag}) {
          dnsAnalyticsAdaptiveGroups(
            limit: 500,
            filter: {datetime_geq: $start, datetime_lt: $end, queryName_in: $names},
            orderBy: [count_DESC]
          ) {
            dimensions { queryName queryType responseCode sourceIP }
            count
          }
        }
      }
    }
    """
    try:
        data = cf_graphql(q, {"zoneTag": zone["id"], "start": start, "end": end,
                              "names": AGENT_FQDNS})
    except RuntimeError as e:
        if "not authorized" in str(e).lower() or "does not have permission" in str(e).lower():
            return
        raise
    zones = ((data.get("viewer") or {}).get("zones")) or []
    if not zones:
        return
    for g in (zones[0].get("dnsAnalyticsAdaptiveGroups") or []):
        dim = g.get("dimensions") or {}
        qname = dim.get("queryName")
        agent = _agent_name_from_qname(qname)
        gelf(
            f"DNS-AGENT {agent or 'other'} {qname} {dim.get('queryType')} {dim.get('responseCode')} x{g.get('count')}",
            host=f"cloudflare-{zone['name']}",
            cf_event_type="dns_agent",
            cf_zone_name=zone["name"],
            cf_dns_agent=agent,
            cf_dns_query_name=qname,
            cf_dns_query_type=dim.get("queryType"),
            cf_dns_response_code=dim.get("responseCode"),
            cf_dns_source_ip=dim.get("sourceIP"),
            cf_dns_queries=g.get("count"),
        )


def poll_workers_invocations(start: str, end: str) -> None:
    """Per-script-per-hour-per-status invocation metrics for every
    Workers script on every account the token can see.

    Source: workersInvocationsAdaptive on the account-level GraphQL
    endpoint. Carries request count, error count, subrequest count,
    p50/p99 cpu+wall time per (script × hour × status). Doesn't carry
    per-call detail (model, token counts, which tool) — for that the
    worker would write to Workers Analytics Engine and we'd add a
    separate poller.

    Each (script × hour × status) group becomes one GELF event with
    cf_event_type=worker_invocations.
    """
    try:
        accounts = (cf_get("/accounts") or {}).get("result") or []
    except error.HTTPError as e:
        if e.code in (401, 403):
            return
        raise

    q = """
    query($acct: String!, $s: Time!, $e: Time!) {
      viewer {
        accounts(filter: {accountTag: $acct}) {
          workersInvocationsAdaptive(
            limit: 1000,
            filter: {datetime_geq: $s, datetime_lt: $e},
            orderBy: [datetimeHour_DESC]
          ) {
            dimensions { datetimeHour scriptName status }
            sum       { requests subrequests errors duration }
            quantiles { cpuTimeP50 cpuTimeP99 wallTimeP50 wallTimeP99 }
          }
        }
      }
    }
    """
    for acc in accounts:
        acc_id = acc["id"]
        try:
            data = cf_graphql(q, {"acct": acc_id, "s": start, "e": end})
        except error.HTTPError as e:
            if e.code in (401, 403):
                continue
            raise
        accs = ((data.get("viewer") or {}).get("accounts")) or []
        if not accs:
            continue
        for g in (accs[0].get("workersInvocationsAdaptive") or []):
            dim = g.get("dimensions") or {}
            sm = g.get("sum") or {}
            qt = g.get("quantiles") or {}
            script = dim.get("scriptName") or "?"
            gelf(
                f"WORKER {script} @ {dim.get('datetimeHour')} {dim.get('status')}: "
                f"{sm.get('requests')} req, {sm.get('errors')} err",
                host=f"cloudflare-worker-{script}",
                cf_event_type="worker_invocations",
                cf_account_id=acc_id,
                cf_account_name=acc.get("name"),
                cf_worker_script=script,
                cf_worker_status=dim.get("status"),
                cf_bucket_datetime=dim.get("datetimeHour"),
                cf_worker_requests=sm.get("requests"),
                cf_worker_subrequests=sm.get("subrequests"),
                cf_worker_errors=sm.get("errors"),
                cf_worker_duration_sum=sm.get("duration"),
                cf_worker_cpu_p50_us=qt.get("cpuTimeP50"),
                cf_worker_cpu_p99_us=qt.get("cpuTimeP99"),
                cf_worker_wall_p50_us=qt.get("wallTimeP50"),
                cf_worker_wall_p99_us=qt.get("wallTimeP99"),
            )


# ── Anthropic per-million-token pricing (USD) ────────────────────────────
# Used to compute ant_usd_delta on each AE event. Update when Anthropic
# changes prices — current as of 2026-05. Cache-creation pricing uses
# the 5m ephemeral rate (the cheaper of 5m vs 1h); 1h would be ~2x.
ANT_PRICING = {
    "claude-opus-4-7":   {"in": 15.00, "out": 75.00, "cache_read": 1.50, "cache_create": 18.75},
    "claude-opus-4-6":   {"in": 15.00, "out": 75.00, "cache_read": 1.50, "cache_create": 18.75},
    "claude-sonnet-4-6": {"in":  3.00, "out": 15.00, "cache_read": 0.30, "cache_create":  3.75},
    "claude-sonnet-4-5": {"in":  3.00, "out": 15.00, "cache_read": 0.30, "cache_create":  3.75},
    "claude-haiku-4-5":  {"in":  0.80, "out":  4.00, "cache_read": 0.08, "cache_create":  1.00},
    "_default":          {"in":  3.00, "out": 15.00, "cache_read": 0.30, "cache_create":  3.75},
}

# Optional: user-set monthly budget so the dashboard can render
# "credits remaining" (Anthropic doesn't expose a balance API on
# personal/self-serve plans — operator updates this manually on top-up).
ANTHROPIC_BUDGET_USD = float(os.environ.get("ANTHROPIC_BUDGET_USD", "0") or 0)


def _ant_usd(model: str, in_tok: int, out_tok: int,
             cr_tok: int, cc_tok: int) -> float:
    p = ANT_PRICING.get(model) or ANT_PRICING["_default"]
    return ((in_tok * p["in"]) + (out_tok * p["out"])
            + (cr_tok * p["cache_read"]) + (cc_tok * p["cache_create"])) / 1_000_000.0


def poll_workers_ae(state: dict) -> None:
    """Per-call detail from Workers Analytics Engine — the
    `anthropic_calls` dataset the darknetian-bookings worker writes to
    via env.AE.writeDataPoint after each CMA session turn.

    AE GraphQL only exposes account-level aggregates (no blob/double
    slicing — that endpoint is built for high-level admin views), so
    we hit the SQL API. Each row is one
      (model, surface, tool, session_id, stop_reason)
    group within the last 24h, with token + latency aggregates.

    Token values are CUMULATIVE per CMA session — the same session
    polled later returns growing totals. Re-emit absolutes every
    cycle; the dashboard uses latest(input_tokens) per session_id for
    current state, and max(... per session) summed across sessions
    for org-level day totals.
    """
    try:
        accounts = (cf_get("/accounts") or {}).get("result") or []
    except error.HTTPError as e:
        if e.code in (401, 403):
            return
        raise
    if not accounts:
        return
    acct_id = accounts[0]["id"]

    # blob6 = worker name (darknetian-bookings / darknetian-morpheus / …).
    # Older rows from bookings (written before the snippet adopted blob6)
    # have blob6 = "" — coalesce to "bookings" so they don't fall into a
    # ghost "" group; downstream dashboards filter on ant_worker.
    sql = (
        "SELECT "
        "blob1 AS model, "
        "blob2 AS surface, "
        "blob3 AS tool, "
        "blob4 AS session_id, "
        "blob5 AS stop_reason, "
        "if(empty(blob6), 'bookings', blob6) AS worker, "
        # Tokens are CUMULATIVE per CMA session — each writeDataPoint
        # call records the session's running total to date, NOT the
        # turn delta. With GROUP BY blob4 (session_id), MAX(doubleN)
        # = final cumulative for that session. Using SUM here would
        # compound every prior turn's cumulative into the total
        # (e.g. cum=[100,250,400] → SUM=750 vs actual=400) and
        # inflate the USD-spend delta math downstream by ~3-25x
        # depending on average turns/session.
        "MAX(double1) AS input_tokens, "
        "MAX(double2) AS output_tokens, "
        "MAX(double3) AS cache_read, "
        "MAX(double4) AS cache_create, "
        "AVG(double5) AS avg_latency_ms, "
        "MAX(double5) AS max_latency_ms, "
        "COUNT() AS samples, "
        "MAX(timestamp) AS last_seen "
        "FROM anthropic_calls "
        "WHERE timestamp > NOW() - INTERVAL '24' HOUR "
        "  AND NOT startsWith(blob1, '_event:') "  # exclude sentinel events (DCV, etc.)
        "GROUP BY blob1, blob2, blob3, blob4, blob5, worker "
        "FORMAT JSON"
    )
    url = f"https://api.cloudflare.com/client/v4/accounts/{acct_id}/analytics_engine/sql"
    req = request.Request(url, data=sql.encode(), headers={
        "Authorization": f"Bearer {CF_API_TOKEN}",
        "Content-Type": "text/plain",
    })
    try:
        with request.urlopen(req, timeout=30) as r:
            body = json.loads(r.read())
    except error.HTTPError as e:
        snippet = e.read().decode("utf-8", "replace")[:200]
        print(f"AE SQL error {e.code}: {snippet}", file=sys.stderr)
        return

    rows = body.get("data") or []

    # If ANTHROPIC_BUDGET_USD just changed (or this is the first run
    # with state), bootstrap session baselines from the current AE
    # snapshot WITHOUT emitting events. The tokens already accumulated
    # by each session before this moment are already reflected in the
    # operator-observed Console balance — we only want to track NEW
    # spend from here forward against that balance.
    last_known_budget = float(state.get("ae_last_budget_usd") or 0)
    budget_just_set = (ANTHROPIC_BUDGET_USD > 0
                       and abs(ANTHROPIC_BUDGET_USD - last_known_budget) > 1e-6)
    if budget_just_set:
        baseline: dict[str, dict] = {}
        for r in rows:
            sid_key = f"{r.get('worker') or 'bookings'}:{r.get('session_id') or ''}"
            baseline[sid_key] = {
                "in":  int(r.get("input_tokens") or 0),
                "out": int(r.get("output_tokens") or 0),
                "cr":  int(r.get("cache_read") or 0),
                "cc":  int(r.get("cache_create") or 0),
            }
        state["ae_sessions"] = baseline
        state["ae_last_budget_usd"] = ANTHROPIC_BUDGET_USD
        state["ae_spent_since_budget_usd"] = 0.0
        gelf(
            f"BUDGET ${ANTHROPIC_BUDGET_USD:.2f} starting baseline "
            f"(session snapshot only — no spend events this cycle)",
            host="cloudflare-anthropic",
            cf_event_type="anthropic_budget",
            ant_budget_usd=ANTHROPIC_BUDGET_USD,
            ant_budget_spent_cum_usd=0.0,
            ant_budget_remaining_usd=ANTHROPIC_BUDGET_USD,
        )
        print(f"  AE budget set to ${ANTHROPIC_BUDGET_USD:.2f} — "
              f"baselined {len(baseline)} sessions, emitted 0 spend events")
        return

    seen = state.get("ae_sessions") or {}
    new_seen: dict[str, dict] = {}
    total_usd_delta = 0.0

    for r in rows:
        # last_seen is ClickHouse DateTime ("YYYY-MM-DD HH:MM:SS")
        # — convert to epoch float so the GELF event lands at the
        # observed time, not poll time.
        ts = None
        try:
            from datetime import datetime as _dt, timezone as _tz
            ls = r.get("last_seen") or ""
            if ls:
                ts = _dt.strptime(ls, "%Y-%m-%d %H:%M:%S").replace(tzinfo=_tz.utc).timestamp()
        except Exception:
            ts = None

        worker = r.get("worker") or "bookings"
        sid_raw = r.get("session_id") or ""
        # Namespace state by worker so morpheus + bookings can't collide
        # if (extremely unlikely) they ever happen to mint the same
        # session id literal.
        sid_key = f"{worker}:{sid_raw}"
        cur = {
            "in":  int(r.get("input_tokens") or 0),
            "out": int(r.get("output_tokens") or 0),
            "cr":  int(r.get("cache_read") or 0),
            "cc":  int(r.get("cache_create") or 0),
        }
        new_seen[sid_key] = cur

        last = seen.get(sid_key) or {"in": 0, "out": 0, "cr": 0, "cc": 0}
        delta = {k: max(0, cur[k] - last[k]) for k in cur}
        # If nothing new for a session we've already seen, skip — avoids
        # re-emitting cumulative totals on every poll (which would
        # inflate sum() widgets). First-time observations: delta = full
        # cumulative, which is correct.
        if sid_key in seen and sum(delta.values()) == 0:
            continue

        model = r.get("model") or ""
        usd_delta = _ant_usd(model, delta["in"], delta["out"],
                             delta["cr"], delta["cc"])
        total_usd_delta += usd_delta

        gelf(
            f"AE {worker} {model} {r.get('surface','?')} "
            f"{(r.get('tool') or '(none)')} sess={sid_raw[:14]}.. "
            f"Δin={delta['in']} Δout={delta['out']} "
            f"${usd_delta:.4f} ms={r.get('avg_latency_ms') or 0:.0f}",
            host=f"cloudflare-worker-darknetian-{worker}",
            timestamp=ts,
            cf_event_type="anthropic_call",
            ant_worker=worker,
            ant_model=model,
            ant_surface=r.get("surface"),
            ant_tool=r.get("tool") or "(none)",
            ant_session_id=sid_raw,
            ant_stop_reason=r.get("stop_reason"),
            # Cumulative (for latest()-per-session widgets)
            ant_input_tokens=cur["in"],
            ant_output_tokens=cur["out"],
            ant_cache_read_tokens=cur["cr"],
            ant_cache_creation_tokens=cur["cc"],
            # Delta since last poll (for sum() widgets — no double-count)
            ant_input_tokens_delta=delta["in"],
            ant_output_tokens_delta=delta["out"],
            ant_cache_read_tokens_delta=delta["cr"],
            ant_cache_creation_tokens_delta=delta["cc"],
            ant_usd_delta=round(usd_delta, 6),
            ant_avg_latency_ms=r.get("avg_latency_ms"),
            ant_max_latency_ms=r.get("max_latency_ms"),
            ant_samples=r.get("samples"),
            ant_last_seen=r.get("last_seen"),
        )

    # Drop sessions that didn't appear in this cycle (they've aged out
    # of AE's 24h window and won't come back). Bounded growth.
    state["ae_sessions"] = new_seen

    # Budget tracking — emit a fresh snapshot every cycle. The
    # bootstrap branch at the top of the function handles env-changes
    # and first runs; here we just accumulate forward.
    if ANTHROPIC_BUDGET_USD > 0:
        spent_since = float(state.get("ae_spent_since_budget_usd") or 0)
        spent_since += total_usd_delta
        state["ae_spent_since_budget_usd"] = spent_since
        remaining = ANTHROPIC_BUDGET_USD - spent_since
        gelf(
            f"BUDGET ${ANTHROPIC_BUDGET_USD:.2f} starting, "
            f"spent ${spent_since:.4f}, remaining ${remaining:.4f}",
            host="cloudflare-anthropic",
            cf_event_type="anthropic_budget",
            ant_budget_usd=ANTHROPIC_BUDGET_USD,
            ant_budget_spent_cum_usd=round(spent_since, 6),
            ant_budget_remaining_usd=round(remaining, 6),
        )


def poll_morpheus_probes() -> None:
    """One AE write per probe tool invocation — captures the domain
    being audited (which the regular per-call telemetry doesn't, since
    blobs1-5 only carry model/surface/tool/session/stop_reason).

    Worker-side schema (must stay in sync with src/observability):
      blob1 = "_event:probe"   (sentinel)
      blob2 = domain           (input.zone / input.host / input.domain)
      blob3 = probe            ("dns_aid_index" / "tls_handshake_audit" / …)
      blob4 = session_id
      blob5 = result_summary   ("pass" | "warn" | "fail" | "error")
      blob6 = "morpheus"
      double1 = findings.pass count
      double2 = findings.warn count
      double3 = findings.fail count
      double4 = findings.error count
      double5 = latency_ms (per-probe wall time)
    """
    try:
        accounts = (cf_get("/accounts") or {}).get("result") or []
    except error.HTTPError as e:
        if e.code in (401, 403):
            return
        raise
    if not accounts:
        return
    acct_id = accounts[0]["id"]

    sql = (
        "SELECT "
        "blob2 AS domain, "
        "blob3 AS probe, "
        "blob4 AS session_id, "
        "blob5 AS result_summary, "
        "SUM(_sample_interval * double1) AS findings_pass, "
        "SUM(_sample_interval * double2) AS findings_warn, "
        "SUM(_sample_interval * double3) AS findings_fail, "
        "SUM(_sample_interval * double4) AS findings_error, "
        "AVG(double5) AS avg_latency_ms, "
        "COUNT() AS invocations, "
        "MAX(timestamp) AS last_seen "
        "FROM anthropic_calls "
        "WHERE timestamp > NOW() - INTERVAL '24' HOUR "
        "  AND blob1 = '_event:probe' "
        "  AND blob6 = 'morpheus' "
        "GROUP BY blob2, blob3, blob4, blob5 "
        "ORDER BY last_seen DESC "
        "FORMAT JSON"
    )
    url = f"https://api.cloudflare.com/client/v4/accounts/{acct_id}/analytics_engine/sql"
    req = request.Request(url, data=sql.encode(), headers={
        "Authorization": f"Bearer {CF_API_TOKEN}",
        "Content-Type": "text/plain",
    })
    try:
        with request.urlopen(req, timeout=30) as r:
            body = json.loads(r.read())
    except error.HTTPError as e:
        snippet = e.read().decode("utf-8", "replace")[:200]
        print(f"AE probe SQL error {e.code}: {snippet}", file=sys.stderr)
        return

    rows = body.get("data") or []
    for r in rows:
        ts = None
        try:
            from datetime import datetime as _dt, timezone as _tz
            ls = r.get("last_seen") or ""
            if ls:
                ts = _dt.strptime(ls, "%Y-%m-%d %H:%M:%S").replace(tzinfo=_tz.utc).timestamp()
        except Exception:
            ts = None
        domain = r.get("domain") or "(unknown)"
        probe = r.get("probe") or "(unknown)"
        result = r.get("result_summary") or "(unknown)"
        gelf(
            f"PROBE {probe} {domain} → {result}",
            host="cloudflare-worker-darknetian-morpheus",
            timestamp=ts,
            cf_event_type="morpheus_probe",
            ant_worker="morpheus",
            morpheus_probe_domain=domain,
            morpheus_probe_name=probe,
            morpheus_probe_result=result,
            morpheus_findings_pass=int(r.get("findings_pass") or 0),
            morpheus_findings_warn=int(r.get("findings_warn") or 0),
            morpheus_findings_fail=int(r.get("findings_fail") or 0),
            morpheus_findings_error=int(r.get("findings_error") or 0),
            # Renamed from ant_samples — that name was already mapped as
            # keyword in OpenSearch (stale mapping from earlier event
            # shapes), which broke sum() on every probe widget. Fresh
            # name = fresh long mapping.
            morpheus_probe_count=int(r.get("invocations") or 0),
            ant_session_id=r.get("session_id"),
            morpheus_probe_latency_ms=r.get("avg_latency_ms"),
            ant_last_seen=r.get("last_seen"),
        )


def poll_morpheus_dcv() -> None:
    """Morpheus emits a dedicated AE write each time runDcvVerifyChallenge
    finishes (success OR failure). Uses a sentinel marker in blob1 so
    the rows can be filtered out from the regular per-call telemetry.

    Schema (worker-side, must stay in sync):
      blob1 = "_event:dcv_verify"  (sentinel)
      blob2 = domain               (the zone being verified)
      blob3 = result               ("pass" | "token_not_found" |
                                   "no_pending_challenge" | "expired" |
                                   "ad_flag_missing" | "doh_error")
      blob4 = session_id
      blob5 = (unused)
      blob6 = "morpheus"
      double1 = latency_ms (DoH query time)
    """
    try:
        accounts = (cf_get("/accounts") or {}).get("result") or []
    except error.HTTPError as e:
        if e.code in (401, 403):
            return
        raise
    if not accounts:
        return
    acct_id = accounts[0]["id"]

    sql = (
        "SELECT "
        "blob2 AS domain, "
        "blob3 AS result, "
        "blob4 AS session_id, "
        "COUNT() AS samples, "
        "AVG(double1) AS avg_latency_ms, "
        "MAX(timestamp) AS last_seen "
        "FROM anthropic_calls "
        "WHERE timestamp > NOW() - INTERVAL '24' HOUR "
        "  AND blob1 = '_event:dcv_verify' "
        "  AND blob6 = 'morpheus' "
        "GROUP BY blob2, blob3, blob4 "
        "ORDER BY last_seen DESC "
        "FORMAT JSON"
    )
    url = f"https://api.cloudflare.com/client/v4/accounts/{acct_id}/analytics_engine/sql"
    req = request.Request(url, data=sql.encode(), headers={
        "Authorization": f"Bearer {CF_API_TOKEN}",
        "Content-Type": "text/plain",
    })
    try:
        with request.urlopen(req, timeout=30) as r:
            body = json.loads(r.read())
    except error.HTTPError as e:
        snippet = e.read().decode("utf-8", "replace")[:200]
        print(f"AE DCV SQL error {e.code}: {snippet}", file=sys.stderr)
        return

    rows = body.get("data") or []
    for r in rows:
        ts = None
        try:
            from datetime import datetime as _dt, timezone as _tz
            ls = r.get("last_seen") or ""
            if ls:
                ts = _dt.strptime(ls, "%Y-%m-%d %H:%M:%S").replace(tzinfo=_tz.utc).timestamp()
        except Exception:
            ts = None
        domain = r.get("domain") or "(unknown)"
        result = r.get("result") or "(unknown)"
        gelf(
            f"DCV {result} {domain} sess={(r.get('session_id') or '')[:14]}..",
            host="cloudflare-worker-darknetian-morpheus",
            timestamp=ts,
            cf_event_type="morpheus_dcv_verify",
            ant_worker="morpheus",
            morpheus_dcv_domain=domain,
            morpheus_dcv_result=result,
            morpheus_dcv_pass="true" if result == "pass" else "false",
            ant_session_id=r.get("session_id"),
            ant_avg_latency_ms=r.get("avg_latency_ms"),
            ant_samples=r.get("samples"),
            ant_last_seen=r.get("last_seen"),
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
        _safe(f"{zone['name']}:http_host",    lambda z=zone: poll_http_by_host(z, start, end))
        _safe(f"{zone['name']}:http_status",  lambda z=zone: poll_http_by_status(z, start, end))
        _safe(f"{zone['name']}:firewall",     lambda z=zone: poll_firewall_events(z, start, end, state))
        _safe(f"{zone['name']}:dns",          lambda z=zone: poll_dns(z, start, end))
        _safe(f"{zone['name']}:dns_nxdomain", lambda z=zone: poll_dns_nxdomain(z, start, end))
        _safe(f"{zone['name']}:dns_agents",   lambda z=zone: poll_dns_agents(z, start, end))

    _safe("audit_logs", lambda: poll_audit_logs(start, state))
    _safe("workers_invocations", lambda: poll_workers_invocations(start, end))
    _safe("workers_ae",          lambda: poll_workers_ae(state))
    _safe("morpheus_dcv",        lambda: poll_morpheus_dcv())
    _safe("morpheus_probes",     lambda: poll_morpheus_probes())
    save_state(state)
    print("done.")


if __name__ == "__main__":
    main()
