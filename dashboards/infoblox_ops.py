"""Infoblox — Operations dashboard.

Complements the user's existing 'Infoblox' dashboard (which is a focused
NX/SERVFAIL deep dive). This adds the operational + analytical cuts the
existing one doesn't cover.

Pages:
  1. Top talkers  — who/what/where, no error filtering
  2. DNS health   — query/response totals, NX vs SERVFAIL trends, error counts
  3. Threat-shape — anomaly indicators: high-NX clients, rare TLDs,
                     unusual qtype mix, query-burst detection
  4. DHCP & ops   — UDDI/NIOS sender heartbeat, query types over time

Queries the NIOS streams (gm/ddi/ns1/tr/ni) and UDDI together via the
search-type multi-stream filter, so the widgets cover the whole DDI fabric.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))
import graylog as gl  # noqa: E402

# All DNS-bearing streams. Order here just affects search_type primary stream id.
NIOS_STREAMS = [
    "697e66d3eeb15b769f4235eb",  # gm
    "697bf15eeeb15b769f3c8567",  # ddi
    "69939874eeb15b769f4f8ebd",  # ns1
    "697e67bdeeb15b769f423c70",  # tr
    "697c03f7eeb15b769f3cd51b",  # ni
]
UDDI_STREAM = "697c067eeeb15b769f3ce126"
ALL_DDI_STREAMS = NIOS_STREAMS + [UDDI_STREAM]
PRIMARY = NIOS_STREAMS[0]

# Per-page streams overrides — for the GM admin / NI / Reporting pages we
# want widgets scoped to a single member's stream, not the whole DDI fabric.
GM_STREAM = "697e66d3eeb15b769f4235eb"
NI_STREAM = "697c03f7eeb15b769f3cd51b"
TR_STREAM = "697e67bdeeb15b769f423c70"

# Service-scoped streams created by indexing/nios_split.py — route the
# same underlying NIOS member syslog by `named[…]` vs `dhcpd[…]` so the
# Auth-DNS / DHCP dashboard pages stop mixing the two.
NIOS_DNS_AUTH_STREAM = "6a07586aa72ecf3a3bf3096b"
NIOS_DHCP_STREAM     = "6a07586ba72ecf3a3bf3097c"

TITLE = "Infoblox — Operations"
SUMMARY = "DDI fabric — DNS top talkers, health, anomalies, DHCP"
DESCRIPTION = (
    "Operational cuts of the Infoblox NIOS + UDDI fabric. Complements the "
    "user's existing 'Infoblox' dashboard (NX/SERVFAIL deep dive). Queries "
    "all 5 NIOS streams (gm/ddi/ns1/tr/ni) plus UDDI together. Key fields "
    "extracted by pipeline rules: dns_event_type, qname, qtype, rcode, "
    "client_ip, client_fqdn, sender_fqdn, dns_is_nxdomain, dns_is_servfail."
)

HOUR = 3600
DAY = 86400
WEEK = 7 * DAY


def _ps(fn: str) -> dict:
    return gl.parse_series_fn(fn)


def numeric(title, query, fn, *, timerange=HOUR, pos, name="value"):
    return {
        "title": title, "kind": "agg", "viz": "numeric",
        "query": query, "timerange": timerange,
        "series": [{"config": {"name": name}, "function": fn}],
        "pivot_series": [_ps(fn)],
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


def msgs(title, query, *, pos, timerange=DAY):
    return {"title": title, "kind": "messages", "query": query,
            "timerange": timerange, "pos": pos}


def page_top_talkers():
    return [
        # Row 1: headline numerics
        numeric("Queries (24h)", "dns_event_type:query", "count()",
                timerange=DAY, pos={"col": 1, "row": 1, "width": 3, "height": 2}, name="q"),
        numeric("Responses (24h)", "dns_event_type:response", "count()",
                timerange=DAY, pos={"col": 4, "row": 1, "width": 3, "height": 2}, name="r"),
        numeric("Distinct clients (24h)",
                "_exists_:client_ip", "cardinality(client_ip)",
                timerange=DAY, pos={"col": 7, "row": 1, "width": 3, "height": 2}, name="clients"),
        numeric("Distinct qnames (24h)",
                "_exists_:qname", "cardinality(qname)",
                timerange=DAY, pos={"col": 10, "row": 1, "width": 3, "height": 2}, name="qnames"),
        # Row 2: top clients
        table("Top clients by query count (24h)",
              "_exists_:qname",
              row_field="client_ip", row_limit=20,
              series=[
                  ("queries",   "count()"),
                  ("name",      "latest(client_fqdn)"),
                  ("hostname",  "latest(client_hostname)"),
                  ("qnames",    "cardinality(qname)"),
              ],
              pos={"col": 1, "row": 3, "width": 12, "height": 5}),
        # Row 3: top qnames + qtype mix
        table("Top qnames (24h)",
              "_exists_:qname AND NOT qname:\"\"",
              row_field="qname", row_limit=20,
              series=[
                  ("queries", "count()"),
                  ("clients", "cardinality(client_ip)"),
              ],
              pos={"col": 1, "row": 8, "width": 8, "height": 5}),
        pie("Query types (24h)",
            "_exists_:qtype", field="qtype",
            pos={"col": 9, "row": 8, "width": 4, "height": 5}),
        # Row 4: client_hostname enrichment effectiveness + qname per source
        line_ts("Queries per NIOS server (24h)",
                "dns_event_type:query",
                series=[("count", "count()")],
                column_field="source",
                pos={"col": 1, "row": 13, "width": 12, "height": 4}),
    ]


def page_health():
    return [
        # Row 1: total + error counts. Graylog pivots can't compute
        # cross-series percentages — these are raw counts, mentally compare
        # the error-flavoured ones against Total to gauge the share.
        numeric("Total messages (24h)",
                "*", "count()", timerange=DAY,
                pos={"col": 1, "row": 1, "width": 3, "height": 2}, name="total"),
        numeric("NXDOMAIN (24h)",
                "dns_is_nxdomain:true OR rcode:NXDOMAIN OR InfobloxDNSRCode:NXDOMAIN",
                "count()", timerange=DAY,
                pos={"col": 4, "row": 1, "width": 3, "height": 2}, name="nx"),
        numeric("SERVFAIL (24h)",
                "dns_is_servfail:true OR rcode:SERVFAIL OR InfobloxDNSRCode:SERVFAIL",
                "count()", timerange=DAY,
                pos={"col": 7, "row": 1, "width": 3, "height": 2}, name="sf"),
        numeric("Errors (24h, any rcode != NOERROR)",
                "dns_is_error:true", "count()", timerange=DAY,
                pos={"col": 10, "row": 1, "width": 3, "height": 2}, name="err"),
        # Row 2: rcode distribution over time
        line_ts("RCODE distribution over 24h",
                "_exists_:rcode",
                series=[("count", "count()")],
                column_field="rcode",
                pos={"col": 1, "row": 3, "width": 12, "height": 4}),
        # Row 3: query vs response rate
        line_ts("Query vs response rate (24h)",
                "_exists_:dns_event_type",
                series=[("count", "count()")],
                column_field="dns_event_type",
                pos={"col": 1, "row": 7, "width": 12, "height": 4}),
        # Row 4: error breakdown by client
        table("Highest error rate clients (24h)",
              "dns_is_error:true",
              row_field="client_ip", row_limit=15,
              series=[
                  ("errors",    "count()"),
                  ("name",      "latest(client_fqdn)"),
                  ("hostname",  "latest(client_hostname)"),
              ],
              pos={"col": 1, "row": 11, "width": 12, "height": 5}),
    ]


def page_anomalies():
    return [
        # Row 1: indicator counters
        numeric("PTR queries (24h)", "qtype:PTR", "count()",
                timerange=DAY, pos={"col": 1, "row": 1, "width": 3, "height": 2}, name="ptr"),
        numeric("HTTPS qtype (24h)", "qtype:HTTPS", "count()",
                timerange=DAY, pos={"col": 4, "row": 1, "width": 3, "height": 2}, name="https"),
        numeric("SVCB qtype (24h)", "qtype:SVCB", "count()",
                timerange=DAY, pos={"col": 7, "row": 1, "width": 3, "height": 2}, name="svcb"),
        numeric("AAAA queries (24h)", "qtype:AAAA", "count()",
                timerange=DAY, pos={"col": 10, "row": 1, "width": 3, "height": 2}, name="aaaa"),
        # Row 2: top NX qnames overall (without the nas filter — that's in user's existing dashboard)
        table("Top NX qnames (24h) — fleet-wide",
              "dns_is_nxdomain:true OR rcode:NXDOMAIN OR InfobloxDNSRCode:NXDOMAIN",
              row_field="qname", row_limit=20,
              series=[
                  ("hits",    "count()"),
                  ("clients", "cardinality(client_ip)"),
              ],
              pos={"col": 1, "row": 3, "width": 12, "height": 5}),
        # Row 3: clients with highest NX ratio (likely scanners or misconfigs)
        table("Top NX-emitting clients (24h)",
              "dns_is_nxdomain:true OR rcode:NXDOMAIN OR InfobloxDNSRCode:NXDOMAIN",
              row_field="client_ip", row_limit=15,
              series=[
                  ("nx_hits", "count()"),
                  ("name",    "latest(client_fqdn)"),
                  ("hostname", "latest(client_hostname)"),
                  ("uniq_qnames", "cardinality(qname)"),
              ],
              pos={"col": 1, "row": 8, "width": 12, "height": 5}),
        # Row 4: oddities (BADCOOKIE etc — observed in your data)
        bar("Unusual rcodes (24h, excl. NOERROR/NXDOMAIN)",
            "_exists_:rcode AND NOT rcode:NOERROR AND NOT rcode:NXDOMAIN AND NOT rcode:SERVFAIL",
            field="rcode",
            pos={"col": 1, "row": 13, "width": 6, "height": 4}),
        msgs("Unusual rcode messages (24h)",
             "_exists_:rcode AND NOT rcode:NOERROR AND NOT rcode:NXDOMAIN AND NOT rcode:SERVFAIL",
             timerange=DAY, pos={"col": 7, "row": 13, "width": 6, "height": 4}),
    ]


def page_network_insight():
    """Network Insight (10.10.0.55) discovery + consolidation activity.

    Fields populated by the 'NIOS Grid' pipeline (see pipelines/nios_grid.json):
      ni_module          netauto_core | netauto_discovery | sudo | scriptxmld | CRON
      ni_summary         Wireless | Topology | Routing | Switching | Stats | Event | Subnet | Normal
      ni_summary_status  Processed | Failed | Error
      ni_target_ip       IP being scanned (discovery worker pulls)
      ni_scan_op         ifTableObject | WirelessObject | InventoryObject | SystemInfo | …
    """
    return [
        # Row 1: headline numerics
        numeric("NI events (24h)", "*", "count()", timerange=DAY,
                pos={"col": 1, "row": 1, "width": 3, "height": 2}, name="events"),
        numeric("Discovery scans (24h)", "ni_module:netauto_discovery", "count()",
                timerange=DAY, pos={"col": 4, "row": 1, "width": 3, "height": 2}, name="scans"),
        numeric("Devices scanned (24h)", "_exists_:ni_target_ip",
                "cardinality(ni_target_ip)", timerange=DAY,
                pos={"col": 7, "row": 1, "width": 3, "height": 2}, name="devices"),
        numeric("Consolidations (24h)", "_exists_:ni_summary AND ni_summary_status:Processed",
                "count()", timerange=DAY,
                pos={"col": 10, "row": 1, "width": 3, "height": 2}, name="runs"),
        # Row 2: subprocess breakdown over time
        line_ts("NI subprocess activity (24h)", "_exists_:ni_module",
                series=[("count", "count()")], column_field="ni_module",
                pos={"col": 1, "row": 3, "width": 12, "height": 4}),
        # Row 3: summary-task volume table + scan-op pie
        table("Consolidation task throughput (24h)",
              "_exists_:ni_summary",
              row_field="ni_summary", row_limit=15,
              series=[
                  ("runs",    "count()"),
                  ("status",  "latest(ni_summary_status)"),
              ],
              pos={"col": 1, "row": 7, "width": 6, "height": 5}),
        pie("Scan-op mix (24h)", "_exists_:ni_scan_op", field="ni_scan_op",
            pos={"col": 7, "row": 7, "width": 6, "height": 5}),
        # Row 4: top devices being scanned
        table("Top devices scanned by NI (24h)",
              "_exists_:ni_target_ip",
              row_field="ni_target_ip", row_limit=20,
              series=[
                  ("scans",  "count()"),
                  ("op mix", "cardinality(ni_scan_op)"),
                  ("first scan-op", "latest(ni_scan_op)"),
              ],
              pos={"col": 1, "row": 12, "width": 12, "height": 5}),
        # Row 5: failures / errors
        msgs("Recent NI errors / non-Processed status (24h)",
             "_exists_:ni_summary AND NOT ni_summary_status:Processed",
             pos={"col": 1, "row": 17, "width": 12, "height": 5}),
    ]


def page_grid_admin():
    """NIOS GM admin activity (10.10.0.54) + Trinzic Reporting heartbeat.

    Fields populated by 'NIOS Grid' pipeline (pipelines/nios_grid.json):
      gm_user       admin username from the bracketed prefix
      gm_event      Login_Allowed | Logout | …
      gm_login_src  source IP that initiated the admin session

    Reporting (tr.darknetian.com) typically just emits `-- MARK --` keepalives,
    so its widget is a heartbeat-presence tile rather than a content cut.
    """
    return [
        # Row 1: headline
        numeric("GM events (24h)", "*", "count()", timerange=DAY,
                pos={"col": 1, "row": 1, "width": 3, "height": 2}, name="events"),
        numeric("Successful logins (24h)", "gm_event:Login_Allowed",
                "count()", timerange=DAY,
                pos={"col": 4, "row": 1, "width": 3, "height": 2}, name="logins"),
        numeric("Logouts (24h)", "gm_event:Logout", "count()", timerange=DAY,
                pos={"col": 7, "row": 1, "width": 3, "height": 2}, name="logouts"),
        numeric("Distinct admin users (24h)", "_exists_:gm_user",
                "cardinality(gm_user)", timerange=DAY,
                pos={"col": 10, "row": 1, "width": 3, "height": 2}, name="users"),
        # Row 2: logins over time
        line_ts("Admin login activity over 24h", "gm_event:Login_Allowed",
                series=[("count", "count()")], column_field="gm_user",
                pos={"col": 1, "row": 3, "width": 12, "height": 4}),
        # Row 3: top admin users + source IPs
        table("Admin users (24h)",
              "_exists_:gm_user",
              row_field="gm_user", row_limit=15,
              series=[
                  ("events",  "count()"),
                  ("logins",  "count()"),
                  ("last src","latest(gm_login_src)"),
                  ("last event", "latest(gm_event)"),
              ],
              pos={"col": 1, "row": 7, "width": 6, "height": 5}),
        bar("Top login source IPs (24h)",
            "gm_event:Login_Allowed AND _exists_:gm_login_src",
            field="gm_login_src",
            pos={"col": 7, "row": 7, "width": 6, "height": 5}, row_limit=10),
        # Row 4: recent admin events
        msgs("Recent GM admin events (24h)", "_exists_:gm_user",
             pos={"col": 1, "row": 12, "width": 12, "height": 5}),
    ]


def page_reporting():
    """Trinzic Reporting (10.10.0.56) — mostly `-- MARK --` syslog
    keepalives. A presence tile + raw log tail is honest about the
    fact that there's no rich structured data to slice."""
    return [
        numeric("Reporting messages (24h)", "*", "count()", timerange=DAY,
                pos={"col": 1, "row": 1, "width": 3, "height": 2}, name="msgs"),
        numeric("MARK heartbeats (24h)", "message:MARK", "count()", timerange=DAY,
                pos={"col": 4, "row": 1, "width": 3, "height": 2}, name="MARK"),
        line_ts("Reporting heartbeat over 24h", "*",
                series=[("count", "count()")],
                pos={"col": 1, "row": 3, "width": 12, "height": 4}),
        msgs("All Reporting messages (24h)", "*",
             pos={"col": 1, "row": 7, "width": 12, "height": 6}),
    ]


def page_auth_dns():
    """Auth/forwarding DNS only — BIND `named[…]` from the NIOS members
    that serve auth + forward to NIOS-X. Scoped to the 'NIOS DNS (auth)'
    stream so DHCP failover chatter and admin events don't contaminate
    the query-rate widgets.

    The existing NIOS pipelines (attached to the per-host streams) set
    dns_event_type / qname / qtype / rcode / client_ip on the same
    messages, so the fields are available here too — Graylog applies
    pipeline rules per stream membership, and these messages live in
    both the per-host AND the service-scoped stream."""
    return [
        # Row 1: headline numerics
        numeric("Auth-DNS messages (24h)", "*", "count()", timerange=DAY,
                pos={"col": 1, "row": 1, "width": 3, "height": 2}, name="msgs"),
        numeric("Queries (24h)", "dns_event_type:query", "count()", timerange=DAY,
                pos={"col": 4, "row": 1, "width": 3, "height": 2}, name="q"),
        numeric("Responses (24h)", "dns_event_type:response", "count()", timerange=DAY,
                pos={"col": 7, "row": 1, "width": 3, "height": 2}, name="r"),
        numeric("NXDOMAIN (24h)",
                "dns_is_nxdomain:true OR rcode:NXDOMAIN",
                "count()", timerange=DAY,
                pos={"col": 10, "row": 1, "width": 3, "height": 2}, name="nx"),
        # Row 2: per-server rate (.57 vs .253)
        line_ts("Auth-DNS rate by server (24h)",
                "*", series=[("count", "count()")],
                column_field="source",
                pos={"col": 1, "row": 3, "width": 12, "height": 4}),
        # Row 3: top auth clients + top qnames
        table("Top auth-DNS clients (24h)",
              "_exists_:client_ip",
              row_field="client_ip", row_limit=15,
              series=[
                  ("queries",  "count()"),
                  ("name",     "latest(client_fqdn)"),
                  ("hostname", "latest(client_hostname)"),
                  ("qnames",   "cardinality(qname)"),
              ],
              pos={"col": 1, "row": 7, "width": 6, "height": 5}),
        table("Top auth-DNS qnames (24h)",
              "_exists_:qname AND NOT qname:\"\"",
              row_field="qname", row_limit=15,
              series=[
                  ("queries", "count()"),
                  ("clients", "cardinality(client_ip)"),
              ],
              pos={"col": 7, "row": 7, "width": 6, "height": 5}),
        # Row 4: rcode mix + qtype mix
        pie("RCODE mix (24h)", "_exists_:rcode", field="rcode",
            pos={"col": 1, "row": 12, "width": 6, "height": 4}),
        pie("Query type mix (24h)", "_exists_:qtype", field="qtype",
            pos={"col": 7, "row": 12, "width": 6, "height": 4}),
    ]


def page_recursive_dns():
    """NIOS-X recursive DNS — UDDI CEF stream only. Each message is one
    recursive resolution NIOS-X performed on behalf of a NIOS-auth
    server (or, more often these days, a direct client of NIOS-X).
    Fields populated by the UDDI pipeline (pipelines/uddi.json)."""
    return [
        # Row 1: headline numerics
        numeric("Recursive answers (24h)",
                "event_class_id:\"DNS Response\"", "count()", timerange=DAY,
                pos={"col": 1, "row": 1, "width": 3, "height": 2}, name="r"),
        numeric("Distinct clients (24h)",
                "_exists_:client_ip", "cardinality(client_ip)", timerange=DAY,
                pos={"col": 4, "row": 1, "width": 3, "height": 2}, name="clients"),
        numeric("Distinct qnames (24h)",
                "_exists_:qname", "cardinality(qname)", timerange=DAY,
                pos={"col": 7, "row": 1, "width": 3, "height": 2}, name="qnames"),
        numeric("NXDOMAIN (24h)",
                "dns_is_nxdomain:true OR rcode:NXDOMAIN OR InfobloxDNSRCode:NXDOMAIN",
                "count()", timerange=DAY,
                pos={"col": 10, "row": 1, "width": 3, "height": 2}, name="nx"),
        # Row 2: response rate over 24h
        line_ts("Recursive answer rate over 24h",
                "event_class_id:\"DNS Response\"",
                series=[("count", "count()")],
                pos={"col": 1, "row": 3, "width": 12, "height": 4}),
        # Row 3: top clients (mostly NIOS-auth forwarders) + top qnames
        table("Top recursive clients (24h)",
              "_exists_:client_ip",
              row_field="client_ip", row_limit=15,
              series=[
                  ("responses", "count()"),
                  ("name",      "latest(client_fqdn)"),
                  ("hostname",  "latest(client_hostname)"),
                  ("qnames",    "cardinality(qname)"),
              ],
              pos={"col": 1, "row": 7, "width": 6, "height": 5}),
        table("Top recursive qnames (24h)",
              "_exists_:qname",
              row_field="qname", row_limit=15,
              series=[
                  ("hits",    "count()"),
                  ("clients", "cardinality(client_ip)"),
              ],
              pos={"col": 7, "row": 7, "width": 6, "height": 5}),
        # Row 4: rcode + qtype mix
        pie("Recursive RCODE mix (24h)",
            "_exists_:rcode OR _exists_:InfobloxDNSRCode",
            field="rcode",
            pos={"col": 1, "row": 12, "width": 6, "height": 4}),
        pie("Recursive query type mix (24h)",
            "_exists_:qtype OR _exists_:InfobloxDNSQType",
            field="qtype",
            pos={"col": 7, "row": 12, "width": 6, "height": 4}),
    ]


def page_dhcp():
    """ISC dhcpd events — failover peer chatter, lease grants/expires,
    scope warnings — from the 'NIOS DHCP' stream. The messages aren't
    structured-extracted yet; widgets work on substring/regex queries
    against the raw message body. Add a dhcp pipeline rule later if
    cardinality/mac-level cuts become useful."""
    return [
        # Row 1: headline event-type counters
        numeric("DHCP events (24h)", "*", "count()", timerange=DAY,
                pos={"col": 1, "row": 1, "width": 3, "height": 2}, name="ev"),
        numeric("Failover messages (24h)", "message:\"failover peer\"",
                "count()", timerange=DAY,
                pos={"col": 4, "row": 1, "width": 3, "height": 2}, name="fo"),
        numeric("Leases added (24h)", "message:\"leases added\"",
                "count()", timerange=DAY,
                pos={"col": 7, "row": 1, "width": 3, "height": 2}, name="add"),
        numeric("DHCP errors / warnings (24h)",
                "message:fail OR message:error OR message:warn OR message:reject",
                "count()", timerange=DAY,
                pos={"col": 10, "row": 1, "width": 3, "height": 2}, name="err"),
        # Row 2: rate over 24h
        line_ts("DHCP message rate over 24h", "*",
                series=[("count", "count()")],
                column_field="source",
                pos={"col": 1, "row": 3, "width": 12, "height": 4}),
        # Row 3: per-NIOS DHCP server table + failover-peer breakdown
        table("DHCP server breakdown (24h)",
              "*",
              row_field="source", row_limit=10,
              series=[
                  ("events",     "count()"),
                  ("failover",   "count()"),
              ],
              pos={"col": 1, "row": 7, "width": 6, "height": 5}),
        bar("Failover peer names (24h)",
            "message:\"failover peer\"",
            field="application_name",
            pos={"col": 7, "row": 7, "width": 6, "height": 5}, row_limit=10),
        # Row 4: raw messages for forensics
        msgs("Recent DHCP events (24h)", "*",
             pos={"col": 1, "row": 12, "width": 12, "height": 6}),
    ]


def page_dhcp_ops_legacy():
    """Legacy page — kept for reference but no longer wired into build().
    The new page_dhcp() scoped to NIOS DHCP stream supersedes this."""
    return [
        numeric("Total DDI messages (24h)", "*", "count()", timerange=DAY,
                pos={"col": 1, "row": 1, "width": 3, "height": 2}, name="msgs"),
        numeric("Distinct NIOS sources (24h)",
                "*", "cardinality(source)", timerange=DAY,
                pos={"col": 4, "row": 1, "width": 3, "height": 2}, name="src"),
        numeric("UDDI events (24h)",
                "_exists_:deviceAddress", "count()", timerange=DAY,
                pos={"col": 7, "row": 1, "width": 3, "height": 2}, name="uddi"),
        numeric("DHCP-port (67/68) traffic (24h)",
                "dns_client_port:67 OR dns_client_port:68",
                "count()", timerange=DAY,
                pos={"col": 10, "row": 1, "width": 3, "height": 2}, name="dhcp"),
        line_ts("Per-appliance message rate (24h)",
                "*",
                series=[("count", "count()")],
                column_field="source",
                pos={"col": 1, "row": 3, "width": 12, "height": 4}),
        table("NIOS / UDDI appliances seen (24h)",
              "*",
              row_field="source", row_limit=20,
              series=[
                  ("messages", "count()"),
                  ("clients",  "cardinality(client_ip)"),
                  ("qnames",   "cardinality(qname)"),
                  ("fqdn",     "latest(sender_fqdn)"),
              ],
              pos={"col": 1, "row": 7, "width": 12, "height": 5}),
        bar("UDDI-only qtype mix (24h)",
            "_exists_:deviceAddress AND _exists_:qtype",
            field="qtype",
            pos={"col": 1, "row": 12, "width": 6, "height": 4}),
        bar("NIOS-only qtype mix (24h)",
            "NOT _exists_:deviceAddress AND _exists_:qtype",
            field="qtype",
            pos={"col": 7, "row": 12, "width": 6, "height": 4}),
    ]


# ── build / apply: multi-stream ──────────────────────────────────────────────

def build_pages_multi(specs, default_timerange_s, streams=None):
    """Like gl.build_widgets_for_page but the search-type queries can scope
    to an arbitrary stream-set per page (defaults to all DDI streams).
    Pass `streams=[GM_STREAM]` for a single-member page, etc."""
    if streams is None:
        streams = ALL_DDI_STREAMS
    primary = streams[0]
    search_types, widgets, positions, titles, widget_mapping = [], [], {}, {}, {}
    for s in specs:
        wid, stid = gl.gen_id(), gl.gen_id()
        timerange = s.get("timerange", default_timerange_s)
        query = s.get("query", "")
        if s["kind"] == "agg":
            ps = gl.align_pivot_ids(s.get("series", []), s.get("pivot_series", []))
            st = gl.pivot(
                search_type_id=stid, stream_id=primary,
                query=query, timerange_s=timerange,
                row_field=s.get("row_field"),
                column_field=s.get("column_field"),
                series=ps,
                row_limit=s.get("row_limit", 25),
                column_limit=s.get("column_limit", 25),
            )
            st["streams"] = streams
            search_types.append(st)
            w = gl.widget_aggregation(
                widget_id=wid, stream_id=primary,
                query=query, timerange_s=timerange,
                row_field=s.get("row_field"),
                column_field=s.get("column_field"),
                series=s.get("series"),
                visualization=s["viz"],
                row_limit=s.get("row_limit", 25),
                column_limit=s.get("column_limit", 25),
            )
            w["streams"] = streams
            widgets.append(w)
        elif s["kind"] == "messages":
            st = gl.messages_searchtype(
                search_type_id=stid, stream_id=primary,
                query=query, timerange_s=timerange,
            )
            st["streams"] = streams
            search_types.append(st)
            w = gl.widget_messages(
                widget_id=wid, stream_id=primary,
                query=query, timerange_s=timerange,
            )
            w["streams"] = streams
            widgets.append(w)
        else:
            raise ValueError(f"unknown widget kind: {s['kind']}")
        positions[wid] = s["pos"]
        titles[wid] = s["title"]
        widget_mapping[wid] = [stid]
    return search_types, widgets, positions, titles, widget_mapping


def build():
    # page_defs: (title, build_fn, default_timerange, streams_override)
    page_defs = [
        ("Top talkers",     page_top_talkers,    DAY, None),
        ("DNS health",      page_health,         DAY, None),
        ("Anomalies",       page_anomalies,      DAY, None),
        ("Auth DNS",        page_auth_dns,       DAY, [NIOS_DNS_AUTH_STREAM]),
        ("Recursive DNS",   page_recursive_dns,  DAY, [UDDI_STREAM]),
        ("DHCP",            page_dhcp,           DAY, [NIOS_DHCP_STREAM]),
        ("Network Insight", page_network_insight, DAY, [NI_STREAM]),
        ("Grid Admin",      page_grid_admin,     DAY, [GM_STREAM]),
        ("Reporting",       page_reporting,      DAY, [TR_STREAM]),
    ]
    pages_for_search, pages_for_view = [], []
    for title, fn, tr, streams in page_defs:
        qid = gl.gen_id()
        sts, ws, pos, ti, wm = build_pages_multi(fn(), tr, streams=streams)
        pages_for_search.append({"query_id": qid, "search_types": sts, "timerange_s": tr})
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
    import os
    print(f"open:      {os.environ['GRAYLOG_URL'].rsplit('/api', 1)[0]}/dashboards/{vresp['id']}")


if __name__ == "__main__":
    build()
