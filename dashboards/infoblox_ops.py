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
# same underlying NIOS member syslog by `named[…]` vs `dhcpd[…]`.
# NIOS_DNS_STREAM catches *all* BIND named[…] events (auth + forwarded);
# the pipelines/nios_dns_role.json rule then tags each one as
# nios_dns_role=auth (qname inside darknetian.com) or =forward (sent
# onwards to NIOS-X). Dashboard pages slice by that field.
NIOS_DNS_STREAM  = "6a07586aa72ecf3a3bf3096b"
NIOS_DHCP_STREAM = "6a07586ba72ecf3a3bf3097c"

# Infoblox CSP (CubeJS / IQ-computed metrics). Filled lazily at build()
# time via lookup-by-title so this constant doesn't need to be edited
# after the indexing/csp.py step has created the stream.
CSP_STREAM_TITLE = "Infoblox CSP"

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
    """Auth-DNS only — queries whose qname is inside the darknetian.com
    zone NIOS is authoritative for. Scoped to the NIOS DNS member-syslog
    stream and filtered by `nios_dns_role:auth`, which the
    pipelines/nios_dns_role.json rule sets in stage 1 after the per-host
    NIOS pipelines extract qname.

    Note: the NIOS DNS member stream also carries forwarded queries
    (everything NIOS sent onwards to NIOS-X). The 'Recursive DNS' page
    is the right place to look at those + the NIOS-X-side response feed.
    A 'forwards (context)' tile here gives you the relative volume."""
    AUTH = "nios_dns_role:auth"
    return [
        # Row 1: auth-specific headline numerics
        numeric("Auth queries (24h)", AUTH, "count()", timerange=DAY,
                pos={"col": 1, "row": 1, "width": 3, "height": 2}, name="auth"),
        numeric("Forwards to NIOS-X (24h)", "nios_dns_role:forward",
                "count()", timerange=DAY,
                pos={"col": 4, "row": 1, "width": 3, "height": 2}, name="fwd"),
        numeric("Auth NXDOMAIN (24h)",
                f"{AUTH} AND (dns_is_nxdomain:true OR rcode:NXDOMAIN)",
                "count()", timerange=DAY,
                pos={"col": 7, "row": 1, "width": 3, "height": 2}, name="nx"),
        numeric("Distinct auth qnames (24h)",
                f"{AUTH} AND _exists_:qname",
                "cardinality(qname)", timerange=DAY,
                pos={"col": 10, "row": 1, "width": 3, "height": 2}, name="qnames"),
        # Row 2: auth-vs-forward rate over 24h (sanity check on traffic mix)
        line_ts("Auth vs forward rate (24h)",
                "_exists_:nios_dns_role",
                series=[("count", "count()")],
                column_field="nios_dns_role",
                pos={"col": 1, "row": 3, "width": 12, "height": 4}),
        # Row 3: per-server auth split (.57 vs .253) + top auth clients
        line_ts("Auth queries by server (24h)",
                AUTH, series=[("count", "count()")],
                column_field="source",
                pos={"col": 1, "row": 7, "width": 6, "height": 5}),
        table("Top auth clients (24h)",
              f"{AUTH} AND _exists_:client_ip",
              row_field="client_ip", row_limit=15,
              series=[
                  ("auth queries", "count()"),
                  ("name",         "latest(client_fqdn)"),
                  ("hostname",     "latest(client_hostname)"),
                  ("qnames",       "cardinality(qname)"),
              ],
              pos={"col": 7, "row": 7, "width": 6, "height": 5}),
        # Row 4: top auth qnames (real auth answers from the zone) +
        # search-domain-appended noise is visible here too — qnames like
        # 'grpc.csp.infoblox.com.darknetian.com' come from clients
        # without proper FQDN qualification and tend to NXDOMAIN.
        table("Top auth qnames (24h)",
              f"{AUTH} AND _exists_:qname AND NOT qname:\"\"",
              row_field="qname", row_limit=20,
              series=[
                  ("queries",  "count()"),
                  ("clients",  "cardinality(client_ip)"),
                  ("last rc",  "latest(rcode)"),
              ],
              pos={"col": 1, "row": 12, "width": 12, "height": 5}),
        # Row 5: auth rcode + qtype mix
        pie("Auth RCODE mix (24h)",
            f"{AUTH} AND _exists_:rcode",
            field="rcode",
            pos={"col": 1, "row": 17, "width": 6, "height": 4}),
        pie("Auth query type mix (24h)",
            f"{AUTH} AND _exists_:qtype",
            field="qtype",
            pos={"col": 7, "row": 17, "width": 6, "height": 4}),
    ]


def page_recursive_dns():
    """Recursive DNS: NIOS-X is the actual recursive resolver. Two
    paths feed it — NIOS member forwarders (.57, .253) when an internal
    client asks NIOS for a non-auth zone, AND direct queries from
    endpoints that have NIOS-X configured as their resolver (DHCP
    option 6 distributes it). So the total recursive volume on NIOS-X
    is typically larger than the NIOS forwarding volume.

    Spans two streams (NIOS DNS member + UDDI). Field semantics:
      * On UDDI events: client_ip is the actual querier (NIOS member
        if forwarded, end-host if direct). event_class_id='DNS Response'
        is the canonical 'one recursive answer' marker.
      * On NIOS DNS member events with nios_dns_role=forward, the
        NIOS member is the one logging the forward; client_ip is the
        end-host that asked NIOS in the first place."""
    FWD = "nios_dns_role:forward"
    REC = 'event_class_id:"DNS Response"'
    REC_VIA_NIOS   = f'{REC} AND (client_ip:"10.10.0.57" OR client_ip:"10.10.0.253")'
    REC_FROM_DIRECT = f'{REC} AND NOT (client_ip:"10.10.0.57" OR client_ip:"10.10.0.253")'
    return [
        # Row 1: NIOS-X total, broken down by source path
        numeric("NIOS-X recursive — all (24h)", REC, "count()", timerange=DAY,
                pos={"col": 1, "row": 1, "width": 3, "height": 2}, name="all"),
        numeric("Via NIOS forwarder (24h)", REC_VIA_NIOS, "count()", timerange=DAY,
                pos={"col": 4, "row": 1, "width": 3, "height": 2}, name="via NIOS"),
        numeric("Direct to NIOS-X (24h)", REC_FROM_DIRECT, "count()", timerange=DAY,
                pos={"col": 7, "row": 1, "width": 3, "height": 2}, name="direct"),
        numeric("NIOS forwards out (24h)", FWD, "count()", timerange=DAY,
                pos={"col": 10, "row": 1, "width": 3, "height": 2}, name="fwd-out"),
        # Row 2: rate over 24h, grouped by client_ip so you see who's
        # driving NIOS-X demand (NIOS forwarders vs direct endpoints)
        line_ts("NIOS-X recursive rate by client (24h)",
                REC, series=[("count", "count()")],
                column_field="client_ip",
                pos={"col": 1, "row": 3, "width": 12, "height": 4}),
        # Row 3: NIOS-side — what NIOS is forwarding (its demand profile)
        table("Top forwarded qnames (24h, NIOS members forwarding to NIOS-X)",
              f"{FWD} AND _exists_:qname AND NOT qname:\"\"",
              row_field="qname", row_limit=20,
              series=[
                  ("forwards",      "count()"),
                  ("client (NIOS)", "latest(source)"),
                  ("via clients",   "cardinality(client_ip)"),
              ],
              pos={"col": 1, "row": 7, "width": 12, "height": 5}),
        # Row 4: NIOS-X-side — what was actually resolved
        table("Top recursive answers (24h, on NIOS-X)",
              f"{REC} AND _exists_:qname",
              row_field="qname", row_limit=20,
              series=[
                  ("hits",     "count()"),
                  ("clients",  "cardinality(client_ip)"),
                  ("last rc",  "latest(rcode)"),
              ],
              pos={"col": 1, "row": 12, "width": 12, "height": 5}),
        # Row 5: who's asking NIOS-X (NIOS members vs direct endpoints)
        table("Top NIOS-X clients (24h)",
              f"{REC} AND _exists_:client_ip",
              row_field="client_ip", row_limit=10,
              series=[
                  ("responses", "count()"),
                  ("name",      "latest(client_fqdn)"),
                  ("hostname",  "latest(client_hostname)"),
              ],
              pos={"col": 1, "row": 17, "width": 6, "height": 5}),
        pie("Recursive RCODE mix (24h)",
            f"{REC} AND _exists_:rcode",
            field="rcode",
            pos={"col": 7, "row": 17, "width": 3, "height": 5}),
        pie("Recursive qtype mix (24h)",
            f"{REC} AND _exists_:qtype",
            field="qtype",
            pos={"col": 10, "row": 17, "width": 3, "height": 5}),
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


def page_infoblox_iq():
    """Infoblox IQ — authoritative health metrics from CSP CubeJS.

    Unlike the log-derived pages above, this page reads numbers Infoblox
    IQ already computed: cache_hit_ratio, DNS QPS, NX/SERVFAIL/REFUSED %,
    upstream resolution latency, plus the LAYER8-NIOSX host's CPU and
    memory. Polled every 5 min by pollers/csp_poller.py against
    /api/cubejs/v1/query — endpoint documented in
    _infoblox/reef/docs/internal/INTERNAL-ENDPOINTS.md.

    Fields (set by csp_poller.py):
      csp_metric         e.g. cache_hit_ratio_iq, dns_qps_iq, …
      csp_scope          'account' (host=='') or 'host'
      csp_value          numeric measurement
      csp_host_uuid      host UUID when scope=='host'
      csp_host_label     friendly name (default 'NIOS-X')
      csp_bucket         ISO timestamp of the cube bucket
    """
    def metric_tile(title, metric, *, pos, name="val", scope=None):
        q = f"csp_metric:{metric}"
        if scope:
            q += f" AND csp_scope:{scope}"
        return numeric(title, q, "latest(csp_value)",
                       timerange=HOUR, pos=pos, name=name)

    return [
        # Row 1: account-level DNS quality headlines
        metric_tile("Cache hit ratio (%)", "cache_hit_ratio_iq",
                    pos={"col": 1, "row": 1, "width": 3, "height": 2}, name="%"),
        metric_tile("DNS QPS", "dns_qps_iq",
                    pos={"col": 4, "row": 1, "width": 3, "height": 2}, name="qps"),
        metric_tile("NXDOMAIN (%)", "dns_nxdomain_percent_iq",
                    pos={"col": 7, "row": 1, "width": 3, "height": 2}, name="%"),
        metric_tile("Upstream latency (ms)", "dns_latency_upstream_iq",
                    pos={"col": 10, "row": 1, "width": 3, "height": 2}, name="ms"),
        # Row 2: rcode breakdown numerics
        metric_tile("SERVFAIL (%)", "dns_servfail_percent_iq",
                    pos={"col": 1, "row": 3, "width": 3, "height": 2}, name="%"),
        metric_tile("REFUSED (%)", "dns_refused_percent_iq",
                    pos={"col": 4, "row": 3, "width": 3, "height": 2}, name="%"),
        metric_tile("Other rcodes (%)", "dns_others_percent_iq",
                    pos={"col": 7, "row": 3, "width": 3, "height": 2}, name="%"),
        metric_tile("DDNS updates/sec", "ddns_ups_iq",
                    pos={"col": 10, "row": 3, "width": 3, "height": 2}, name="ups"),
        # Row 3: trend — cache hit + QPS over 24h
        line_ts("Cache hit ratio over 24h",
                "csp_metric:cache_hit_ratio_iq",
                series=[("cache hit %", "avg(csp_value)")],
                pos={"col": 1, "row": 5, "width": 6, "height": 4}),
        line_ts("DNS QPS over 24h",
                "csp_metric:dns_qps_iq",
                series=[("qps", "avg(csp_value)")],
                pos={"col": 7, "row": 5, "width": 6, "height": 4}),
        # Row 4: rcode trends overlaid
        line_ts("rcode percent trends over 24h",
                "csp_metric:dns_nxdomain_percent_iq OR csp_metric:dns_servfail_percent_iq OR csp_metric:dns_refused_percent_iq",
                series=[("percent", "avg(csp_value)")],
                column_field="csp_metric",
                pos={"col": 1, "row": 9, "width": 12, "height": 4}),
        # Row 5: LAYER8-NIOSX host CPU + memory
        metric_tile("LAYER8-NIOSX CPU (%)", "host_cpu_iq",
                    pos={"col": 1, "row": 13, "width": 3, "height": 2},
                    name="%", scope="host"),
        metric_tile("LAYER8-NIOSX memory (%)", "host_memory_iq",
                    pos={"col": 4, "row": 13, "width": 3, "height": 2},
                    name="%", scope="host"),
        # Row 5 cont: host trend
        line_ts("LAYER8-NIOSX CPU + memory over 24h",
                "csp_scope:host AND (csp_metric:host_cpu_iq OR csp_metric:host_memory_iq)",
                series=[("percent", "avg(csp_value)")],
                column_field="csp_metric",
                pos={"col": 7, "row": 13, "width": 6, "height": 4}),
    ]


def page_infoblox_iq_mcp():
    """Infoblox IQ - MCP — per-DFP DNS query activity for LAYER8-NIOSX.

    Source: pollers/mcp_poller.py polls the `PortunusDnsLogs` cube every
    5 minutes scoped to `network = "LAYER8 NIOS-X (DFP)"`. Discovered
    via the CSP MCP gateway catalog (hence the page name) — it's where
    DFP-attributed DNS query data actually lives, in contrast to the
    `*_iq` HostMetrics rollups on the Infoblox IQ page.

    Fields:
      csp_metric           dfp_requests_total | dfp_top_* (per dimension)
      csp_scope            'dfp_host'
      csp_value            request count for the row's bucket
      csp_network          DFP service name (e.g. 'LAYER8 NIOS-X (DFP)')
      dfp_qname / dfp_qip / dfp_policy_action / dfp_tclass /
      dfp_tfamily / dfp_feed_name / dfp_app_category /
      dfp_dns_view / dfp_response
    """
    return [
        # ── Row 1 — headline tiles (1h) ────────────────────────────
        numeric("Total queries (1h)",
                "csp_metric:dfp_requests_total",
                "latest(csp_value)", timerange=HOUR,
                pos={"col": 1, "row": 1, "width": 3, "height": 2}, name="reqs"),
        numeric("Blocked (1h)",
                "csp_metric:dfp_top_policy_action AND dfp_policy_action:Block",
                "sum(csp_value)", timerange=HOUR,
                pos={"col": 4, "row": 1, "width": 3, "height": 2}, name="blocks"),
        numeric("Distinct clients (1h)",
                "csp_metric:dfp_top_qip",
                "cardinality(dfp_qip)", timerange=HOUR,
                pos={"col": 7, "row": 1, "width": 3, "height": 2}, name="qips"),
        numeric("Distinct threat classes (1h)",
                "csp_metric:dfp_top_tclass",
                "cardinality(dfp_tclass)", timerange=HOUR,
                pos={"col": 10, "row": 1, "width": 3, "height": 2}, name="classes"),

        # ── Row 2 — request volume + breakdowns over 24h ──────────
        line_ts("Requests over 24h",
                "csp_metric:dfp_requests_total",
                series=[("reqs", "max(csp_value)")],
                pos={"col": 1, "row": 3, "width": 6, "height": 4}),
        line_ts("Policy actions over 24h",
                "csp_metric:dfp_top_policy_action",
                series=[("reqs", "max(csp_value)")],
                column_field="dfp_policy_action",
                pos={"col": 7, "row": 3, "width": 6, "height": 4}),

        # ── Row 3 — rcode + DNS view ──────────────────────────────
        pie("Query types (24h)",
            "csp_metric:dfp_top_qtype",
            field="dfp_qtype",
            pos={"col": 1, "row": 7, "width": 6, "height": 4}),
        bar("DNS views in use (24h)",
            "csp_metric:dfp_top_dns_view",
            field="dfp_dns_view",
            pos={"col": 7, "row": 7, "width": 6, "height": 4}),

        # ── Row 4 — top qnames table ──────────────────────────────
        table("Top qnames (24h)",
              "csp_metric:dfp_top_qname",
              row_field="dfp_qname", row_limit=25,
              series=[("requests", "max(csp_value)")],
              pos={"col": 1, "row": 11, "width": 6, "height": 6}),
        table("Top clients / qips (24h)",
              "csp_metric:dfp_top_qip",
              row_field="dfp_qip", row_limit=25,
              series=[("requests", "max(csp_value)")],
              pos={"col": 7, "row": 11, "width": 6, "height": 6}),

        # ── Row 5 — threat intel cuts ─────────────────────────────
        bar("Top threat classes (24h)",
            "csp_metric:dfp_top_tclass",
            field="dfp_tclass",
            pos={"col": 1, "row": 17, "width": 4, "height": 4}),
        bar("Top threat families (24h)",
            "csp_metric:dfp_top_tfamily",
            field="dfp_tfamily",
            pos={"col": 5, "row": 17, "width": 4, "height": 4}),
        bar("Top intel feeds firing (24h)",
            "csp_metric:dfp_top_feed_name",
            field="dfp_feed_name",
            pos={"col": 9, "row": 17, "width": 4, "height": 4}),

        # ── Row 6 — app awareness ─────────────────────────────────
        bar("Top app categories (24h)",
            "csp_metric:dfp_top_app_category",
            field="dfp_app_category",
            pos={"col": 1, "row": 21, "width": 12, "height": 4}),
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


def _resolve_stream_id(title: str) -> str | None:
    """Lookup a stream by title at build time. Returns None if missing;
    caller decides whether to skip the page or fail loudly."""
    streams = gl.api("GET", "streams") or {}
    for s in streams.get("streams", []):
        if s.get("title") == title:
            return s["id"]
    return None


def build():
    csp_stream_id = _resolve_stream_id(CSP_STREAM_TITLE)
    csp_streams = [csp_stream_id] if csp_stream_id else None

    # page_defs: (title, build_fn, default_timerange, streams_override)
    page_defs = [
        ("Top talkers",     page_top_talkers,    DAY, None),
        ("DNS health",      page_health,         DAY, None),
        ("Anomalies",       page_anomalies,      DAY, None),
        ("Auth DNS",        page_auth_dns,       DAY, [NIOS_DNS_STREAM]),
        ("Recursive DNS",   page_recursive_dns,  DAY, [NIOS_DNS_STREAM, UDDI_STREAM]),
        ("DHCP",            page_dhcp,           DAY, [NIOS_DHCP_STREAM]),
        ("Network Insight", page_network_insight, DAY, [NI_STREAM]),
        ("Grid Admin",      page_grid_admin,     DAY, [GM_STREAM]),
        ("Reporting",       page_reporting,      DAY, [TR_STREAM]),
    ]
    if csp_streams:
        page_defs.append(("Infoblox IQ",       page_infoblox_iq,     DAY, csp_streams))
        page_defs.append(("Infoblox CubeJS API", page_infoblox_iq_mcp, DAY, csp_streams))
    else:
        print("  (Infoblox CSP stream not found — run indexing/csp.py first to add the IQ pages)")
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
