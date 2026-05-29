"""Detect CLIENT_QUERYs on the dnstap stream that never got a matching
CLIENT_RESPONSE. Runs every 60s — pulls a sliding 60s window with 30s
grace, joins Q and R rows on (dnstap_identity, dns_client_ip,
dns_query_port, dns_id), and emits one GELF event per orphan.

Caveats:
  * dns_id is 16 bits. With (identity, client_ip, port, id) as the join
    key, collisions inside a 60s window are vanishingly rare under
    home-lab load, but a single client bursting >65k same-tuple queries
    in 30s would undercount.
  * Non-overlapping windows: each query gets one chance to be matched.
    Operator-restart can re-cover an already-evaluated window, which
    would double-emit those orphans. Acceptable miss given the cadence.

Output: GELF events on the dnstap stream (host=nios-dnstap-unanswered)
with dnstap_event=unanswered_query — already routed to the dnstap
stream because of the host pattern. Dashboard widgets filter on
dnstap_event:unanswered_query.
"""

from __future__ import annotations

import base64
import json
import os
import socket
import ssl
import sys
import time
from datetime import datetime, timedelta, timezone
from urllib import error, request

# Graylog at graylog.darknetian.com terminates on a self-signed cert.
# The poller runs on the same VM hitting the same endpoint, so cert
# verification adds no security and forces an unfixable failure. Use
# an unverified context for HTTPS calls.
_SSL_CTX = ssl._create_unverified_context()

GRAYLOG_URL   = os.environ["GRAYLOG_URL"].rstrip("/")
GRAYLOG_TOKEN = os.environ["GRAYLOG_TOKEN"]
GELF_URL      = os.environ.get("GELF_URL", "http://127.0.0.1:12202/gelf")
DNSTAP_STREAM = os.environ.get("DNSTAP_STREAM", "6a0b235712e68f7f742811ec")

# Window math: every cycle covers [now-WINDOW_END_S, now-WINDOW_START_S].
# WINDOW_START_S is the grace period for in-flight responses.
WINDOW_START_S = int(os.environ.get("WINDOW_START_S", "30"))   # 30s grace
WINDOW_END_S   = int(os.environ.get("WINDOW_END_S",   "90"))   # 60s wide

# Belt-and-suspenders cap so a misconfigured timer doesn't try to pull
# all-day queries at once.
MAX_WINDOW_S   = int(os.environ.get("MAX_WINDOW_S",  "300"))

# Cap on per-cycle Graylog page size. dnstap on this grid does ~5k Q/min
# steady-state, so a 60s window is ~5k Q + 5k R = 10k rows.
PAGE_LIMIT     = int(os.environ.get("PAGE_LIMIT",    "10000"))


def _auth_header() -> dict:
    raw = f"{GRAYLOG_TOKEN}:token".encode()
    return {
        "Authorization": "Basic " + base64.b64encode(raw).decode(),
        "X-Requested-By": "dnstap-unanswered",
        "Accept": "application/json",
    }


def gl_messages(query: str, frm: datetime, to: datetime, fields: list[str]) -> list[dict]:
    """Page through Graylog absolute-range search until PAGE_LIMIT or
    exhaustion. Returns a list of message dicts."""
    headers = _auth_header()
    out: list[dict] = []
    offset = 0
    page = 1000  # Graylog hard-caps per-page at ~10k; 1000 is the sweet spot
    while True:
        params = (
            f"query={request.quote(query)}"
            f"&from={frm.strftime('%Y-%m-%dT%H:%M:%S.000Z')}"
            f"&to={to.strftime('%Y-%m-%dT%H:%M:%S.000Z')}"
            f"&filter=streams:{DNSTAP_STREAM}"
            f"&fields={','.join(fields)}"
            f"&limit={page}&offset={offset}"
        )
        url = f"{GRAYLOG_URL}/search/universal/absolute?{params}"
        req = request.Request(url, headers=headers)
        with request.urlopen(req, timeout=30, context=_SSL_CTX) as r:
            data = json.loads(r.read())
        msgs = [m["message"] for m in (data.get("messages") or [])]
        out.extend(msgs)
        if len(msgs) < page or len(out) >= PAGE_LIMIT:
            break
        offset += page
    return out


def gelf(message: str, **fields) -> None:
    payload = {
        "version": "1.1",
        "host": "nios-dnstap-unanswered",
        "short_message": message,
        "level": 5,  # NOTICE — orphans aren't errors, they're a signal
    }
    for k, v in fields.items():
        if v is None:
            continue
        payload[f"_{k}"] = v
    req = request.Request(
        GELF_URL, data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
    )
    try:
        request.urlopen(req, timeout=5).read()
    except error.URLError as e:
        print(f"  gelf error: {e}", file=sys.stderr)


def main() -> int:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    window_size = WINDOW_END_S - WINDOW_START_S
    if window_size <= 0 or window_size > MAX_WINDOW_S:
        print(f"bad window {WINDOW_START_S}..{WINDOW_END_S}", file=sys.stderr)
        return 2
    frm = now - timedelta(seconds=WINDOW_END_S)
    to  = now - timedelta(seconds=WINDOW_START_S)
    print(f"== dnstap unanswered {frm.isoformat()} .. {to.isoformat()} ==")

    fields = [
        "dnstap_operation", "dns_id", "dns_client_ip", "dns_query_port",
        "dnstap_identity", "dns_qname", "dns_qtype", "timestamp",
        "client_fqdn", "client_hostname",
    ]
    msgs = gl_messages(
        "dnstap_operation:(CLIENT_QUERY OR CLIENT_RESPONSE)",
        frm, to, fields,
    )

    queries: dict[tuple, dict] = {}
    responses: set[tuple] = set()
    for m in msgs:
        op = m.get("dnstap_operation")
        key = (
            m.get("dnstap_identity"),
            m.get("dns_client_ip"),
            m.get("dns_query_port"),
            m.get("dns_id"),
        )
        if None in key:
            continue
        if op == "CLIENT_QUERY":
            queries[key] = m
        elif op == "CLIENT_RESPONSE":
            responses.add(key)

    orphans = [m for k, m in queries.items() if k not in responses]
    print(f"  Q={len(queries)} R={len(responses)} orphans={len(orphans)}")

    for m in orphans:
        gelf(
            f"UNANSWERED {m.get('dns_qname')} {m.get('dns_qtype')} "
            f"from {m.get('dns_client_ip')} via {m.get('dnstap_identity')}",
            dnstap_event="unanswered_query",
            dns_qname=m.get("dns_qname"),
            dns_qtype=m.get("dns_qtype"),
            dns_id=m.get("dns_id"),
            dns_client_ip=m.get("dns_client_ip"),
            dns_query_port=m.get("dns_query_port"),
            dnstap_identity=m.get("dnstap_identity"),
            client_fqdn=m.get("client_fqdn"),
            client_hostname=m.get("client_hostname"),
            original_timestamp=m.get("timestamp"),
            window_start=frm.isoformat(),
            window_end=to.isoformat(),
        )

    print("done.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
