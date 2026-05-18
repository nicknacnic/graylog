"""dnscollector stdout (mixed INFO logs + JSON dnstap events) → GELF.

Skips non-JSON lines (the INFO/WARNING noise dnscollector mixes on stdout).
Counts processed events; periodically logs a summary to stderr so the
systemd journal shows it's alive.
"""

from __future__ import annotations
import json, os, sys, time
from urllib import error, request

GELF_URL = os.environ.get("GELF_URL", "http://127.0.0.1:12202/gelf")
HOST_OVERRIDE = os.environ.get("DNSTAP_HOST_LABEL", "").strip()

_seen = 0
_emitted = 0
_failed = 0
_last_log = time.monotonic()


def emit(msg):
    global _emitted, _failed
    try:
        req = request.Request(GELF_URL, data=json.dumps(msg).encode(),
                              headers={"Content-Type": "application/json"})
        with request.urlopen(req, timeout=5) as r:
            r.read()
        _emitted += 1
    except (error.URLError, OSError) as e:
        _failed += 1
        if _failed <= 5:
            print(f"GELF POST failed ({_failed}): {e}", file=sys.stderr, flush=True)


def reshape(ev):
    dnstap = ev.get("dnstap") or {}
    dns = ev.get("dns") or {}
    net = ev.get("network") or {}
    op = dnstap.get("operation") or ""
    qname = (dns.get("qname") or "").rstrip(".")
    qtype = dns.get("qtype")
    rcode = dns.get("rcode")
    qip = net.get("query-ip")
    rip = net.get("response-ip")

    if "QUERY" in op:
        short = f"Q {qname} {qtype} from {qip}"
    elif "RESPONSE" in op:
        short = f"R {qname} {qtype} → {rcode} for {qip}"
    else:
        short = f"{op} {qname} {qtype}"

    # Fixed source label so a single stream rule routes everything to the
    # dedicated nios-dnstap index set. Per-member identity is preserved
    # in _dnstap_identity (queryable as `dnstap_identity`).
    msg = {
        "version": "1.1",
        "host": HOST_OVERRIDE or "nios-dnstap",
        "short_message": short[:1024],
        "level": 6,
        "timestamp": time.time(),
    }
    flat = {
        "dnstap_operation":   op,
        "dnstap_identity":    dnstap.get("identity"),
        "dnstap_version":     dnstap.get("version"),
        "dnstap_latency_ms":  dnstap.get("latency_ms"),
        "dnstap_peer_name":   dnstap.get("peer-name"),
        "dns_qname":          qname or None,
        "dns_qtype":          qtype,
        "dns_qclass":         dns.get("qclass"),
        "dns_rcode":          rcode,
        "dns_opcode":         dns.get("opcode"),
        "dns_length":         dns.get("length"),
        "dns_id":             dns.get("id"),
        "dns_client_ip":      qip,
        "dns_server_ip":      rip,
        "dns_protocol":       net.get("protocol"),
        "dns_family":         net.get("family"),
        "dns_query_port":     net.get("query-port"),
        "dns_response_port":  net.get("response-port"),
    }
    flags = (dns.get("flags") or {})
    for k, v in flags.items():
        flat[f"dns_flag_{k}"] = bool(v)
    for k, v in flat.items():
        if v is None or v == "":
            continue
        msg[f"_{k}"] = v
    return msg


def heartbeat():
    global _last_log
    now = time.monotonic()
    if now - _last_log >= 10:
        print(f"bridge: seen={_seen} emitted={_emitted} failed={_failed}",
              file=sys.stderr, flush=True)
        _last_log = now


print("bridge: starting", file=sys.stderr, flush=True)
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    if not line.startswith("{"):
        # noise from dnscollector stdout — skip cheaply
        continue
    _seen += 1
    try:
        ev = json.loads(line)
    except json.JSONDecodeError:
        continue
    msg = reshape(ev)
    emit(msg)
    heartbeat()
print(f"bridge: stdin closed. seen={_seen} emitted={_emitted} failed={_failed}",
      file=sys.stderr, flush=True)
