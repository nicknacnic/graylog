"""WAN performance probe — speedtest + canary pings + DNS timing.

Each cycle emits a small bundle of GELF events to the existing
Cradlepoint stream (matched by `source:e300.darknetian.com`):

  - 1 × cp_event_type=speedtest
        cp_speedtest_down_mbps, cp_speedtest_up_mbps,
        cp_speedtest_latency_ms, cp_speedtest_jitter_ms,
        cp_speedtest_loss_pct, cp_speedtest_server,
        cp_speedtest_server_id, cp_speedtest_isp,
        cp_speedtest_external_ip, cp_speedtest_result_url

  - N × cp_event_type=ping_canary  (one per target)
        cp_canary_target, cp_canary_loss_pct,
        cp_canary_rtt_min_ms, cp_canary_rtt_avg_ms,
        cp_canary_rtt_max_ms, cp_canary_rtt_mdev_ms

  - N × cp_event_type=dns_timing  (one per resolver)
        cp_dns_resolver, cp_dns_resolver_ip, cp_dns_query_name,
        cp_dns_query_ms

  - 1 × cp_event_type=wan_ip
        cp_wan_external_ip, cp_wan_external_ip_source

Why these three together:
  - Speedtest gives the "is the pipe wide" answer but is expensive
    to run (data + time) so it only fires every 30 min.
  - Canary pings give cheap continuous loss/jitter visibility between
    speedtests — far more sensitive to brief LTE blips.
  - DNS timing surfaces the first thing that breaks on a degraded LTE
    link (resolver round-trip balloons before bandwidth visibly drops).

Source is set to `e300.darknetian.com` so the Cradlepoint stream (which
matches on the source field) picks these up alongside the syslog events
already there — no new stream rule needed.

Env:
  GELF_URL          http://127.0.0.1:12202/gelf
  WAN_HOST_LABEL    `source` value in GELF (default e300.darknetian.com)
  WAN_CANARIES      CSV, default '1.1.1.1,8.8.8.8,darknetian.com'
  WAN_DNS_RESOLVERS CSV, default '1.1.1.1,8.8.8.8,10.10.0.253'
  WAN_DNS_QUERY     default 'cloudflare.com'
  WAN_PING_COUNT    default 10
  SKIP_SPEEDTEST    '1' to disable Ookla (still ship canaries + DNS)
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import time
from typing import Any
from urllib import error, request


GELF_URL = os.environ.get("GELF_URL", "http://127.0.0.1:12202/gelf")
SOURCE = os.environ.get("WAN_HOST_LABEL", "e300.darknetian.com").strip()

CANARIES = [c.strip() for c in os.environ.get(
    "WAN_CANARIES",
    "1.1.1.1,8.8.8.8,threatdefense.infoblox.com,www.darknetian.com",
).split(",") if c.strip()]
DNS_RESOLVERS = [r.strip() for r in os.environ.get(
    "WAN_DNS_RESOLVERS",
    "1.1.1.1,8.8.8.8,10.10.0.253,threatdefense.infoblox.com",
).split(",") if r.strip()]
DNS_QUERY = os.environ.get("WAN_DNS_QUERY", "cloudflare.com").strip()
PING_COUNT = int(os.environ.get("WAN_PING_COUNT", "10"))
SKIP_SPEEDTEST = os.environ.get("SKIP_SPEEDTEST", "0") == "1"


def gelf(short: str, level: int = 6, **fields: Any) -> None:
    msg = {
        "version": "1.1", "host": SOURCE,
        "short_message": short[:1024], "level": level,
        "timestamp": time.time(),
    }
    for k, v in fields.items():
        if v is None:
            continue
        msg[k if k.startswith("_") else f"_{k}"] = v
    try:
        req = request.Request(GELF_URL, data=json.dumps(msg).encode(),
                              headers={"Content-Type": "application/json"})
        with request.urlopen(req, timeout=5) as r:
            r.read()
    except (error.URLError, OSError) as e:
        # OSError covers bare TimeoutError on read (3.10+: socket.timeout
        # is an alias for TimeoutError and isn't a URLError subclass).
        print(f"GELF POST failed: {e}", file=sys.stderr)


# ── speedtest (Ookla) ─────────────────────────────────────────────────────
def run_speedtest() -> None:
    if SKIP_SPEEDTEST:
        print("  speedtest: skipped (SKIP_SPEEDTEST=1)")
        return
    bin_ = shutil.which("speedtest")
    if not bin_:
        print("  speedtest: binary not on PATH — skipping (install Ookla speedtest-cli)", file=sys.stderr)
        return
    try:
        r = subprocess.run(
            [bin_, "--format=json", "--accept-license", "--accept-gdpr"],
            capture_output=True, text=True, timeout=120,
        )
    except subprocess.TimeoutExpired:
        print("  speedtest: timed out", file=sys.stderr)
        return
    if r.returncode != 0 or not r.stdout.strip():
        print(f"  speedtest exit={r.returncode} stderr={r.stderr[:200]}",
              file=sys.stderr)
        return
    try:
        d = json.loads(r.stdout)
    except json.JSONDecodeError as exc:
        print(f"  speedtest JSON parse failed: {exc}", file=sys.stderr)
        return

    # Ookla returns bandwidth in bytes/sec.
    down_mbps = round((d.get("download", {}).get("bandwidth", 0) * 8) / 1_000_000, 2)
    up_mbps = round((d.get("upload", {}).get("bandwidth", 0) * 8) / 1_000_000, 2)
    ping = d.get("ping", {})
    server = d.get("server", {})
    iface = d.get("interface", {})

    gelf(
        f"speedtest: {down_mbps}↓ {up_mbps}↑ Mbps  {ping.get('latency', 0):.0f}ms",
        cp_event_type="speedtest",
        cp_speedtest_down_mbps=down_mbps,
        cp_speedtest_up_mbps=up_mbps,
        cp_speedtest_latency_ms=round(ping.get("latency", 0) or 0, 2),
        cp_speedtest_jitter_ms=round(ping.get("jitter", 0) or 0, 2),
        cp_speedtest_loss_pct=round(d.get("packetLoss", 0) or 0, 3),
        cp_speedtest_server=server.get("name"),
        cp_speedtest_server_id=server.get("id"),
        cp_speedtest_server_location=server.get("location"),
        cp_speedtest_isp=d.get("isp"),
        cp_speedtest_external_ip=iface.get("externalIp"),
        cp_speedtest_result_url=(d.get("result") or {}).get("url"),
    )
    print(f"  speedtest: down={down_mbps} up={up_mbps} latency={ping.get('latency'):.1f}")


# ── canary pings ──────────────────────────────────────────────────────────
def _parse_ping(stdout: str) -> dict[str, float] | None:
    # We want loss + the rtt min/avg/max/mdev summary lines.
    loss = None
    rtt = None
    for line in stdout.splitlines():
        if "packet loss" in line:
            # "10 packets transmitted, 10 received, 0% packet loss, time 9013ms"
            for tok in line.split(","):
                tok = tok.strip()
                if tok.endswith("packet loss"):
                    loss = float(tok.split("%", 1)[0].strip())
        if "rtt min/avg/max/mdev" in line or "round-trip min/avg/max/stddev" in line:
            # "rtt min/avg/max/mdev = 10.123/12.456/14.789/1.234 ms"
            try:
                vals = line.split("=", 1)[1].strip().split(" ", 1)[0]
                a, b, c, d = (float(x) for x in vals.split("/"))
                rtt = {"min": a, "avg": b, "max": c, "mdev": d}
            except (ValueError, IndexError):
                pass
    if loss is None:
        return None
    out: dict[str, float] = {"loss_pct": loss}
    if rtt:
        out.update(rtt)
    return out


def run_canaries() -> None:
    bin_ = shutil.which("ping")
    if not bin_:
        print("  canaries: ping binary missing — skipping", file=sys.stderr)
        return
    for target in CANARIES:
        try:
            r = subprocess.run(
                [bin_, "-c", str(PING_COUNT), "-w", "15", target],
                capture_output=True, text=True, timeout=30,
            )
        except subprocess.TimeoutExpired:
            print(f"  ping {target}: timed out", file=sys.stderr)
            gelf(f"ping_canary timeout {target}",
                 level=4, cp_event_type="ping_canary",
                 cp_canary_target=target, cp_canary_loss_pct=100.0)
            continue
        parsed = _parse_ping(r.stdout)
        if parsed is None:
            # No summary lines = ping failed before sending packets
            # (NXDOMAIN, "Network unreachable", "Name or service not
            # known"). Surface as 100% loss with a stderr snippet so
            # the dashboard's loss-pct widget catches it.
            err = (r.stderr or r.stdout).strip().splitlines()[-1:] if (r.stderr or r.stdout) else []
            err_msg = err[0][:200] if err else "unknown ping failure"
            print(f"  ping {target}: {err_msg}", file=sys.stderr)
            gelf(f"ping_canary {target}: {err_msg}",
                 level=4, cp_event_type="ping_canary",
                 cp_canary_target=target, cp_canary_loss_pct=100.0,
                 cp_canary_error=err_msg)
            continue
        gelf(
            f"ping {target}: loss={parsed['loss_pct']}% avg={parsed.get('avg', 0):.1f}ms",
            cp_event_type="ping_canary",
            cp_canary_target=target,
            cp_canary_loss_pct=parsed["loss_pct"],
            cp_canary_rtt_min_ms=parsed.get("min"),
            cp_canary_rtt_avg_ms=parsed.get("avg"),
            cp_canary_rtt_max_ms=parsed.get("max"),
            cp_canary_rtt_mdev_ms=parsed.get("mdev"),
        )
        print(f"  ping {target}: loss={parsed['loss_pct']}% avg={parsed.get('avg', 0):.1f}ms")


# ── DNS timing ────────────────────────────────────────────────────────────
def _time_dns(resolver_ip: str, query: str) -> float | None:
    # Use socket-level UDP DNS query; cheaper than spawning dig.
    # Build minimal A query.
    import struct, random
    txid = random.randint(0, 0xFFFF)
    header = struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    qname = b"".join(bytes([len(p)]) + p.encode() for p in query.split(".")) + b"\x00"
    qbody = qname + struct.pack(">HH", 1, 1)  # A, IN
    pkt = header + qbody
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(2.5)
    try:
        t0 = time.monotonic()
        s.sendto(pkt, (resolver_ip, 53))
        data, _ = s.recvfrom(512)
        elapsed_ms = (time.monotonic() - t0) * 1000
        if len(data) >= 2 and int.from_bytes(data[:2], "big") == txid:
            return round(elapsed_ms, 2)
        return None
    except (socket.timeout, OSError):
        return None
    finally:
        s.close()


def run_dns_timing() -> None:
    for r in DNS_RESOLVERS:
        # Resolve hostname-style entries (threatdefense.infoblox.com, etc.)
        # once per cycle. If the resolver itself is a hostname and we
        # can't resolve it, that's the signal — log it and move on.
        try:
            resolver_ip = socket.gethostbyname(r)
        except socket.gaierror:
            print(f"  dns {r}: hostname resolution failed", file=sys.stderr)
            gelf(f"dns_timing {r}: hostname unresolvable", level=4,
                 cp_event_type="dns_timing",
                 cp_dns_resolver=r, cp_dns_query_name=DNS_QUERY,
                 cp_dns_query_ms=2500.0)
            continue
        ms = _time_dns(resolver_ip, DNS_QUERY)
        common = {
            "cp_event_type": "dns_timing",
            "cp_dns_resolver": r,
            "cp_dns_resolver_ip": resolver_ip,
            "cp_dns_query_name": DNS_QUERY,
        }
        if ms is None:
            gelf(f"dns_timing {r}: timeout/error", level=4,
                 **common, cp_dns_query_ms=2500.0)
            print(f"  dns {r} ({resolver_ip}): timeout")
            continue
        gelf(f"dns_timing {r} {DNS_QUERY}: {ms}ms",
             **common, cp_dns_query_ms=ms)
        print(f"  dns {r} ({resolver_ip}): {ms}ms")


# ── WAN external IP probe ──────────────────────────────────────────────────
_IP_PROVIDERS = [
    ("ipify",       "https://api.ipify.org?format=json", "json", "ip"),
    ("icanhazip",   "https://icanhazip.com",             "text", None),
]


def run_wan_ip() -> None:
    for label, url, fmt, key in _IP_PROVIDERS:
        try:
            with request.urlopen(url, timeout=6) as r:
                body = r.read().decode().strip()
        except (error.URLError, error.HTTPError, OSError) as exc:
            print(f"  wan_ip {label}: {exc}", file=sys.stderr)
            continue
        if fmt == "json":
            try:
                ip = json.loads(body).get(key)
            except json.JSONDecodeError:
                ip = None
        else:
            ip = body
        if not ip:
            continue
        gelf(f"wan_ip via {label}: {ip}",
             cp_event_type="wan_ip",
             cp_wan_external_ip=ip,
             cp_wan_external_ip_source=label)
        print(f"  wan_ip ({label}): {ip}")
        return  # first success wins; second provider is just a fallback
    print("  wan_ip: all providers failed", file=sys.stderr)


def main() -> None:
    print(f"== wan-perf poller source={SOURCE!r} ==")
    run_wan_ip()
    run_canaries()
    run_dns_timing()
    run_speedtest()
    print("done.")


if __name__ == "__main__":
    main()
