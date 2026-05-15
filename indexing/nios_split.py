"""Split the NIOS member-syslog firehose by service type.

Today, NIOS members 10.10.0.57 (ddi.darknetian.com) and 10.10.0.253
(ns1.darknetian.com) emit a mixed stream — BIND auth (`named[…]`),
DHCP (`dhcpd[…]`), admin UI (`httpd[…]`), and a long tail of system
syslog — and the existing per-host streams catch all of it
together. That makes any DNS-scoped widget see DHCP failover chatter,
and vice versa.

This script creates two service-scoped streams that route the same
underlying messages by syslog process name:

  NIOS DNS (auth)   — BIND `named[…]` from both DNS-serving NIOS members
                      Use this on the dashboard's Auth-DNS page.
  NIOS DHCP         — `dhcpd[…]` from the same hosts
                      Use this on the dashboard's DHCP page.

Per-host streams are NOT touched (additive change). Graylog allows a
message to live in multiple streams, so the existing dashboards keep
working and the new ones see only what they're scoped for.

Idempotent. Re-running on a healthy instance is a no-op.

Run after sourcing env.sh:
    python3 indexing/nios_split.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))
import graylog as gl  # noqa: E402

# These two NIOS members are the auth-DNS + DHCP servers.
NIOS_DNS_DHCP_SOURCES = "^(10\\.10\\.0\\.(57|253)|(ddi|ns1)\\.darknetian\\.com)$"

# The 'Infoblox NIOS' index set we already use for all the per-host
# NIOS streams — service-split streams write to the same shard pool.
def find_index_set_id(title: str) -> str:
    for s in (gl.api("GET", "system/indices/index_sets") or {}).get("index_sets", []):
        if s.get("title") == title:
            return s["id"]
    raise SystemExit(f"index set {title!r} not found")


def find_stream(title: str) -> dict | None:
    for s in (gl.api("GET", "streams") or {}).get("streams", []):
        if s.get("title") == title:
            return s
    return None


def ensure_stream(title: str, description: str, index_set_id: str,
                  process_regex: str) -> str:
    existing = find_stream(title)
    if existing:
        print(f"  stream exists: {title!r} id={existing['id']}")
        return existing["id"]
    body = {
        "title": title,
        "description": description,
        "index_set_id": index_set_id,
        "remove_matches_from_default_stream": False,  # additive — per-host streams still catch these too
        "matching_type": "AND",
        "rules": [
            {"field": "source", "type": 2, "value": NIOS_DNS_DHCP_SOURCES,
             "inverted": False,
             "description": "DNS/DHCP-serving NIOS members"},
            {"field": "message", "type": 2, "value": process_regex,
             "inverted": False,
             "description": "syslog process name in message body"},
        ],
    }
    resp = gl.api("POST", "streams", body)
    sid = resp["stream_id"]
    print(f"  created stream: {title!r} id={sid}")
    gl.api("POST", f"streams/{sid}/resume")
    print(f"  resumed {title!r}")
    return sid


def main() -> None:
    print("== Splitting NIOS streams by service ==")
    idx_set_id = find_index_set_id("Infoblox NIOS")
    print(f"  using index set id={idx_set_id}")

    ensure_stream(
        "NIOS DNS (auth)",
        "BIND auth-DNS events (`named[pid]:…`) from the DNS-serving "
        "NIOS members (10.10.0.57 and 10.10.0.253). Same underlying "
        "messages as the per-host streams, scoped to DNS only so the "
        "Auth-DNS dashboard page isn't polluted by DHCP/admin chatter.",
        idx_set_id,
        process_regex="\\bnamed\\[\\d+\\]",
    )
    ensure_stream(
        "NIOS DHCP",
        "ISC dhcpd events (`dhcpd[pid]:…`) from the DHCP-serving NIOS "
        "members. Failover peer messages, lease grants/expires, scope "
        "warnings. Routes the same messages as the per-host streams; "
        "use this for DHCP-scoped dashboards.",
        idx_set_id,
        process_regex="\\bdhcpd\\[\\d+\\]",
    )
    print("done.")


if __name__ == "__main__":
    main()
