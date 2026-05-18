"""Set up the infoblox-nios-ip-to-mac CSV lookup chain.

Maps client IPs to their NIOS-known MAC addresses (record:host
ipv4addrs + fixedaddress). Used by the MAC Enrichment pipeline to
derive client_mac for events that only have a client IP (e.g. dnstap,
UDDI CEF DNS Response), so the downstream `mac enrich client_mac` rule
can resolve the DHCP hostname.

CSV is rebuilt by tools/nios_ip_to_mac_csv.py (run hourly alongside
the existing MAC and PTR exporters).
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))
import graylog as gl  # noqa: E402

NAME = "infoblox-nios-ip-to-mac"
CSV_PATH = "/etc/graylog/server/lookups/ip_to_mac.csv"


def find_existing(kind: str, name: str) -> dict | None:
    for item in (gl.api("GET", f"system/lookup/{kind}?per_page=500") or {}).get(
        {"adapters": "data_adapters", "caches": "caches",
         "tables": "lookup_tables"}[kind], []
    ):
        if item.get("name") == name:
            return item
    return None


def ensure_adapter() -> str:
    existing = find_existing("adapters", NAME)
    if existing:
        print(f"  adapter exists: id={existing['id']}")
        return existing["id"]
    body = {
        "title": NAME, "name": NAME,
        "description": "CSV-file IP → MAC mapping from Infoblox NIOS "
                       "(record:host ipv4addrs + fixedaddress).",
        "content_pack": None,
        "config": {
            "type": "csvfile",
            "path": CSV_PATH,
            "separator": ",",
            "quotechar": "\"",
            "key_column": "ip",
            "value_column": "mac",
            "check_interval": 60,
            "case_insensitive_lookup": False,
            "cidr_lookup": False,
        },
    }
    resp = gl.api("POST", "system/lookup/adapters", body)
    print(f"  created adapter: id={resp['id']}")
    return resp["id"]


def ensure_cache() -> str:
    existing = find_existing("caches", NAME)
    if existing:
        print(f"  cache exists: id={existing['id']}")
        return existing["id"]
    body = {
        "title": NAME, "name": NAME,
        "description": "Guava cache for IP → MAC lookup",
        "content_pack": None,
        "config": {
            "type": "guava_cache",
            "max_size": 1000,
            "expire_after_access": 5,
            "expire_after_access_unit": "MINUTES",
            "expire_after_write": 0,
            "expire_after_write_unit": None,
            "ignore_null": False,
            "ttl_empty": None, "ttl_empty_unit": None,
        },
    }
    resp = gl.api("POST", "system/lookup/caches", body)
    print(f"  created cache: id={resp['id']}")
    return resp["id"]


def ensure_table(adapter_id: str, cache_id: str) -> str:
    existing = find_existing("tables", NAME)
    if existing:
        print(f"  lookup table exists: id={existing['id']}")
        return existing["id"]
    body = {
        "title": NAME, "name": NAME,
        "description": "IP → MAC (NIOS host ipv4addrs + fixedaddress)",
        "content_pack": None,
        "cache_id": cache_id,
        "data_adapter_id": adapter_id,
        "default_single_value": "",
        "default_single_value_type": "NULL",
        "default_multi_value": "",
        "default_multi_value_type": "NULL",
    }
    resp = gl.api("POST", "system/lookup/tables", body)
    print(f"  created table: id={resp['id']}")
    return resp["id"]


def main() -> None:
    print(f"== Setting up '{NAME}' lookup chain ==")
    adapter_id = ensure_adapter()
    cache_id = ensure_cache()
    ensure_table(adapter_id, cache_id)
    print(f"done.")


if __name__ == "__main__":
    main()
