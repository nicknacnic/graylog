"""Create the Graylog lookup-table chain for MAC → hostname enrichment.

Mirrors the existing `infoblox-nios-ptr` lookup's shape:
  - CSV file data adapter pointing at /etc/graylog/server/lookups/mac_to_hostname.csv
  - Guava cache (5-minute access TTL, 1000 entries)
  - Lookup table tying them together

The CSV is produced by /usr/local/sbin/nios_mac_to_graylog_csv.py (driven by
the systemd timer nios-mac-export.timer).

Idempotent. Run after sourcing env.sh:
    python3 lookups/mac_to_hostname.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))
import graylog as gl  # noqa: E402

NAME = "infoblox-nios-mac"
CSV_PATH = "/etc/graylog/server/lookups/mac_to_hostname.csv"


def find_existing(kind: str, name: str) -> dict | None:
    """kind: 'adapters' | 'caches' | 'tables'"""
    for item in (gl.api("GET", f"system/lookup/{kind}?per_page=500") or {}).get(
        {"adapters": "data_adapters", "caches": "caches", "tables": "lookup_tables"}[kind], []
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
        "title": NAME,
        "name": NAME,
        "description": "CSV-file MAC → hostname mapping from Infoblox NIOS DHCP",
        "content_pack": None,
        "config": {
            "type": "csvfile",
            "path": CSV_PATH,
            "separator": ",",
            "quotechar": "\"",
            "key_column": "mac",
            "value_column": "hostname",
            "check_interval": 60,
            "case_insensitive_lookup": True,
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
        "title": NAME,
        "name": NAME,
        "description": "Guava cache for MAC → hostname lookup",
        "content_pack": None,
        "config": {
            "type": "guava_cache",
            "max_size": 1000,
            "expire_after_access": 5,
            "expire_after_access_unit": "MINUTES",
            "expire_after_write": 0,
            "expire_after_write_unit": None,
            "ignore_null": False,
            "ttl_empty": None,
            "ttl_empty_unit": None,
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
        "title": NAME,
        "name": NAME,
        "description": "MAC → DHCP hostname (Infoblox NIOS fixedaddrs + leases)",
        "content_pack": None,
        "cache_id": cache_id,
        "data_adapter_id": adapter_id,
        "default_single_value": "unknown",
        "default_single_value_type": "STRING",
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
    print(f"done. Use lookup_value(\"{NAME}\", <mac>) in pipeline rules.")


if __name__ == "__main__":
    main()
