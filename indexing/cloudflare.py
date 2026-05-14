"""Set up the Cloudflare indexing path on Graylog.

Mirrors indexing/idrac_redfish.py shape. The poller emits one GELF
message per zone bucket, plus per-event firewall + audit log entries —
fairly low volume (5-min buckets) so no special index sizing concerns.

Idempotent. Creates (or updates):
  1. Index set 'Cloudflare' (prefix cloudflare, 1/0 shards, 30d
     retention).
  2. Stream 'Cloudflare' matching:
       source starts with 'cloudflare-'
     Achieved with a regex source rule so both per-zone messages
     (cloudflare-darknetian.com, cloudflare-darknetian.net) and
     account-level audits (cloudflare-account) land in the same stream.

Run after sourcing env.sh:
    python3 indexing/cloudflare.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))
import graylog as gl  # noqa: E402

INDEX_SET_TITLE = "Cloudflare"
INDEX_PREFIX = "cloudflare"
STREAM_TITLE = "Cloudflare"


def find_index_set() -> dict | None:
    sets = gl.api("GET", "system/indices/index_sets") or {}
    for s in sets.get("index_sets", []):
        if s.get("title") == INDEX_SET_TITLE:
            return s
    return None


def create_index_set() -> str:
    existing = find_index_set()
    if existing:
        print(f"  index set exists: id={existing['id']} prefix={existing['index_prefix']}")
        return existing["id"]
    body = {
        "title": INDEX_SET_TITLE,
        "description": "Dedicated index for Cloudflare poller output "
                       "(traffic analytics, firewall events, DNS analytics, "
                       "and account-level audit logs).",
        "index_prefix": INDEX_PREFIX,
        "shards": 1,
        "replicas": 0,
        "index_analyzer": "standard",
        "index_optimization_max_num_segments": 1,
        "index_optimization_disabled": False,
        "field_type_refresh_interval": 5000,
        "rotation_strategy_class": "org.graylog2.indexer.rotation.strategies.TimeBasedSizeOptimizingStrategy",
        "rotation_strategy": {
            "type": "org.graylog2.indexer.rotation.strategies.TimeBasedSizeOptimizingStrategyConfig",
            "index_lifetime_min": "P30D",
            "index_lifetime_max": "P40D",
        },
        "retention_strategy_class": "org.graylog2.indexer.retention.strategies.DeletionRetentionStrategy",
        "retention_strategy": {
            "type": "org.graylog2.indexer.retention.strategies.DeletionRetentionStrategyConfig",
            "max_number_of_indices": 6,
        },
        "data_tiering": {
            "type": "hot_only",
            "index_lifetime_min": "P30D",
            "index_lifetime_max": "P40D",
        },
        "writable": True,
        "can_be_default": False,
    }
    resp = gl.api("POST", "system/indices/index_sets", body)
    print(f"  created index set: id={resp['id']} prefix={resp['index_prefix']}")
    return resp["id"]


def find_stream(title: str) -> dict | None:
    streams = gl.api("GET", "streams") or {}
    for s in streams.get("streams", []):
        if s.get("title") == title:
            return s
    return None


def create_stream(index_set_id: str) -> str:
    existing = find_stream(STREAM_TITLE)
    if existing:
        print(f"  stream exists: id={existing['id']}")
        return existing["id"]
    body = {
        "title": STREAM_TITLE,
        "description": "Cloudflare poller events: per-zone traffic/firewall/DNS "
                       "analytics + account-level audit logs. All sources start "
                       "with 'cloudflare-' (e.g. cloudflare-darknetian.com, "
                       "cloudflare-darknetian.net, cloudflare-account).",
        "index_set_id": index_set_id,
        "remove_matches_from_default_stream": True,
        "rules": [
            # Regex match on source: cloudflare-<anything>
            {"field": "source", "type": 2, "value": "^cloudflare-",
             "inverted": False, "description": "any cloudflare-* source"},
            # Guard: must have cf_event_type field set (so any unrelated
            # message that happens to have a cloudflare-* source still
            # wouldn't match unless it's from our poller)
            {"field": "cf_event_type", "type": 5, "value": "",
             "inverted": False, "description": "poller event marker"},
        ],
        "matching_type": "AND",
    }
    resp = gl.api("POST", "streams", body)
    sid = resp["stream_id"]
    print(f"  created stream: id={sid}")
    gl.api("POST", f"streams/{sid}/resume")
    print("  stream resumed (started)")
    return sid


def main() -> None:
    print("== Setting up Cloudflare indexing ==")
    print("1. index set")
    idx_id = create_index_set()
    print("2. stream")
    create_stream(idx_id)
    print("done.")


if __name__ == "__main__":
    main()
