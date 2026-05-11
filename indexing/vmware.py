"""Migrate the ESXi/vCenter stream to a dedicated 'VMware' index set.

vCenter and the ESXi hosts are by far the highest-volume + highest-field-
cardinality source on this Graylog (2.2M msgs/day, dozens of unique
application_name values, each adding fields). Keeping them on the default
index set is what caused the 1000-field cap to be hit on graylog_12.

What this does:
  1. Creates index set 'VMware' (prefix 'vmware', 2 shards, 0 replicas,
     14-day retention).
  2. Switches the existing 'ESXi' stream (id 697e9e92eeb15b769f43098c) to
     use that index set. Future ESXi messages write to vmware_*, leaving
     graylog_* fresh for everything else.

Idempotent. Run after sourcing env.sh:
    python3 indexing/vmware.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))
import graylog as gl  # noqa: E402

INDEX_SET_TITLE = "VMware"
INDEX_PREFIX = "vmware"
ESXI_STREAM_ID = "697e9e92eeb15b769f43098c"


def find_index_set(title: str) -> dict | None:
    for s in (gl.api("GET", "system/indices/index_sets") or {}).get("index_sets", []):
        if s.get("title") == title:
            return s
    return None


def create_index_set() -> str:
    existing = find_index_set(INDEX_SET_TITLE)
    if existing:
        print(f"  index set exists: id={existing['id']}")
        return existing["id"]
    body = {
        "title": INDEX_SET_TITLE,
        "description": (
            "Dedicated index for VMware ESXi + vCenter syslog. High message "
            "volume and high field cardinality (~dozens of vCSA app names, "
            "each with their own log schema)."
        ),
        "index_prefix": INDEX_PREFIX,
        "shards": 2,
        "replicas": 0,
        "index_analyzer": "standard",
        "index_optimization_max_num_segments": 1,
        "index_optimization_disabled": False,
        "field_type_refresh_interval": 5000,
        "rotation_strategy_class": "org.graylog2.indexer.rotation.strategies.TimeBasedSizeOptimizingStrategy",
        "rotation_strategy": {
            "type": "org.graylog2.indexer.rotation.strategies.TimeBasedSizeOptimizingStrategyConfig",
            "index_lifetime_min": "P14D",
            "index_lifetime_max": "P20D",
        },
        "retention_strategy_class": "org.graylog2.indexer.retention.strategies.DeletionRetentionStrategy",
        "retention_strategy": {
            "type": "org.graylog2.indexer.retention.strategies.DeletionRetentionStrategyConfig",
            "max_number_of_indices": 3,
        },
        "data_tiering": {
            "type": "hot_only",
            "index_lifetime_min": "P14D",
            "index_lifetime_max": "P20D",
        },
        "writable": True,
        "can_be_default": False,
    }
    resp = gl.api("POST", "system/indices/index_sets", body)
    print(f"  created index set: id={resp['id']} prefix={resp['index_prefix']} ~14d retention, 2 shards")
    return resp["id"]


def repoint_esxi_stream(index_set_id: str) -> None:
    stream = gl.api("GET", f"streams/{ESXI_STREAM_ID}")
    if stream.get("index_set_id") == index_set_id:
        print(f"  ESXi stream already on this index set")
        return
    # PUT requires the full stream body
    body = {
        "title": stream["title"],
        "description": stream.get("description") or "",
        "matching_type": stream.get("matching_type", "AND"),
        "rules": [
            {k: r[k] for k in ("field", "type", "value", "inverted", "description") if k in r}
            for r in stream.get("rules", [])
        ],
        "remove_matches_from_default_stream": stream.get("remove_matches_from_default_stream", False),
        "index_set_id": index_set_id,
    }
    gl.api("PUT", f"streams/{ESXI_STREAM_ID}", body)
    print(f"  ESXi stream switched to index set {index_set_id}")


def main() -> None:
    print("== Migrating ESXi/vCenter to its own index set ==")
    idx_id = create_index_set()
    repoint_esxi_stream(idx_id)
    print("done. New ESXi messages will write to vmware_*.")
    print("Existing data stays in graylog_* until aged out by retention.")


if __name__ == "__main__":
    main()
