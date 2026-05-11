"""Set up the iDRAC Redfish indexing path on Graylog.

Mirrors indexing/ilo_redfish.py but for the Dell iDRAC poller's output.

Idempotent. Creates (or updates):
  1. Index set 'iDRAC Redfish' (prefix idrac-redfish, 1/0 shards, 30d retention).
  2. Stream 'iDRAC Redfish' that matches:
       source = idrac.darknetian.com  AND
       idrac_event_type field present
     Writes to the new index set; removes matches from the default stream.

Run after sourcing env.sh:
    python3 indexing/idrac_redfish.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))
import graylog as gl  # noqa: E402

INDEX_SET_TITLE = "iDRAC Redfish"
INDEX_PREFIX = "idrac-redfish"
STREAM_TITLE = "iDRAC Redfish"
IDRAC_HOST = "idrac.darknetian.com"


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
        "description": "Dedicated index for Dell iDRAC Redfish poller output. "
                       "Has its own mapping limit so idrac_* fields don't strain "
                       "the default index.",
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


def create_redfish_stream(index_set_id: str) -> str:
    existing = find_stream(STREAM_TITLE)
    if existing:
        print(f"  stream exists: id={existing['id']}")
        return existing["id"]
    body = {
        "title": STREAM_TITLE,
        "description": "Dell iDRAC Redfish poller events (health snapshots + Lclog/Sel entries)",
        "index_set_id": index_set_id,
        "remove_matches_from_default_stream": True,
        "rules": [
            {"field": "source", "type": 1, "value": IDRAC_HOST, "inverted": False,
             "description": "exact source"},
            {"field": "idrac_event_type", "type": 5, "value": "", "inverted": False,
             "description": "Redfish event"},
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
    print("== Setting up iDRAC Redfish indexing ==")
    print("1. index set")
    idx_id = create_index_set()
    print("2. stream")
    create_redfish_stream(idx_id)
    print("done.")


if __name__ == "__main__":
    main()
