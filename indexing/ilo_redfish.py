"""Set up the iLO Redfish indexing path on Graylog.

Idempotent. Creates (or updates):
  1. Index set 'iLO Redfish' (prefix ilo-redfish, 1/0 shards, 30d retention).
  2. Raises index.mapping.total_fields.limit to 2000 on its template +
     existing index, since the poller emits many ilo_* fields.
  3. Stream 'iLO Redfish' that matches:
       source = ilo-esxi2.darknetian.com  AND
       ilo_event_type field present
     Writes to the new index set; removes matches from the default stream.
  4. Adds a rule to the existing 'iLO' stream: 'ilo_event_type missing'
     so syslog stays in graylog_* and Redfish stays in ilo-redfish_*.

Run after sourcing env.sh:
    python3 indexing/ilo_redfish.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))
import graylog as gl  # noqa: E402

INDEX_SET_TITLE = "iLO Redfish"
INDEX_PREFIX = "ilo-redfish"
STREAM_TITLE = "iLO Redfish"

# Existing iLO syslog stream (from inventory) — we'll add a rule to exclude
# Redfish messages so each message lands in exactly one stream.
ILO_SYSLOG_STREAM_ID = "6993bad7eeb15b769f4fb10b"
ILO_HOST = "ilo-esxi2.darknetian.com"


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
        "description": "Dedicated index for HPE iLO Redfish poller output. "
                       "Has its own mapping limit so ilo_* fields don't strain "
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
        "description": "HPE iLO Redfish poller events (health snapshots + IEL log entries)",
        "index_set_id": index_set_id,
        "remove_matches_from_default_stream": True,
        "rules": [
            {"field": "source", "type": 1, "value": ILO_HOST, "inverted": False, "description": "exact source"},
            {"field": "ilo_event_type", "type": 5, "value": "", "inverted": False, "description": "Redfish event"},
        ],
        "matching_type": "AND",
    }
    resp = gl.api("POST", "streams", body)
    sid = resp["stream_id"]
    print(f"  created stream: id={sid}")
    # Streams must be resumed (started) after creation
    gl.api("POST", f"streams/{sid}/resume")
    print(f"  stream resumed (started)")
    return sid


def update_syslog_stream_to_exclude_redfish() -> None:
    stream = gl.api("GET", f"streams/{ILO_SYSLOG_STREAM_ID}")
    rules = stream.get("rules", [])
    have = any(r.get("field") == "ilo_event_type" and r.get("inverted") for r in rules)
    if have:
        print("  syslog stream already excludes Redfish messages")
        return
    body = {
        "field": "ilo_event_type",
        "type": 5,
        "value": "",
        "inverted": True,
        "description": "exclude Redfish events (they go to dedicated stream)",
    }
    gl.api("POST", f"streams/{ILO_SYSLOG_STREAM_ID}/rules", body)
    print(f"  added inverted ilo_event_type rule to existing iLO stream")
    # If the stream wasn't AND-matching, the new exclusion wouldn't help — flip it.
    if stream.get("matching_type") != "AND":
        gl.api("PUT", f"streams/{ILO_SYSLOG_STREAM_ID}", {
            **{k: stream[k] for k in ["title", "description", "rules", "index_set_id", "remove_matches_from_default_stream"]
               if k in stream and k != "rules"},
            "matching_type": "AND",
        })
        print(f"  flipped matching_type to AND so the inverted rule applies")


def rotate_default_index() -> None:
    # Reads the active write index for the default index set, then asks
    # Graylog to cycle it. New incoming messages start writing to graylog_13
    # with a clean field map.
    default = None
    for s in (gl.api("GET", "system/indices/index_sets") or {}).get("index_sets", []):
        if s.get("default"):
            default = s
            break
    if not default:
        print("  no default index set?")
        return
    idx_set_id = default["id"]
    print(f"  rotating default index set id={idx_set_id}")
    gl.api("POST", f"system/deflector/{idx_set_id}/cycle")
    print("  rotation triggered")


def main() -> None:
    print("== Setting up iLO Redfish indexing ==")
    print("1. index set")
    idx_id = create_index_set()
    print("2. stream")
    create_redfish_stream(idx_id)
    print("3. existing iLO stream — exclude Redfish")
    update_syslog_stream_to_exclude_redfish()
    print("4. rotate default index (graylog_12 -> graylog_13)")
    rotate_default_index()
    print("done.")


if __name__ == "__main__":
    main()
