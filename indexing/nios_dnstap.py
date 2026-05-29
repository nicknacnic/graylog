"""Set up the NIOS dnstap indexing path.

Bridge (pollers/dnstap_bridge.py via dnscollector) emits every dnstap
event as GELF with `source: nios-dnstap`. This script creates:

  1. Index set 'NIOS dnstap' — dedicated, 1/0 shards, 30d retention,
     field-count limit bumped so per-RR resource-record fields can
     coexist without bumping the default index past 1000.
  2. Stream 'NIOS dnstap' matching source:nios-dnstap, with
     remove-from-default-stream so events don't double-index.

Run after sourcing env.sh:
    python3 indexing/nios_dnstap.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))
import graylog as gl  # noqa: E402

INDEX_SET_TITLE = "NIOS dnstap"
INDEX_PREFIX = "dnstap"
STREAM_TITLE = "NIOS dnstap"


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
        "description": "NIOS dnstap events from every grid member with "
                       "dnstap-output enabled. dnscollector receives "
                       "fstrm frames on :6000; bridge reshapes to GELF "
                       "with source=nios-dnstap.",
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
        "description": "Per-query dnstap events forwarded by every NIOS "
                       "grid member with dnstap-output enabled, decoded "
                       "by dnscollector and reshaped to GELF by the "
                       "dnstap-collector bridge.",
        "index_set_id": index_set_id,
        "remove_matches_from_default_stream": True,
        "rules": [
            # Regex prefix so the bridge AND the unanswered-query
            # poller (source=nios-dnstap-unanswered) both land here.
            {"field": "source", "type": 2, "value": "^nios-dnstap",
             "inverted": False,
             "description": "bridge source label + nios-dnstap-* siblings"},
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
    print("== Setting up NIOS dnstap indexing ==")
    idx = create_index_set()
    create_stream(idx)
    print("done.")


if __name__ == "__main__":
    main()
