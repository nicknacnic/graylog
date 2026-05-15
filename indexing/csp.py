"""Set up the Infoblox CSP (Cube/IQ metrics) indexing path on Graylog.

Mirrors indexing/cloudflare.py shape. Creates:
  1. Index set 'Infoblox CSP' (prefix infoblox-csp, 1/0 shards, 30d retention)
  2. Stream 'Infoblox CSP' matching source='csp-infoblox-com' AND
     csp_metric IS SET (so any unrelated message accidentally tagged
     with that source still won't match)

Idempotent. Run after sourcing env.sh:
    python3 indexing/csp.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))
import graylog as gl  # noqa: E402

INDEX_SET_TITLE = "Infoblox CSP"
INDEX_PREFIX = "infoblox-csp"
STREAM_TITLE = "Infoblox CSP"
CSP_HOST = "csp-infoblox-com"


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
        "description": "Dedicated index for Infoblox CSP CubeJS poller output "
                       "(Infoblox IQ-computed *_iq health metrics — cache hit "
                       "ratio, DNS QPS, NX/SERVFAIL/REFUSED %, upstream latency, "
                       "DDNS rate, plus per-host CPU/memory).",
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
        "description": "Infoblox CSP CubeJS poller events. *_iq metrics from "
                       "the Infoblox IQ analytics layer (cache_hit_ratio, "
                       "dns_qps, NX/SERVFAIL %, host CPU/mem). Polled every "
                       "5 min by csp-poller on the Graylog VM.",
        "index_set_id": index_set_id,
        "remove_matches_from_default_stream": True,
        "rules": [
            {"field": "source", "type": 1, "value": CSP_HOST,
             "inverted": False, "description": "exact source"},
            {"field": "csp_metric", "type": 5, "value": "",
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
    print("== Setting up Infoblox CSP indexing ==")
    print("1. index set")
    idx_id = create_index_set()
    print("2. stream")
    create_stream(idx_id)
    print("done.")


if __name__ == "__main__":
    main()
