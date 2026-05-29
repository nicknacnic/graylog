"""Home Assistant stream + dedicated index set.

The ha-log-poller (pollers/ha_log_poller.py) ships WARN+ entries from
Home Assistant's /api/hassio/core/logs with GELF host=ha-darknetian.
Before this script those events landed on the default stream alongside
random noise; this gives them their own stream + 'home_assistant_*'
index so the HA dashboard's queries don't have to share filter scope
with everything else, and so retention can be tuned independently of
the catch-all default index.

Volume is low (~1500/day at WARN+), so this is a stream-and-narrow-
index pair rather than the heavier per-shard layout used for VMware
or NIOS DNS.

Idempotent — run after sourcing env.sh:
    python3 indexing/ha.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))
import graylog as gl  # noqa: E402

SOURCE = "ha-darknetian"
STREAM_TITLE = "Home Assistant"


def ensure_stream(index_set_id: str) -> str:
    existing = next(
        (s for s in (gl.api("GET", "streams") or {}).get("streams", [])
         if s.get("title") == STREAM_TITLE),
        None,
    )
    if existing:
        print(f"  stream exists: id={existing['id']}")
        return existing["id"]
    body = {
        "title": STREAM_TITLE,
        "description": (
            "Home Assistant core logs (WARN+ entries from "
            "/api/hassio/core/logs, shipped by ha-log-poller as GELF "
            "with host=ha-darknetian)."
        ),
        "index_set_id": index_set_id,
        "remove_matches_from_default_stream": True,
        "matching_type": "AND",
        "rules": [
            {"field": "source", "type": 1, "value": SOURCE, "inverted": False,
             "description": "GELF host of the ha-log-poller"},
        ],
    }
    resp = gl.api("POST", "streams", body)
    sid = resp["stream_id"]
    print(f"  created stream: id={sid}")
    gl.api("POST", f"streams/{sid}/resume")
    print("  stream resumed")
    return sid


def main() -> None:
    print("== Setting up Home Assistant indexing ==")
    idx_id = gl.ensure_index_set(
        title="Home Assistant",
        prefix="home_assistant",
        description=(
            "Home Assistant WARN/ERROR/CRITICAL log entries from the "
            "ha-log-poller. Low-volume; tight retention is fine."
        ),
        shards=1,
        retention_days=60,
        max_indices=6,
    )
    ensure_stream(idx_id)
    print("done.")


if __name__ == "__main__":
    main()
