"""Set up a NAS stream.

The NAS at 10.10.0.50 sends its own syslog to the shared UDP :514 input
(separate from the CEF DNS-events about it that go to UDDI). Three source
forms show up depending on rDNS state at the time of parsing: `nas`,
`nas.darknetian.com`, and bare `10.10.0.50`. ~12K msgs/day combined —
worth lifting out of Default so a future NAS dashboard has a clean stream
to attach to.

No new index set — volume is low and field cardinality is modest, default
`graylog_*` is fine. Stream is configured to remove matches from Default
so messages land in exactly one place.

Idempotent. Run after sourcing env.sh:
    python3 indexing/nas.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))
import graylog as gl  # noqa: E402

STREAM_TITLE = "NAS"
DEFAULT_INDEX_SET_ID = "697bc531578e7b6843600cba"   # 'Default index set'
SYSLOG_INPUT_ID = "697ef8d7eeb15b769f444708"        # 'ESXI 7 (Syslog UDP)' :514
NAS_SOURCE_FORMS = ["nas", "nas.darknetian.com", "10.10.0.50"]


def find_stream(title: str) -> dict | None:
    for s in (gl.api("GET", "streams") or {}).get("streams", []):
        if s.get("title") == title:
            return s
    return None


def main() -> None:
    print(f"== Setting up '{STREAM_TITLE}' stream ==")
    existing = find_stream(STREAM_TITLE)
    if existing:
        print(f"  stream exists: id={existing['id']}")
        return

    body = {
        "title": STREAM_TITLE,
        "description": (
            "NAS-side syslog from 10.10.0.50. Filters by source IN (nas, "
            "nas.darknetian.com, 10.10.0.50) AND gl2_source_input = the "
            "UDP :514 syslog input. The input-id check excludes the CEF "
            "DNS-events about NAS (which go to the UDDI stream instead)."
        ),
        "index_set_id": DEFAULT_INDEX_SET_ID,
        "remove_matches_from_default_stream": True,
        "matching_type": "AND",
        "rules": [
            # Must come from the syslog UDP input (not the CEF input)
            {"field": "gl2_source_input", "type": 1, "value": SYSLOG_INPUT_ID,
             "inverted": False, "description": "via UDP :514 syslog input"},
            # AND source matches one of the NAS hostname/IP forms.
            # With matching_type=AND on a single stream, we can't OR multiple
            # source values inline — but rule type 2 is regex match, so use one
            # regex that covers all three forms.
            {"field": "source", "type": 2,
             "value": "^(nas|nas\\.darknetian\\.com|10\\.10\\.0\\.50)$",
             "inverted": False,
             "description": "any rDNS form of the NAS host"},
        ],
    }
    resp = gl.api("POST", "streams", body)
    sid = resp["stream_id"]
    print(f"  created stream: id={sid}")
    gl.api("POST", f"streams/{sid}/resume")
    print("  stream resumed")


if __name__ == "__main__":
    main()
