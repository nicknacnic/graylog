"""Set up a NAS stream.

The Synology at 10.10.0.50 sends DSM syslog to the shared UDP :514 input.
The `source` field arrives as either `nas` or `nas.darknetian.com`
depending on rDNS-cache state at parse time — both rules below are
exact-match, joined by OR, so we capture either form.

The IP-form `10.10.0.50` is *not* a NAS-syslog source. That traffic is
UDDI CEF DNS-events ABOUT queries originating from the NAS, and lives
correctly in the UDDI stream — including it here would mix two unrelated
event families.

History: the original version used matching_type=AND with a
`gl2_source_input` rule + a regex source rule. `gl2_source_input` is a
Graylog-internal control field and doesn't behave like a normal field
during stream-rule evaluation — messages that should have matched landed
in zero streams. The clean fix is matching_type=OR with two exact rules.

No new index set — volume is low (a few hundred msgs/day) and field
cardinality is modest, default `graylog_*` is fine. Stream is configured
to remove matches from Default so messages land in exactly one place.

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
NAS_SOURCE_FORMS = ["nas", "nas.darknetian.com"]


def find_stream(title: str) -> dict | None:
    for s in (gl.api("GET", "streams") or {}).get("streams", []):
        if s.get("title") == title:
            return s
    return None


def main() -> None:
    print(f"== Setting up '{STREAM_TITLE}' stream ==")
    existing = find_stream(STREAM_TITLE)
    if existing:
        print(f"  stream exists: id={existing['id']} (rules not modified)")
        return

    body = {
        "title": STREAM_TITLE,
        "description": (
            "Synology DSM syslog from 10.10.0.50. Source matches nas OR "
            "nas.darknetian.com (rDNS varies). 10.10.0.50 IP-form excluded "
            "because that traffic is UDDI CEF DNS-events ABOUT the NAS."
        ),
        "index_set_id": DEFAULT_INDEX_SET_ID,
        "remove_matches_from_default_stream": True,
        "matching_type": "OR",
        "rules": [
            {"field": "source", "type": 1, "value": src,
             "inverted": False, "description": f"Synology hostname: {src}"}
            for src in NAS_SOURCE_FORMS
        ],
    }
    resp = gl.api("POST", "streams", body)
    sid = resp["stream_id"]
    print(f"  created stream: id={sid}")
    gl.api("POST", f"streams/{sid}/resume")
    print("  stream resumed")


if __name__ == "__main__":
    main()
