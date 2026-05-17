"""Set up two NAS streams.

The Synology at 10.10.0.50 sends DSM syslog to the shared UDP :514 input.
The `source` field arrives as one of three forms depending on rDNS-cache
state at parse time:

  - `nas`                  — short hostname (BSD header used as-is)
  - `nas.darknetian.com`   — PTR succeeded, full FQDN
  - `10.10.0.50`           — PTR failed, IP-form fallback

Graylog stream rules don't support nested AND/OR groups in a single
stream, so we use two streams that both route to the same index set:

  1. "NAS"           — matching_type=OR, exact-matches on `nas` /
                       `nas.darknetian.com`. Catches the rDNS-resolved
                       messages.
  2. "NAS (IP-form)" — matching_type=AND with rules:
                         source = 10.10.0.50
                         field absent: device_vendor
                       The absent-field rule disambiguates from the
                       UDDI CEF "Infoblox Data Connector" traffic that
                       *also* has source=10.10.0.50 but arrives on the
                       CEF TCP input with device_vendor=Infoblox set.

Dashboards/pipelines must reference BOTH streams.

History: the original version used matching_type=AND with a
`gl2_source_input` rule + a regex source rule. `gl2_source_input` is a
Graylog-internal control field and doesn't behave like a normal field
during stream-rule evaluation — messages that should have matched
landed in zero streams. The clean fix is per above.

No new index set — volume is modest and field cardinality is low,
default `graylog_*` is fine. Streams are configured to remove matches
from Default so messages land in exactly one place.

Idempotent. Run after sourcing env.sh:
    python3 indexing/nas.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))
import graylog as gl  # noqa: E402

DEFAULT_INDEX_SET_ID = "697bc531578e7b6843600cba"   # 'Default index set'

NAS_STREAM_TITLE = "NAS"
NAS_IP_STREAM_TITLE = "NAS (IP-form)"
NAS_SOURCE_FORMS = ["nas", "nas.darknetian.com"]
NAS_IP_FORM = "10.10.0.50"


def find_stream(title: str) -> dict | None:
    for s in (gl.api("GET", "streams") or {}).get("streams", []):
        if s.get("title") == title:
            return s
    return None


def _create_stream(title: str, description: str, matching_type: str,
                   rules: list[dict]) -> None:
    existing = find_stream(title)
    if existing:
        print(f"  stream exists: {title!r} id={existing['id']} (rules not modified)")
        return
    body = {
        "title": title,
        "description": description,
        "index_set_id": DEFAULT_INDEX_SET_ID,
        "remove_matches_from_default_stream": True,
        "matching_type": matching_type,
        "rules": rules,
    }
    resp = gl.api("POST", "streams", body)
    sid = resp["stream_id"]
    print(f"  created stream: {title!r} id={sid}")
    gl.api("POST", f"streams/{sid}/resume")
    print(f"  stream resumed: {title!r}")


def main() -> None:
    print(f"== Setting up NAS streams ==")
    # Stream 1: rDNS-resolved sources
    _create_stream(
        NAS_STREAM_TITLE,
        "Synology DSM syslog from 10.10.0.50 (rDNS-resolved). Source matches "
        "nas OR nas.darknetian.com. IP-form fallback lives in the 'NAS (IP-form)' "
        "stream.",
        matching_type="OR",
        rules=[
            {"field": "source", "type": 1, "value": src,
             "inverted": False, "description": f"Synology hostname: {src}"}
            for src in NAS_SOURCE_FORMS
        ],
    )
    # Stream 2: IP-form fallback, with device_vendor-absent rule to exclude
    # the UDDI CEF "Infoblox Data Connector" traffic that also has source=10.10.0.50.
    _create_stream(
        NAS_IP_STREAM_TITLE,
        "Synology DSM syslog fallback for when rDNS fails (source=10.10.0.50). "
        "AND'd with field-absent device_vendor to exclude UDDI CEF traffic "
        "from the Infoblox Data Connector on the same source IP.",
        matching_type="AND",
        rules=[
            {"field": "source", "type": 1, "value": NAS_IP_FORM,
             "inverted": False, "description": "IP-form NAS source"},
            {"field": "device_vendor", "type": 5, "value": "",
             "inverted": True, "description": "exclude CEF (which sets device_vendor)"},
        ],
    )


if __name__ == "__main__":
    main()
