"""Set up indexing for native Aruba AP225 syslog.

The AP225 in IAP mode only ships to UDP :514, so its syslog lands on the
existing 'ESXI 7 (Syslog UDP)' input alongside ESXi messages. After
Graylog's syslog parser + rDNS, the AP's `source` field becomes
'aruba.darknetian.com' (PTR on 10.10.0.172 in NIOS), and that's what
the stream rule matches on.

Creates:
  - 'Aruba' index set (prefix aruba) for the native AP syslog
  - new 'Aruba AP' stream -> source=aruba.darknetian.com

NB: an earlier version of this script also renamed the pre-existing
'Aruba' stream (which was a UDDI-DNS-by-source-IP cut) to
'Aruba (UDDI DNS view)' and added an _exists_:deviceAddress rule to
keep it from catching the new native syslog. That stream has since
been merged back into the regular UDDI stream — its source-IP
(10.10.0.172) was added to UDDI's OR rule list, and the standalone
stream was deleted. Re-running this script does not recreate it.

Idempotent. Run after sourcing env.sh:
    python3 indexing/aruba.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))
import graylog as gl  # noqa: E402

AP_FQDN = "aruba.darknetian.com"
NEW_STREAM_TITLE = "Aruba AP"


def ensure_new_stream(index_set_id: str) -> str:
    existing = next(
        (s for s in (gl.api("GET", "streams") or {}).get("streams", [])
         if s.get("title") == NEW_STREAM_TITLE),
        None,
    )
    if existing:
        print(f"  stream exists: id={existing['id']}")
        return existing["id"]
    body = {
        "title": NEW_STREAM_TITLE,
        "description": (
            "Native syslog from the Aruba AP225 (IAP mode). The AP sends to "
            "the shared UDP :514 syslog input; Graylog rDNS rewrites the "
            "source to the PTR (aruba.darknetian.com), and this stream "
            "filters on that."
        ),
        "index_set_id": index_set_id,
        "remove_matches_from_default_stream": True,
        "matching_type": "AND",
        "rules": [
            {"field": "source", "type": 1, "value": AP_FQDN, "inverted": False,
             "description": "post-rDNS AP hostname"},
        ],
    }
    resp = gl.api("POST", "streams", body)
    sid = resp["stream_id"]
    print(f"  created stream: id={sid}")
    gl.api("POST", f"streams/{sid}/resume")
    print("  stream resumed")
    return sid


def main() -> None:
    print("== Setting up Aruba AP indexing ==")
    idx_id = gl.ensure_index_set(
        title="Aruba",
        prefix="aruba",
        description=(
            "Native Aruba IAP syslog from the AP225. Captures wifi auth, "
            "AP up/down, radio/station events."
        ),
        shards=1,
        retention_days=30,
        max_indices=4,
    )
    ensure_new_stream(idx_id)
    print("done.")


if __name__ == "__main__":
    main()
