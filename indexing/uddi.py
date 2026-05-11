"""Migrate UDDI/CEF + the two UDDI-DNS-cut streams to a shared
'Infoblox UDDI' index set.

UDDI/CEF events carry many Infoblox* fields per message (InfobloxDNSQType,
InfobloxB1Region, InfobloxNsCount, etc) — high per-message field cardinality.
The 'Aruba' and 'PAN MGT' streams are intentional cuts of UDDI DNS by
originating-client IP, so they share the same field schema and belong on
the same index set.

If you later set up native syslog from the Aruba AP, that will be a NEW
stream and should get its own index set (different schema entirely).

Idempotent. Run after sourcing env.sh:
    python3 indexing/uddi.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))
import graylog as gl  # noqa: E402

UDDI_STREAM = "697c067eeeb15b769f3ce126"
ARUBA_STREAM = "69aee3c80cbe6230c004b6fd"     # UDDI-DNS cut for 10.10.0.172
PAN_MGT_STREAM = "69aee2600cbe6230c004ae77"   # UDDI-DNS cut for PAN mgt IPs


def main() -> None:
    print("== Migrating UDDI/CEF + DNS-cut streams to shared index set ==")
    idx_id = gl.ensure_index_set(
        title="Infoblox UDDI",
        prefix="uddi",
        description=(
            "Infoblox UDDI (B1DDI on-prem proxy) CEF events plus the "
            "stream cuts that filter UDDI by originating client IP "
            "(currently 'Aruba' and 'PAN MGT'). High per-message field "
            "cardinality from InfobloxDNS*, InfobloxB1*, and CEF base fields."
        ),
        shards=1,
        retention_days=30,
        max_indices=4,
    )
    gl.repoint_streams_to_index_set(
        [UDDI_STREAM, ARUBA_STREAM, PAN_MGT_STREAM], idx_id,
    )
    print("done. UDDI/Aruba/PAN-MGT messages now write to uddi_*.")


if __name__ == "__main__":
    main()
