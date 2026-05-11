"""Migrate the two PANOS streams to a dedicated 'Palo Alto Networks' index set.

The PAN-OS Graylog plugins pre-extract dozens of structured fields per
message (src/dst IP+port, app, threat, url category, etc). Combined with
~10K msgs/15min, PANOS is the next biggest field-mapping pressure source
on the default index after VMware was migrated out.

Idempotent. Run after sourcing env.sh:
    python3 indexing/panos.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))
import graylog as gl  # noqa: E402

PANOS_9_STREAM = "697e6ba3eeb15b769f425397"
PANOS_11_STREAM = "697e6ac9eeb15b769f424e8c"


def main() -> None:
    print("== Migrating PANOS streams to dedicated index set ==")
    idx_id = gl.ensure_index_set(
        title="Palo Alto Networks",
        prefix="panos",
        description=(
            "PAN-OS syslog from PA-3020 (9.1.13), HA pair of PA-220s (10.1.0), "
            "PA-440 (11.0.0), and PRA (11.1.0). Field-heavy: each PA-OS log "
            "type adds many extracted fields."
        ),
        shards=2,
        retention_days=14,
        max_indices=3,
    )
    gl.repoint_streams_to_index_set([PANOS_9_STREAM, PANOS_11_STREAM], idx_id)
    print("done. PANOS messages now write to panos_*.")


if __name__ == "__main__":
    main()
