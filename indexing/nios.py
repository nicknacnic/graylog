"""Migrate the five NIOS streams to a shared 'Infoblox NIOS' index set.

The five NIOS-source streams (gm, ddi, ns1, tr, ni) all share the same
schema: pipeline rules add dns_event_type / qname / qtype / rcode /
client_ip plus IPAM enrichment (client_fqdn, sender_fqdn). Modest
field cardinality individually but worth isolating from the default
index now that other big sources are moving off.

Idempotent. Run after sourcing env.sh:
    python3 indexing/nios.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))
import graylog as gl  # noqa: E402

NIOS_STREAMS = [
    "697e66d3eeb15b769f4235eb",  # NIOS (gm.darknetian.com)  — grid manager
    "697bf15eeeb15b769f3c8567",  # NIOS (ddi.darknetian.com) — services node
    "69939874eeb15b769f4f8ebd",  # NIOS (ns1.darknetian.com) — services node
    "697e67bdeeb15b769f423c70",  # NIOS (tr.darknetian.com)  — trinzic reporting
    "697c03f7eeb15b769f3cd51b",  # NIOS (ni.darknetian.com)  — network insight
]


def main() -> None:
    print("== Migrating NIOS streams to shared index set ==")
    idx_id = gl.ensure_index_set(
        title="Infoblox NIOS",
        prefix="nios",
        description=(
            "Infoblox NIOS syslog from grid manager, services nodes "
            "(ddi, ns1), trinzic reporting, and network insight. Pipeline "
            "rules extract DNS query/response fields; IPAM enrichment "
            "adds client_fqdn / sender_fqdn."
        ),
        shards=1,
        retention_days=30,
        max_indices=4,
    )
    gl.repoint_streams_to_index_set(NIOS_STREAMS, idx_id)
    print("done. All five NIOS streams now write to nios_*.")


if __name__ == "__main__":
    main()
