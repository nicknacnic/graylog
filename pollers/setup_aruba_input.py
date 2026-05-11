"""Create the Raw/Plaintext UDP input for Aruba AP syslog (port 5514).

Aruba IAP includes a year in its syslog timestamp ('May 11 10:03:20 2026
…') which isn't RFC 3164 — Graylog's syslog parser silently drops these.
A Raw/Plaintext UDP input doesn't try to parse syslog format, so the AP
packets survive and pipeline rules can do the extraction.

Idempotent. Run after sourcing env.sh:
    python3 pollers/setup_aruba_input.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))
import graylog as gl  # noqa: E402

INPUT_TITLE = "Aruba AP Raw UDP"
BIND = "0.0.0.0"
PORT = 5514


def main() -> None:
    inputs = gl.api("GET", "system/inputs") or {}
    for inp in inputs.get("inputs", []):
        if inp.get("title") == INPUT_TITLE:
            print(f"input already exists: id={inp['id']} bind={inp['attributes'].get('bind_address')}:{inp['attributes'].get('port')}")
            return inp["id"]
    body = {
        "title": INPUT_TITLE,
        "type": "org.graylog2.inputs.raw.udp.RawUDPInput",
        "global": True,
        "configuration": {
            "bind_address": BIND,
            "port": PORT,
            "recv_buffer_size": 262144,
            "number_worker_threads": 2,
            "override_source": None,
            "charset_name": "UTF-8",
        },
    }
    resp = gl.api("POST", "system/inputs", body)
    print(f"created input: id={resp.get('id')}  bind={BIND}:{PORT}")
    return resp.get("id")


if __name__ == "__main__":
    main()
