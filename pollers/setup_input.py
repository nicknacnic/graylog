"""Create the GELF HTTP input on Graylog if it doesn't already exist.

The poller writes to http://127.0.0.1:12202/gelf — this input is what
receives those messages. Listening on 127.0.0.1 means only local clients
(the poller, running on the Graylog VM itself) can submit.

Idempotent. Re-running is a no-op once the input exists.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))
import graylog as gl  # noqa: E402

INPUT_TITLE = "iLO Redfish poller"
BIND = "127.0.0.1"
PORT = 12202


def main() -> None:
    inputs = gl.api("GET", "system/inputs") or {}
    for inp in inputs.get("inputs", []):
        if inp.get("title") == INPUT_TITLE:
            print(f"input already exists: id={inp['id']} bind={inp['attributes'].get('bind_address')}:{inp['attributes'].get('port')}")
            return

    body = {
        "title": INPUT_TITLE,
        "type": "org.graylog2.inputs.gelf.http.GELFHttpInput",
        "global": True,
        "configuration": {
            "bind_address": BIND,
            "port": PORT,
            "recv_buffer_size": 1048576,
            "max_chunk_size": 65536,
            "enable_cors": False,
            "tls_enable": False,
            "tls_cert_file": "",
            "tls_key_file": "",
            "tls_key_password": "",
            "tls_client_auth": "disabled",
            "tls_client_auth_cert_file": "",
            "decompress_size_limit": 8388608,
            "idle_writer_timeout": 60,
            "override_source": None,
            "tcp_keepalive": False,
            "number_worker_threads": 2,
        },
    }
    resp = gl.api("POST", "system/inputs", body)
    print(f"created input: id={resp.get('id')}  bind={BIND}:{PORT}")


if __name__ == "__main__":
    main()
