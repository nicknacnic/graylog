"""Wire CSP CubeJS messages through the user-managed `Enrichment` pipeline.

Two steps:
  1) Splice `ipam normalize client_ip from dfp_qip` into stage 1 of the
     existing Enrichment pipeline so the IPAM chain (PTR + DHCP) sees a
     `client_ip` derived from CSP's `dfp_qip` field.
  2) Connect the Infoblox CSP stream to the Enrichment pipeline (and to
     the MAC Enrichment pipeline for symmetry — harmless on CSP data).

Idempotent. Same shape as `extend_enrichment_destination.py`.

Run after sourcing env.sh:
    python3 pipelines/extend_enrichment_csp.py
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))
import graylog as gl  # noqa: E402

ENRICHMENT_PIPELINE_ID = "697f0960eeb15b769f4470a3"
RULE_NAME = "ipam normalize client_ip from dfp_qip"
CSP_STREAM_TITLE = "Infoblox CSP"


def _ensure_rule() -> None:
    spec_path = Path(__file__).parent / "csp_qip_normalize.json"
    spec = json.loads(spec_path.read_text())
    rule_spec = spec["rules"][0]
    assert rule_spec["title"] == RULE_NAME

    existing = {r["title"]: r for r in gl.api("GET", "system/pipelines/rule")}
    if RULE_NAME in existing:
        rid = existing[RULE_NAME]["id"]
        gl.api("PUT", f"system/pipelines/rule/{rid}", {**rule_spec, "id": rid})
        print(f"  rule exists: id={rid} (PUT, kept current)")
    else:
        resp = gl.api("POST", "system/pipelines/rule", rule_spec)
        print(f"  rule created: id={resp['id']}")


def _splice_into_enrichment() -> None:
    cur = gl.api("GET", f"system/pipelines/pipeline/{ENRICHMENT_PIPELINE_ID}")
    src = cur["source"]
    if RULE_NAME in src:
        print("  Enrichment pipeline already references the rule")
        return
    m = re.search(r'(stage\s+1\s+match\s+\w+\n(?:rule\s+\"[^\"]+\"\n)+)', src)
    if not m:
        print("ERROR: stage 1 block not found in Enrichment pipeline:",
              file=sys.stderr)
        print(src, file=sys.stderr)
        sys.exit(2)
    block = m.group(1)
    new_block = block.rstrip() + f'\nrule "{RULE_NAME}"\n'
    new_src = src.replace(block, new_block)
    resp = gl.api("PUT", f"system/pipelines/pipeline/{ENRICHMENT_PIPELINE_ID}", {
        "title": cur["title"],
        "description": cur.get("description") or "",
        "source": new_src,
    })
    if resp.get("errors"):
        print(f"  PUT errors: {resp['errors']}", file=sys.stderr)
        sys.exit(2)
    print(f"  Enrichment pipeline updated; stage 1 now references {RULE_NAME!r}")


def _connect_csp_stream() -> None:
    streams = (gl.api("GET", "streams") or {}).get("streams", [])
    stream = next((s for s in streams if s["title"] == CSP_STREAM_TITLE), None)
    if not stream:
        print(f"  WARN: stream {CSP_STREAM_TITLE!r} not found — skipping connect")
        return
    sid = stream["id"]
    try:
        cur = gl.api("GET", f"system/pipelines/connections/to_stream/{sid}") or {}
    except RuntimeError as e:
        if "404" in str(e):
            cur = {}
        else:
            raise
    have = set(cur.get("pipeline_ids") or [])
    want = set(have) | {ENRICHMENT_PIPELINE_ID}
    if want == have:
        print(f"  stream {CSP_STREAM_TITLE!r} already wired to Enrichment")
        return
    gl.api("POST", "system/pipelines/connections/to_stream", {
        "stream_id": sid,
        "pipeline_ids": sorted(want),
    })
    print(f"  stream {CSP_STREAM_TITLE!r} now connected to Enrichment pipeline")


def main() -> None:
    _ensure_rule()
    _splice_into_enrichment()
    _connect_csp_stream()


if __name__ == "__main__":
    main()
