"""Splice the `ipam enrich destination_ip to destination_fqdn` rule into the
user-managed 'Enrichment' pipeline at stage 2.

Idempotent. Safe to re-run. Logic:
  - POST the rule from pipelines/destination_fqdn_enrich.json if it doesn't exist
  - GET the current Enrichment pipeline source
  - If the rule reference isn't in the source yet, splice it into stage 2
  - PUT the updated pipeline

We can't use pipelines/apply.py for this because that script creates or
replaces a whole pipeline. The Enrichment pipeline is user-managed (it
holds the existing IPAM rules) so we surgically add one rule.

Run after sourcing env.sh:
    python3 pipelines/extend_enrichment_destination.py
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))
import graylog as gl  # noqa: E402

# Pipeline ID for 'Enrichment' (user-owned). Stable across rebuilds since the
# user created this pipeline in the UI originally.
ENRICHMENT_PIPELINE_ID = "697f0960eeb15b769f4470a3"
RULE_NAME = "ipam enrich destination_ip to destination_fqdn"


def main() -> None:
    spec_path = Path(__file__).parent / "destination_fqdn_enrich.json"
    spec = json.loads(spec_path.read_text())
    rule_spec = spec["rules"][0]
    assert rule_spec["title"] == RULE_NAME

    # 1) Ensure rule exists
    existing_rules = {r["title"]: r for r in gl.api("GET", "system/pipelines/rule")}
    if RULE_NAME in existing_rules:
        rid = existing_rules[RULE_NAME]["id"]
        body = {**rule_spec, "id": rid}
        gl.api("PUT", f"system/pipelines/rule/{rid}", body)
        print(f"  rule exists: id={rid} (PUT, kept current)")
    else:
        resp = gl.api("POST", "system/pipelines/rule", rule_spec)
        print(f"  rule created: id={resp['id']}")

    # 2) Splice into Enrichment pipeline source
    cur = gl.api("GET", f"system/pipelines/pipeline/{ENRICHMENT_PIPELINE_ID}")
    src = cur["source"]
    if RULE_NAME in src:
        print("  Enrichment pipeline already references the rule")
        return

    # Match stage-2 block: "stage 2 match either\n" + rule lines (no indent on this grid)
    m = re.search(r'(stage\s+2\s+match\s+\w+\n(?:rule\s+\"[^\"]+\"\n)+)', src)
    if not m:
        print("ERROR: could not find stage 2 block in Enrichment pipeline source:",
              file=sys.stderr)
        print(src, file=sys.stderr)
        sys.exit(2)
    block = m.group(1)
    new_block = block.rstrip() + f'\nrule "{RULE_NAME}"\n'
    new_src = src.replace(block, new_block)

    body = {
        "title": cur["title"],
        "description": cur.get("description") or "",
        "source": new_src,
    }
    resp = gl.api("PUT", f"system/pipelines/pipeline/{ENRICHMENT_PIPELINE_ID}", body)
    if resp.get("errors"):
        print(f"  PUT returned errors: {resp['errors']}", file=sys.stderr)
        sys.exit(2)
    print(f"  Enrichment pipeline updated; stage 2 now references {RULE_NAME!r}")


if __name__ == "__main__":
    main()
