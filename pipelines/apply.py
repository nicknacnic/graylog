"""Apply a pipeline JSON file (rules + pipeline source) to Graylog.

Idempotent: rules matched by title are updated (PUT); new ones are created
(POST). The pipeline itself is matched by title; if it doesn't already exist
it's created. Stream-to-pipeline connections are NOT managed here — those
were set up in the UI when the stream was first created.

Usage:
    source env.sh && python3 pipelines/apply.py pipelines/cradlepoint.json
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))
import graylog as gl  # noqa: E402


def apply(spec_path: str) -> None:
    spec = json.loads(Path(spec_path).read_text())
    rules = spec["rules"]
    pipeline_spec = spec["pipeline"]

    # Index existing rules by title
    existing_rules = {r["title"]: r for r in gl.api("GET", "system/pipelines/rule")}

    for r in rules:
        title = r["title"]
        if title in existing_rules:
            rid = existing_rules[title]["id"]
            body = {**r, "id": rid}
            gl.api("PUT", f"system/pipelines/rule/{rid}", body)
            print(f"  PUT  rule {title!r:40s} id={rid}")
        else:
            resp = gl.api("POST", "system/pipelines/rule", r)
            print(f"  POST rule {title!r:40s} id={resp['id']}")

    # Build the pipeline source from the stages list
    title = pipeline_spec["title"]
    rule_names = pipeline_spec["stages"][0]["rules"]
    rules_block = "\n".join(f'  rule "{n}"' for n in rule_names)
    source = (
        f'pipeline "{title}"\n'
        f'stage 0 match either\n'
        f'{rules_block}\n'
        f'end'
    )
    body = {
        "title": title,
        "description": pipeline_spec.get("description", ""),
        "source": source,
    }

    existing_pipelines = {p["title"]: p for p in gl.api("GET", "system/pipelines/pipeline")}
    if title in existing_pipelines:
        pid = existing_pipelines[title]["id"]
        gl.api("PUT", f"system/pipelines/pipeline/{pid}", body)
        print(f"  PUT  pipeline {title!r:35s} id={pid}")
    else:
        resp = gl.api("POST", "system/pipelines/pipeline", body)
        print(f"  POST pipeline {title!r:35s} id={resp['id']}")
        print("  NOTE: connect this pipeline to its stream in the UI "
              "(System -> Pipelines -> Manage rule connections)")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: apply.py <spec.json>", file=sys.stderr)
        sys.exit(2)
    apply(sys.argv[1])
