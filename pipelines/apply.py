"""Apply a pipeline JSON file (rules + pipeline source) to Graylog.

Idempotent: rules matched by title are updated (PUT); new ones are created
(POST). The pipeline itself is matched by title; if it doesn't already exist
it's created. Supports multi-stage pipelines.

Optionally connects the pipeline to one or more streams (by title):

    python3 pipelines/apply.py pipelines/synology.json --connect=NAS
    python3 pipelines/apply.py pipelines/foo.json --connect=A --connect=B

The connection is additive — if other pipelines are already wired into the
stream they're preserved.

Usage:
    source env.sh && python3 pipelines/apply.py pipelines/cradlepoint.json
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))
import graylog as gl  # noqa: E402


def _build_source(pipeline_spec: dict) -> str:
    title = pipeline_spec["title"]
    parts = [f'pipeline "{title}"']
    for stage in pipeline_spec["stages"]:
        match = stage.get("match", "either").lower()
        parts.append(f'stage {stage["stage"]} match {match}')
        for r in stage["rules"]:
            parts.append(f'  rule "{r}"')
    parts.append("end")
    return "\n".join(parts)


def _stream_by_title(title: str) -> dict | None:
    for s in (gl.api("GET", "streams") or {}).get("streams", []):
        if s.get("title") == title:
            return s
    return None


def _connect_pipeline_to_stream(pipeline_id: str, stream_title: str) -> None:
    stream = _stream_by_title(stream_title)
    if not stream:
        print(f"  WARN: stream {stream_title!r} not found — skipping connect")
        return
    sid = stream["id"]
    # Fetch existing connections for this stream — 404 just means none yet.
    try:
        existing = gl.api("GET", f"system/pipelines/connections/to_stream/{sid}") or {}
    except RuntimeError as e:
        if "404" in str(e):
            existing = {}
        else:
            raise
    pipeline_ids = list(existing.get("pipeline_ids") or [])
    if pipeline_id in pipeline_ids:
        print(f"  pipeline already connected to stream {stream_title!r} (id={sid})")
        return
    pipeline_ids.append(pipeline_id)
    gl.api("POST", "system/pipelines/connections/to_stream",
           {"stream_id": sid, "pipeline_ids": pipeline_ids})
    print(f"  CONNECT pipeline {pipeline_id} → stream {stream_title!r} (id={sid})")


def apply(spec_path: str, connect_titles: list[str]) -> None:
    spec = json.loads(Path(spec_path).read_text())
    rules = spec["rules"]
    pipeline_spec = spec["pipeline"]

    existing_rules = {r["title"]: r for r in gl.api("GET", "system/pipelines/rule")}
    for r in rules:
        title = r["title"]
        if title in existing_rules:
            rid = existing_rules[title]["id"]
            gl.api("PUT", f"system/pipelines/rule/{rid}", {**r, "id": rid})
            print(f"  PUT  rule {title!r:40s} id={rid}")
        else:
            resp = gl.api("POST", "system/pipelines/rule", r)
            print(f"  POST rule {title!r:40s} id={resp['id']}")

    title = pipeline_spec["title"]
    body = {
        "title": title,
        "description": pipeline_spec.get("description", ""),
        "source": _build_source(pipeline_spec),
    }
    existing_pipelines = {p["title"]: p for p in gl.api("GET", "system/pipelines/pipeline")}
    if title in existing_pipelines:
        pid = existing_pipelines[title]["id"]
        gl.api("PUT", f"system/pipelines/pipeline/{pid}", body)
        print(f"  PUT  pipeline {title!r:35s} id={pid}")
    else:
        resp = gl.api("POST", "system/pipelines/pipeline", body)
        pid = resp["id"]
        print(f"  POST pipeline {title!r:35s} id={pid}")

    for st in connect_titles:
        _connect_pipeline_to_stream(pid, st)


if __name__ == "__main__":
    args = sys.argv[1:]
    connect_titles: list[str] = []
    spec_path: str | None = None
    for a in args:
        if a.startswith("--connect="):
            connect_titles.append(a.split("=", 1)[1])
        elif spec_path is None:
            spec_path = a
        else:
            print(f"unexpected arg: {a}", file=sys.stderr); sys.exit(2)
    if not spec_path:
        print("usage: apply.py <spec.json> [--connect=<stream_title> ...]", file=sys.stderr)
        sys.exit(2)
    apply(spec_path, connect_titles)
