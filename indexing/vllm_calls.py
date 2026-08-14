"""Set up the vLLM Calls indexing path on Graylog.

vLLM's own access log is payload-blind (vllm-coder runs with
--no-enable-log-requests), so per-call visibility comes from the callers
instead: benchmarks/scripts/{expand_preflight,triage_preflight}.py on atlas
each emit one GELF UDP message per vLLM call (via gelf_log.py) to the
existing "atlas GELF UDP" input on :12201. This gives us caller, card_id,
model, prompt/completion token counts, latency, and status per call.

Idempotent. Creates (or updates):
  1. Index set 'vLLM Calls' (prefix vllm-calls, 1/0 shards, 30d retention).
  2. Stream 'vLLM Calls' that matches vllm_caller field present.
     Writes to the new index set; removes matches from the default stream.

Run after sourcing env.sh:
    python3 indexing/vllm_calls.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))
import graylog as gl  # noqa: E402

INDEX_SET_TITLE = "vLLM Calls"
INDEX_PREFIX = "vllm-calls"
STREAM_TITLE = "vLLM Calls"


def find_stream(title: str) -> dict | None:
    streams = gl.api("GET", "streams") or {}
    for s in streams.get("streams", []):
        if s.get("title") == title:
            return s
    return None


def create_stream(index_set_id: str) -> str:
    existing = find_stream(STREAM_TITLE)
    if existing:
        print(f"  stream exists: id={existing['id']}")
        return existing["id"]
    body = {
        "title": STREAM_TITLE,
        "description": "Per-call vLLM invocation events from atlas preflight "
                       "scripts (expand_preflight.py, triage_preflight.py) — "
                       "caller, card_id, model, tokens, latency, status.",
        "index_set_id": index_set_id,
        "remove_matches_from_default_stream": True,
        "rules": [
            {"field": "vllm_caller", "type": 5, "value": "", "inverted": False,
             "description": "vllm_caller field present"},
        ],
        "matching_type": "AND",
    }
    resp = gl.api("POST", "streams", body)
    sid = resp["stream_id"]
    print(f"  created stream: id={sid}")
    gl.api("POST", f"streams/{sid}/resume")
    print("  stream resumed (started)")
    return sid


def main() -> None:
    print("== Setting up vLLM Calls indexing ==")
    print("1. index set")
    idx_id = gl.ensure_index_set(
        title=INDEX_SET_TITLE,
        prefix=INDEX_PREFIX,
        description="Dedicated index for per-call vLLM invocation events "
                     "(atlas preflight scripts). Kept separate so vllm_* "
                     "fields don't strain the default index.",
        retention_days=30,
    )
    print("2. stream")
    create_stream(idx_id)
    print("done.")


if __name__ == "__main__":
    main()
