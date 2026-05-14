"""Watch Graylog's indexer-failure count; rotate the offending index set
when it spikes, so the field-cap problem stops blocking ingestion until
a permanent OpenSearch-side fix lands.

Why this exists:
  Graylog 6 + datanode + OpenSearch caps each index at 1000 total fields
  by default. High-cardinality sources (UDDI CEF events, VMware host
  events, etc.) eventually saturate their index's mapping; from that
  point, every new message with a previously-unseen field gets rejected
  as an indexer failure. Rotating the index lets the next index start
  fresh with 0 mapped fields, and ingestion resumes immediately.

  Raising index.mapping.total_fields.limit on the underlying OpenSearch
  template would be the permanent fix, but it requires admin-cert
  access to OpenSearch that Graylog's datanode wraps in mTLS. For the
  homelab, periodic auto-rotation is a clean substitute.

Behavior:
  - Poll /system/indexer/failures, get total count and the index names
    of the most recent N failures.
  - Compare to last-seen count from state file.
  - If delta exceeds SPIKE_THRESHOLD within one poll cycle, find which
    index set owns each offending index and POST cycle on it.
  - Cooldown: don't rotate the same index set more than once per
    COOLDOWN_S seconds, regardless of spike.
  - All actions logged to stdout (captured by journald) with timestamps.

Env vars:
  GRAYLOG_URL      e.g. https://graylog.darknetian.com/api
  GRAYLOG_TOKEN    Graylog API token (token-auth: token used as username,
                   literal 'token' as password)
  STATE_PATH       default /var/lib/graylog-auto-rotate/state.json
  SPIKE_THRESHOLD  default 500 — new failures per cycle that triggers
  COOLDOWN_S       default 1800 — don't re-rotate same set within 30min
  FAILURES_PEEK    default 200 — how many recent failures to fetch to
                   identify which index set is to blame
"""

from __future__ import annotations

import json
import os
import ssl
import sys
import time
from base64 import b64encode
from collections import Counter
from pathlib import Path
from urllib import error, request


GRAYLOG_URL = os.environ["GRAYLOG_URL"].rstrip("/")
GRAYLOG_TOKEN = os.environ["GRAYLOG_TOKEN"]
STATE_PATH = Path(os.environ.get("STATE_PATH", "/var/lib/graylog-auto-rotate/state.json"))
SPIKE_THRESHOLD = int(os.environ.get("SPIKE_THRESHOLD", "500"))
COOLDOWN_S = int(os.environ.get("COOLDOWN_S", "1800"))
FAILURES_PEEK = int(os.environ.get("FAILURES_PEEK", "200"))


def _ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _auth_header() -> str:
    raw = f"{GRAYLOG_TOKEN}:token".encode()
    return "Basic " + b64encode(raw).decode()


def api(method: str, path: str, body: dict | None = None) -> dict | None:
    url = path if path.startswith("http") else GRAYLOG_URL + "/" + path.lstrip("/")
    data = json.dumps(body).encode() if body is not None else None
    req = request.Request(
        url, data=data, method=method,
        headers={
            "Authorization": _auth_header(),
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Requested-By": "graylog-auto-rotate",
        },
    )
    try:
        with request.urlopen(req, context=_ctx(), timeout=20) as r:
            body = r.read()
            if not body:
                return None
            return json.loads(body)
    except error.HTTPError as e:
        # 204 No Content is fine (e.g., POST .../cycle)
        if e.code in (204, 202):
            return None
        raise


def load_state() -> dict:
    try:
        return json.loads(STATE_PATH.read_text())
    except FileNotFoundError:
        return {}


def save_state(state: dict) -> None:
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    STATE_PATH.write_text(json.dumps(state))


def log(msg: str) -> None:
    print(f"{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} {msg}", flush=True)


def index_set_for_index(name: str, sets_cache: dict) -> dict | None:
    """Match an index name (e.g. 'uddi_3') to its index set by prefix.
    `sets_cache` is a dict of {prefix: set_dict} built once per run."""
    for prefix, s in sets_cache.items():
        if name.startswith(prefix):
            return s
    return None


def main() -> int:
    state = load_state()
    last_total = state.get("last_total", 0)
    last_rotated = state.get("last_rotated", {})  # {index_set_id: epoch}

    # 1. Get current failure total
    resp = api("GET", "system/indexer/failures?limit=1")
    total = resp.get("total") if resp else 0
    delta = total - last_total

    if delta < 0:
        # Counter decreased — failure log was truncated/reset. Re-baseline.
        log(f"failure-count decreased ({last_total} → {total}); rebaselining")
        state["last_total"] = total
        save_state(state)
        return 0

    log(f"failures: total={total} delta-since-last-run={delta} threshold={SPIKE_THRESHOLD}")

    if delta < SPIKE_THRESHOLD:
        state["last_total"] = total
        save_state(state)
        return 0

    # 2. Spike detected — figure out which index(es) are at fault
    peek = api("GET", f"system/indexer/failures?limit={FAILURES_PEEK}")
    failures = (peek or {}).get("failures") or []
    by_index = Counter(f.get("index") for f in failures)
    log(f"spike — recent failure indices: {dict(by_index)}")

    # 3. Map indices to index sets (one fetch, cache by prefix)
    sets_resp = api("GET", "system/indices/index_sets")
    sets_cache = {s["index_prefix"] + "_": s for s in (sets_resp or {}).get("index_sets", [])}

    now = time.time()
    rotated: list[str] = []
    for index_name, n in by_index.most_common():
        if not index_name:
            continue
        idx_set = index_set_for_index(index_name, sets_cache)
        if not idx_set:
            log(f"  skip {index_name}: no matching index set")
            continue
        sid = idx_set["id"]
        title = idx_set.get("title", "?")
        last_t = last_rotated.get(sid, 0)
        if now - last_t < COOLDOWN_S:
            log(f"  skip '{title}' ({index_name}): cooldown — last rotated "
                f"{int(now - last_t)}s ago, cooldown {COOLDOWN_S}s")
            continue
        log(f"  rotating '{title}' (id={sid}) — {n} recent failures on {index_name}")
        api("POST", f"system/deflector/{sid}/cycle")
        last_rotated[sid] = now
        rotated.append(title)

    state["last_total"] = total
    state["last_rotated"] = last_rotated
    save_state(state)

    if rotated:
        log(f"rotated: {', '.join(rotated)}")
    else:
        log("spike acknowledged but no index sets eligible (cooldown / no mapping)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
