"""Home Assistant core-log → Graylog (GELF HTTP) poller.

Pulls the HA core log via the Supervisor proxy
(`GET /api/hassio/core/logs`) every 5 minutes, parses line-by-line,
dedupes against the last-emitted timestamp, and ships warnings and
errors as GELF events to the existing Graylog HTTP input.

Why this endpoint:
  - `/api/error_log` was removed in newer HA versions (returns 404).
  - `/api/states/system_log.last_message` doesn't exist on this install.
  - `/api/hassio/core/logs` is the Supervisor proxy and works with the
    same long-lived token the dashboard uses.
  - SSH-tailing `/config/home-assistant.log` would also work but adds
    another credential surface.

Default emit level is WARNING+ — INFO is mostly automation/HTTP noise
that the HA recorder already keeps. Tune via HA_LOG_LEVELS.

Multi-line tracebacks: HA writes the stack frames as continuation
lines without a timestamp prefix. They get coalesced into the previous
entry's `_ha_traceback` field rather than emitted as standalone events.

Env vars:
    HA_URL              http://10.10.0.220:8123
    HA_TOKEN            long-lived access token
    HA_LOG_LEVELS       comma list; default: WARNING,ERROR,CRITICAL
    HA_HOST_LABEL       GELF `host` (default: ha-darknetian)
    GELF_URL            http://127.0.0.1:12202/gelf
    HA_STATE_PATH       /var/lib/ha-log-poller/state.json
    HA_INSECURE         0/1

GELF fields:
    host           ha-darknetian          (so a Graylog stream rule on
                                            source=ha-darknetian routes
                                            cleanly)
    _ha_level      WARNING | ERROR | CRITICAL
    _ha_logger     dotted module name, e.g. homeassistant.loader
    _ha_thread     MainThread | SyncWorker_2 | etc.
    _ha_traceback  full traceback if continuation lines were present
"""

from __future__ import annotations

import json
import os
import re
import ssl
import sys
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib import error, parse, request
from zoneinfo import ZoneInfo


def _env(name: str, default: str | None = None) -> str:
    v = os.environ.get(name, default)
    if v is None:
        print(f"ERROR: {name} not set", file=sys.stderr)
        sys.exit(2)
    return v


HA_URL = _env("HA_URL").rstrip("/")
HA_TOKEN = _env("HA_TOKEN")
HA_LEVELS = set(
    lvl.strip().upper()
    for lvl in os.environ.get("HA_LOG_LEVELS", "WARNING,ERROR,CRITICAL").split(",")
    if lvl.strip()
)
HA_HOST_LABEL = os.environ.get("HA_HOST_LABEL", "ha-darknetian").strip()
GELF_URL = os.environ.get("GELF_URL", "http://127.0.0.1:12202/gelf")
STATE_PATH = Path(os.environ.get("HA_STATE_PATH", "/var/lib/ha-log-poller/state.json"))
HA_INSECURE = os.environ.get("HA_INSECURE", "0") == "1"


# Strip ANSI escape sequences HA writes for terminal coloring.
_ANSI = re.compile(r"\x1b\[[0-9;]*m")

# `2026-05-17 15:58:05.323 WARNING (SyncWorker_2) [logger.name] message`
_LINE = re.compile(
    r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+) "
    r"(DEBUG|INFO|WARNING|ERROR|CRITICAL|FATAL) "
    r"\((\S+?)\) \[([^\]]+)\] (.*)$"
)


def _ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    if HA_INSECURE:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _ha_get(path: str, accept: str = "text/plain") -> str:
    req = request.Request(f"{HA_URL}{path}", headers={
        "Authorization": f"Bearer {HA_TOKEN}",
        "Accept": accept,
        "User-Agent": "homelab-graylog-ha-log-poller/0.1",
    })
    with request.urlopen(req, context=_ctx(), timeout=30) as r:
        return r.read().decode("utf-8", "replace")


def fetch_logs() -> str:
    return _ha_get("/api/hassio/core/logs", "text/plain")


def fetch_tz() -> ZoneInfo:
    # HA writes naive timestamps in the configured `time_zone`. Without
    # this lookup the timestamps drift by the UTC offset (we saw 6h on
    # the first deploy — every event landed in Graylog 6h in the past).
    try:
        cfg = json.loads(_ha_get("/api/config", "application/json"))
        return ZoneInfo(cfg.get("time_zone") or "UTC")
    except Exception as exc:
        print(f"WARN: tz lookup failed ({exc}), assuming UTC", file=sys.stderr)
        return ZoneInfo("UTC")


def gelf(short_message: str, *, level_gelf: int, ts_epoch: float | None = None,
         **fields: Any) -> None:
    msg = {
        "version": "1.1",
        "host": HA_HOST_LABEL,
        "short_message": short_message[:1024],
        "level": level_gelf,
        "timestamp": ts_epoch if ts_epoch is not None else time.time(),
    }
    for k, v in fields.items():
        if v is None or v == "":
            continue
        if isinstance(v, bool):
            v = "true" if v else "false"
        key = k if k.startswith("_") else f"_{k}"
        msg[key] = v
    data = json.dumps(msg).encode()
    req = request.Request(GELF_URL, data=data,
                          headers={"Content-Type": "application/json"})
    try:
        with request.urlopen(req, timeout=5) as r:
            r.read()
    except error.URLError as e:
        print(f"GELF POST failed: {e}", file=sys.stderr)


def load_state() -> dict:
    try:
        return json.loads(STATE_PATH.read_text())
    except FileNotFoundError:
        return {}


def save_state(state: dict) -> None:
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    STATE_PATH.write_text(json.dumps(state))


def _gelf_level(ha_level: str) -> int:
    return {
        "CRITICAL": 2, "FATAL": 2,
        "ERROR": 3,
        "WARNING": 4,
        "INFO": 6,
        "DEBUG": 7,
    }.get(ha_level.upper(), 6)


def _parse_ts(s: str, tz: ZoneInfo) -> float:
    return datetime.strptime(s, "%Y-%m-%d %H:%M:%S.%f").replace(
        tzinfo=tz).timestamp()


def main() -> None:
    state = load_state()
    last_ts: float = float(state.get("last_ts") or 0)
    last_emitted = float(last_ts)
    print(f"== ha-log poller (last_ts={last_ts}) levels={sorted(HA_LEVELS)} ==")

    try:
        tz = fetch_tz()
        body = fetch_logs()
    except (error.URLError, error.HTTPError) as e:
        print(f"fetch failed: {e}", file=sys.stderr)
        sys.exit(1)
    print(f"  ha tz: {tz.key}")
    body = _ANSI.sub("", body)

    # Walk lines; coalesce continuation lines into the previous entry.
    parsed: list[dict] = []
    pending: dict | None = None
    for line in body.splitlines():
        if not line:
            continue
        m = _LINE.match(line)
        if m:
            if pending:
                parsed.append(pending)
            ts_str, lvl, thread, logger, msg = m.groups()
            try:
                ts = _parse_ts(ts_str, tz)
            except ValueError:
                continue
            pending = {
                "ts": ts, "level": lvl, "thread": thread,
                "logger": logger, "message": msg,
                "traceback": [],
            }
        else:
            if pending is not None:
                pending["traceback"].append(line)
    if pending:
        parsed.append(pending)

    emitted = 0
    skipped_dedup = 0
    skipped_level = 0
    for e in parsed:
        if e["ts"] <= last_ts:
            skipped_dedup += 1
            continue
        if e["level"] not in HA_LEVELS:
            skipped_level += 1
            continue
        traceback_text = "\n".join(e["traceback"]) if e["traceback"] else None
        gelf(
            f"{e['logger']}: {e['message']}",
            level_gelf=_gelf_level(e["level"]),
            ts_epoch=e["ts"],
            ha_level=e["level"],
            ha_logger=e["logger"],
            ha_thread=e["thread"],
            ha_traceback=traceback_text,
        )
        emitted += 1
        if e["ts"] > last_emitted:
            last_emitted = e["ts"]

    print(f"  parsed={len(parsed)}  emitted={emitted}  "
          f"skipped_dedup={skipped_dedup}  skipped_level={skipped_level}")

    state["last_ts"] = last_emitted
    state["last_run"] = datetime.now(timezone.utc).isoformat()
    save_state(state)
    print("done.")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("[ha_log_poller] crashed:", file=sys.stderr)
        traceback.print_exc()
        sys.exit(1)
