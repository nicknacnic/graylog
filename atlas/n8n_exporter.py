#!/usr/bin/env python3
"""Prometheus exporter for n8n workflow execution health.

Polls the n8n API on an interval, tracks per-workflow execution counts
(success/error/waiting) and durations. Dedupes on execution id via a
small on-disk seen-set so Prometheus counters stay monotonic across
restarts.

Also harvests vLLM token usage per (workflow, node). Detail data is
fetched per NEW execution id only -- never via includeData on the bulk
list call -- so API cost scales with new executions, not poll frequency.
"""
import json
import os
import sys
import tempfile
import time
import urllib.request
from datetime import datetime
from pathlib import Path

from prometheus_client import Counter, Gauge, Histogram, start_http_server

try:
    import claude_metrics
except Exception as _exc:  # module optional; exporter must still serve n8n metrics
    claude_metrics = None
    print("warning: claude_metrics unavailable (%s); transcript metrics disabled" % _exc,
          file=sys.stderr)

N8N_KEY = os.environ["N8N_KEY"]
N8N_BASE = "http://localhost:5678/api/v1"
POLL_INTERVAL = 30
SEEN_FILE = Path(os.environ.get("N8N_EXPORTER_SEEN_FILE", "/var/lib/n8n_exporter/seen_ids.json"))
TOTALS_FILE = Path(os.environ.get("N8N_EXPORTER_TOTALS_FILE", "/var/lib/n8n_exporter/totals.json"))
LISTEN_PORT = int(os.environ.get("N8N_EXPORTER_PORT", "9103"))
# The poll only ever sees the newest 50 executions, so an id can only be
# re-counted if it falls out of the seen-set while still inside that window.
# 200k ids (~2MB) puts that boundary years away at lab volume.
SEEN_CAP = int(os.environ.get("N8N_EXPORTER_SEEN_CAP", "200000"))

executions_total = Counter(
    "n8n_executions_total", "Total n8n executions", ["workflow_id", "workflow_name", "status"]
)
execution_duration = Histogram(
    "n8n_execution_duration_seconds", "n8n execution duration", ["workflow_id", "workflow_name"],
    buckets=(0.5, 1, 2, 5, 10, 30, 60, 120, 300, 600, 1800)
)
last_execution_ts = Gauge(
    "n8n_last_execution_timestamp_seconds", "Unix ts of last seen execution", ["workflow_id", "workflow_name"]
)
last_execution_status = Gauge(
    "n8n_last_execution_status", "1 if last execution succeeded, 0 if error", ["workflow_id", "workflow_name"]
)
poll_errors = Counter("n8n_exporter_poll_errors_total", "Exporter poll failures")

vllm_prompt_tokens = Counter(
    "atlas_vllm_prompt_tokens_total", "vLLM prompt tokens consumed",
    ["workflow_id", "workflow_name", "node"]
)
vllm_completion_tokens = Counter(
    "atlas_vllm_completion_tokens_total", "vLLM completion tokens produced",
    ["workflow_id", "workflow_name", "node"]
)
vllm_calls = Counter(
    "atlas_vllm_calls_total", "vLLM chat/completions calls",
    ["workflow_id", "workflow_name", "node"]
)

# Productivity rate constants. Defined in exactly one place -- here, overridable
# via /etc/n8n-exporter.env -- so Grafana panels never hardcode a rate.
RATE_DEFAULTS = {
    "atlas_productivity_rate_usd_per_hour": ("ATLAS_RATE_USD_PER_HOUR", 132.2115,
                                             "Loaded labor rate in USD per hour"),
    "atlas_productivity_read_wpm": ("ATLAS_READ_WPM", 130.0, "Assumed human reading speed, words/min"),
    "atlas_productivity_write_wpm": ("ATLAS_WRITE_WPM", 100.0, "Assumed human writing speed, words/min"),
    "atlas_productivity_words_per_token": ("ATLAS_WORDS_PER_TOKEN", 0.75, "Assumed words per LLM token"),
    # Command/search output is skimmed for the failure line, not read word for
    # word. Bash alone is ~54% of all consumed characters, so valuing it at the
    # prose rate above materially overstates human-equivalent hours.
    "atlas_productivity_skim_wpm": ("ATLAS_SKIM_WPM", 600.0,
                                    "Assumed human skim speed for tool output, words/min"),
    "atlas_productivity_lines_per_hour": ("ATLAS_LINES_PER_HOUR", 50.0,
                                          "Assumed human authoring rate, lines of file content/hour"),
    # Transcript consumption is measured in characters; panels need words.
    # Kept here so no panel has to hardcode the divisor.
    "atlas_productivity_chars_per_word": ("ATLAS_CHARS_PER_WORD", 5.0,
                                          "Assumed characters per word for tool output"),
    # Lets the headline read in working days rather than raw hours.
    "atlas_productivity_hours_per_day": ("ATLAS_HOURS_PER_DAY", 8.0,
                                         "Hours in a working day, for the days-saved headline"),
}
rate_gauges = {}
for _metric, (_env, _default, _help) in RATE_DEFAULTS.items():
    rate_gauges[_metric] = Gauge(_metric, _help)


def set_rate_gauges() -> None:
    for metric, (env, default, _help) in RATE_DEFAULTS.items():
        try:
            value = float(os.environ.get(env, default))
        except ValueError:
            value = default
        rate_gauges[metric].set(value)


def api_get(path: str) -> dict:
    req = urllib.request.Request(f"{N8N_BASE}{path}", headers={"X-N8N-API-KEY": N8N_KEY})
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read())


def load_seen() -> set:
    if SEEN_FILE.exists():
        try:
            return set(json.loads(SEEN_FILE.read_text()))
        except Exception:
            return set()
    return set()


def _atomic_write(path: Path, text: str) -> None:
    """Write via temp file in the same dir + os.replace, so a crash mid-write
    leaves the previous file intact rather than a truncated one."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=path.name + ".", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def save_seen(seen: set) -> None:
    # Cap file growth — keep the most recent SEEN_CAP ids only.
    trimmed = set(sorted(seen, key=lambda x: int(x))[-SEEN_CAP:])
    _atomic_write(SEEN_FILE, json.dumps(list(trimmed)))


# Counters whose per-label values survive a restart via TOTALS_FILE.
# Keyed by the metric's exposed name.
PERSISTED_COUNTERS = {
    "n8n_executions_total": executions_total,
    "atlas_vllm_prompt_tokens_total": vllm_prompt_tokens,
    "atlas_vllm_completion_tokens_total": vllm_completion_tokens,
    "atlas_vllm_calls_total": vllm_calls,
}


def save_totals() -> None:
    """Snapshot every persisted counter's value per label tuple."""
    state = {}
    for name, counter in PERSISTED_COUNTERS.items():
        entries = []
        for metric in counter.collect():
            for sample in metric.samples:
                if sample.name != name:
                    continue  # skip the _created companion sample
                entries.append({"labels": dict(sample.labels), "value": sample.value})
        state[name] = entries
    try:
        _atomic_write(TOTALS_FILE, json.dumps(state))
    except Exception as exc:
        print(f"warning: could not write totals file {TOTALS_FILE}: {exc}", file=sys.stderr)


def restore_totals() -> None:
    """Replay saved counter values at startup, before the first scrape.

    Deliberately touches only the counters -- the seen-set is loaded and
    written independently, so restoring totals cannot mark or unmark an
    execution id.
    """
    if not TOTALS_FILE.exists():
        print(f"info: no totals file at {TOTALS_FILE}, starting counters at zero", file=sys.stderr)
        return
    try:
        state = json.loads(TOTALS_FILE.read_text())
        if not isinstance(state, dict):
            raise ValueError("totals file is not a JSON object")
    except Exception as exc:
        print(f"warning: unreadable totals file {TOTALS_FILE} ({exc}); starting counters "
              f"at zero", file=sys.stderr)
        return

    for name, counter in PERSISTED_COUNTERS.items():
        for entry in state.get(name) or []:
            try:
                labels = entry["labels"]
                value = float(entry["value"])
                if value < 0:
                    continue
                counter.labels(**labels).inc(value)
            except Exception as exc:
                print(f"warning: skipping bad {name} entry {entry!r}: {exc}", file=sys.stderr)


def workflow_names() -> dict:
    try:
        data = api_get("/workflows?limit=100")
        return {w["id"]: w["name"] for w in data.get("data", [])}
    except Exception:
        return {}


def _iter_output_items(run: dict):
    """Yield each item's json dict from a single node run's main outputs."""
    for branch in (run.get("data", {}) or {}).get("main", []) or []:
        for item in branch or []:
            if isinstance(item, dict) and isinstance(item.get("json"), dict):
                yield item["json"]


def harvest_tokens(ex_id: str, wf_id: str, wf_name: str) -> None:
    """Fetch one execution's data and count any vLLM `usage` objects in it.

    Detected by the presence of a `usage` object in a node's output JSON --
    the node list is deliberately not hardcoded, it drifts.
    """
    try:
        ex = api_get(f"/executions/{ex_id}?includeData=true")
    except Exception:
        poll_errors.inc()
        return

    data = ex.get("data")
    if not isinstance(data, dict):
        return
    run_data = (data.get("resultData") or {}).get("runData") or {}
    if not isinstance(run_data, dict):
        return

    for node_name, runs in run_data.items():
        for run in runs or []:
            if not isinstance(run, dict):
                continue
            for j in _iter_output_items(run):
                usage = j.get("usage")
                if not isinstance(usage, dict):
                    continue
                labels = dict(workflow_id=wf_id, workflow_name=wf_name, node=node_name)
                vllm_calls.labels(**labels).inc()
                prompt = usage.get("prompt_tokens")
                completion = usage.get("completion_tokens")
                if isinstance(prompt, (int, float)):
                    vllm_prompt_tokens.labels(**labels).inc(prompt)
                if isinstance(completion, (int, float)):
                    vllm_completion_tokens.labels(**labels).inc(completion)


def poll_once(seen: set, names: dict) -> set:
    try:
        data = api_get("/executions?limit=50&includeData=false")
    except Exception:
        poll_errors.inc()
        return seen

    new_seen = set(seen)
    for ex in data.get("data", []):
        ex_id = ex["id"]
        wf_id = ex.get("workflowId", "unknown")
        wf_name = names.get(wf_id, wf_id)
        status = ex.get("status", "unknown")

        started = ex.get("startedAt")
        stopped = ex.get("stoppedAt")
        if started and stopped:
            try:
                t0 = datetime.fromisoformat(started.replace("Z", "+00:00"))
                t1 = datetime.fromisoformat(stopped.replace("Z", "+00:00"))
                duration = (t1 - t0).total_seconds()
                last_ts = t1.timestamp()
            except Exception:
                duration = None
                last_ts = time.time()
        else:
            duration = None
            last_ts = time.time()

        if ex_id not in seen:
            executions_total.labels(workflow_id=wf_id, workflow_name=wf_name, status=status).inc()
            if duration is not None:
                execution_duration.labels(workflow_id=wf_id, workflow_name=wf_name).observe(duration)
            # Same dedupe gate as the execution counters -- one seen-set, so token
            # counters stay monotonic across restarts too.
            harvest_tokens(ex_id, wf_id, wf_name)
            new_seen.add(ex_id)

        # Always refresh "last execution" gauges to latest seen, regardless of dedupe.
        _update_last(wf_id, wf_name, last_ts, status)

    return new_seen


_last_seen_per_wf = {}

def _update_last(wf_id, wf_name, ts, status):
    key = (wf_id, wf_name)
    prev = _last_seen_per_wf.get(key, 0)
    if ts >= prev:
        _last_seen_per_wf[key] = ts
        last_execution_ts.labels(workflow_id=wf_id, workflow_name=wf_name).set(ts)
        last_execution_status.labels(workflow_id=wf_id, workflow_name=wf_name).set(1 if status == "success" else 0)


def poll_loop():
    seen = load_seen()
    names = workflow_names()
    names_refreshed = time.time()
    while True:
        if time.time() - names_refreshed > 300:
            names = workflow_names()
            names_refreshed = time.time()
        seen = poll_once(seen, names)
        save_seen(seen)
        save_totals()
        if claude_metrics is not None:
            try:
                claude_metrics.scan()   # self-throttles; no-op between intervals
            except Exception as exc:
                print("warning: claude transcript scan failed: %r" % exc, file=sys.stderr)
        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    set_rate_gauges()
    restore_totals()
    start_http_server(LISTEN_PORT)
    poll_loop()
