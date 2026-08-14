"""Productivity metrics from Claude Code transcripts synced to the NAS.

The laptop scrubs and pushes ~/.claude/projects/**/*.jsonl to
/mnt/nas/lab/claude-transcripts (see claude-transcript-sync.py on the laptop);
this module turns them into Prometheus metrics. Nothing here talks to the
laptop -- it only reads the CIFS mount.

Two dedupe keys, deliberately different -- getting them backwards skews numbers
by 2-3x in opposite directions:
  * requestId   -- for TOKENS. Resumed sessions and subagent files replay the
                   same assistant message; it was billed once.
  * tool_use_id -- for WORK. A replayed message describes the same Edit that
                   happened once. (Observed: 43% of assistant messages are
                   replays, but 0% of tool_use ids are.)

Values are absolute lifetime totals recomputed from a full rescan, so they are
Gauges, not Counters -- a rescan is idempotent and self-healing rather than
incremental. Use delta() rather than increase() on these in PromQL.
"""
import json
import os
import time
from pathlib import Path

from prometheus_client import Gauge

CLAUDE_DIR = Path(os.environ.get("N8N_EXPORTER_CLAUDE_DIR", "/mnt/nas/lab/claude-transcripts"))
RESCAN_INTERVAL = int(os.environ.get("N8N_EXPORTER_CLAUDE_RESCAN", "300"))

# Tools whose output a human would skim rather than read word-for-word.
# Bash alone is ~54% of all consumed characters; valuing 88k lines of command
# output at a prose reading rate is the same error class as guessing
# words-per-token, just larger.
SKIM_TOOLS = {"Bash", "Grep", "Glob", "TaskOutput"}

lines_produced = Gauge("claude_lines_produced", "Lines of file content produced", ["kind"])
lines_consumed = Gauge("claude_lines_consumed", "Lines of tool output consumed", ["tool", "mode"])
chars_consumed = Gauge("claude_chars_consumed", "Characters of tool output consumed", ["tool", "mode"])
tool_calls = Gauge("claude_tool_calls", "Tool invocations", ["tool"])
files_touched = Gauge("claude_files_touched", "Distinct files written or edited")
sessions_total = Gauge("claude_sessions", "Distinct sessions observed")
tokens = Gauge("claude_tokens", "Token usage", ["model", "kind"])
# Per-session detail, capped to the most recent SESSION_LIMIT sessions. Session
# ids are unbounded over time, so emitting one series per session forever would
# grow cardinality without limit; recent sessions are what anyone actually looks at.
SESSION_LIMIT = int(os.environ.get("N8N_EXPORTER_CLAUDE_SESSIONS", "20"))
session_tokens = Gauge("claude_session_tokens", "Token usage per recent session",
                       ["session", "project", "kind"])
session_lines = Gauge("claude_session_lines_produced", "Lines produced per recent session",
                      ["session", "project"])
last_scan = Gauge("claude_last_scan_timestamp_seconds", "Unix ts of last transcript scan")
scan_duration = Gauge("claude_scan_duration_seconds", "Duration of last transcript scan")
files_scanned = Gauge("claude_transcript_files", "Transcript files present on the NAS")

_state = {"next_scan": 0.0}


def _walk():
    if not CLAUDE_DIR.is_dir():
        return []
    return sorted(CLAUDE_DIR.rglob("*.jsonl"))


def scan():
    """Full rescan. Returns True if metrics were refreshed."""
    now = time.time()
    if now < _state["next_scan"]:
        return False
    _state["next_scan"] = now + RESCAN_INTERVAL
    t0 = time.time()

    paths = _walk()
    if not paths:
        last_scan.set(now)
        files_scanned.set(0)
        return False

    seen_req = set()
    seen_tool = set()
    tool_name_of = {}
    produced = {"written": 0, "added": 0, "replaced": 0}
    files = set()
    sessions = set()
    calls = {}
    consumed = {}
    tok = {}
    sess = {}          # sessionId -> per-session tallies

    records = []
    for p in paths:
        try:
            with p.open(errors="replace") as fh:
                for line in fh:
                    try:
                        records.append(json.loads(line))
                    except Exception:
                        continue
        except OSError:
            continue

    # Pass 1: map every tool_use id to its tool name, and count work + tokens.
    for d in records:
        if d.get("type") != "assistant":
            continue
        msg = d.get("message") or {}
        for b in msg.get("content") or []:
            if not isinstance(b, dict) or b.get("type") != "tool_use":
                continue
            tid = b.get("id")
            tool_name_of[tid] = b.get("name")
            if tid in seen_tool:
                continue
            seen_tool.add(tid)
            name = b.get("name") or "(unknown)"
            calls[name] = calls.get(name, 0) + 1
            inp = b.get("input") or {}
            path = inp.get("file_path")
            if name in ("Edit", "Write") and path:
                files.add(path)
            sid = d.get("sessionId")
            n_lines = 0
            if name == "Edit":
                n_lines = len((inp.get("new_string") or "").splitlines())
                produced["added"] += n_lines
                produced["replaced"] += len((inp.get("old_string") or "").splitlines())
            elif name == "Write":
                n_lines = len((inp.get("content") or "").splitlines())
                produced["written"] += n_lines
            if sid and n_lines:
                _s = sess.setdefault(sid, {"lines": 0, "tok": {}, "ts": "", "project": ""})
                _s["lines"] += n_lines

        # Tokens use requestId, not tool_use_id.
        rq = d.get("requestId") or msg.get("id")
        if rq is None or rq in seen_req:
            continue
        seen_req.add(rq)
        sid = d.get("sessionId")
        if sid:
            sessions.add(sid)
            _s = sess.setdefault(sid, {"lines": 0, "tok": {}, "ts": "", "project": ""})
            ts = d.get("timestamp") or ""
            if ts > _s["ts"]:
                _s["ts"] = ts
            cwd = d.get("cwd") or ""
            if cwd and not _s["project"]:
                _s["project"] = os.path.basename(cwd) or cwd
        u = msg.get("usage") or {}
        model = msg.get("model") or "(unknown)"
        cc = u.get("cache_creation") or {}
        for kind, val in (
            ("input", u.get("input_tokens", 0)),
            ("output", u.get("output_tokens", 0)),
            ("cache_read", u.get("cache_read_input_tokens", 0)),
            ("cache_write_1h", cc.get("ephemeral_1h_input_tokens", 0)),
            ("cache_write_5m", cc.get("ephemeral_5m_input_tokens", 0)),
        ):
            tok[(model, kind)] = tok.get((model, kind), 0) + (val or 0)
            if sid:
                _t = sess[sid]["tok"]
                _t[kind] = _t.get(kind, 0) + (val or 0)

    # Pass 2: consumption, deduped by tool_use_id (a replayed result is one read).
    done = set()
    for d in records:
        if d.get("type") != "user":
            continue
        c = (d.get("message") or {}).get("content")
        if not isinstance(c, list):
            continue
        for b in c:
            if not isinstance(b, dict) or b.get("type") != "tool_result":
                continue
            tid = b.get("tool_use_id")
            if tid in done:
                continue
            done.add(tid)
            name = tool_name_of.get(tid, "(unknown)")
            cont = b.get("content")
            txt = cont if isinstance(cont, str) else json.dumps(cont, default=str)
            mode = "skim" if name in SKIM_TOOLS else "read"
            key = (name, mode)
            cur = consumed.setdefault(key, [0, 0])
            cur[0] += len(txt.splitlines())
            cur[1] += len(txt)

    for k, v in produced.items():
        lines_produced.labels(kind=k).set(v)
    files_touched.set(len(files))
    sessions_total.set(len(sessions))
    for name, n in calls.items():
        tool_calls.labels(tool=name).set(n)
    for (name, mode), (ln, ch) in consumed.items():
        lines_consumed.labels(tool=name, mode=mode).set(ln)
        chars_consumed.labels(tool=name, mode=mode).set(ch)
    for (model, kind), v in tok.items():
        tokens.labels(model=model, kind=kind).set(v)
    # Most recent sessions only -- clear first so a session ageing out of the
    # window stops reporting a stale value.
    session_tokens.clear()
    session_lines.clear()
    recent = sorted(sess.items(), key=lambda kv: kv[1]["ts"], reverse=True)[:SESSION_LIMIT]
    for sid, v in recent:
        short = sid[:8]
        proj = v["project"] or "(unknown)"
        session_lines.labels(session=short, project=proj).set(v["lines"])
        for kind, val in v["tok"].items():
            session_tokens.labels(session=short, project=proj, kind=kind).set(val)

    files_scanned.set(len(paths))
    last_scan.set(now)
    scan_duration.set(time.time() - t0)
    return True
