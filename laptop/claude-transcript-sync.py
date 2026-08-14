#!/usr/bin/env python3
"""Scrub Claude Code transcripts and push them to the NAS.

Moves bytes only -- no metric logic lives here. Everything derived from these
files (productivity counters, agent memory) is computed on atlas, which reads
the same directory over its CIFS mount at /mnt/nas/lab/claude-transcripts.

Laptop  ~/.claude/projects/**/*.jsonl
   |  scrub known secret values + secret-shaped patterns
   v
NAS     /volume1/lab/_atlas/claude-transcripts/
   =    /mnt/nas/lab/claude-transcripts/   (as atlas sees it)

Fails closed: if any known secret value survives scrubbing, the file is not
staged and the run exits non-zero rather than shipping a credential.
"""
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

SRC = Path.home() / ".claude" / "projects"
STAGE = Path.home() / ".cache" / "claude-transcript-sync" / "staged"
STATE = Path.home() / ".cache" / "claude-transcript-sync" / "state.json"
# Values are read from this file at run time and never written into this script.
SECRETS_FILE = SRC / "-Users-nwilliams" / "memory" / "atlas_credentials.md"
NAS = "atlas@10.10.0.50"
NAS_PATH = "/volume1/lab/_atlas/claude-transcripts/"

# Secret-shaped tokens, redacted by pattern regardless of whether we know the value.
PATTERNS = [
    ("anthropic-key", re.compile(r"sk-ant-[A-Za-z0-9_\-]{20,}")),
    ("openai-key", re.compile(r"sk-[A-Za-z0-9]{32,}")),
    ("github-pat", re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}")),
    ("github-fine-grained", re.compile(r"github_pat_[A-Za-z0-9_]{40,}")),
    ("aws-key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("slack-token", re.compile(r"xox[baprs]-[A-Za-z0-9\-]{10,}")),
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}")),
    ("private-key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("bearer", re.compile(r"(?i)\b(?:authorization|bearer)\s*[:=]\s*[A-Za-z0-9._\-]{20,}")),
]


def known_secrets():
    """Literal secret values to scrub. Read at call time from the memory file."""
    vals = set()
    if not SECRETS_FILE.exists():
        print("warning: %s missing; pattern-only scrubbing" % SECRETS_FILE, file=sys.stderr)
        return vals
    text = SECRETS_FILE.read_text(errors="replace")
    for m in re.finditer(r"`([^`\n]+)`", text):
        v = m.group(1).strip()
        if looks_like_secret(v):
            vals.add(v)
    return vals


def looks_like_secret(v):
    """Credential values only.

    The memory file backticks both credential *names* and *values*, plus hosts,
    ports, and model names. Redacting those would gut the archive -- 127.0.0.1
    alone appears in 76 transcripts -- so require the shape of an actual secret:
    no whitespace, and either a long opaque token or mixed character classes.
    """
    if len(v) < 10 or any(c.isspace() for c in v):
        return False
    if v.startswith(("/", "~", "http://", "https://")):
        return False
    if re.fullmatch(r"[\w.\-]+@[\w.\-]+", v):          # user@host
        return False
    if re.fullmatch(r"[\d.]+(:\d+)?", v):              # IP / IP:port
        return False
    if len(v) >= 32 and re.fullmatch(r"[A-Za-z0-9+/=_\-.]+", v):
        return True                                     # long opaque token
    if re.fullmatch(r"[a-z0-9][a-z0-9._\-]*", v):      # lowercase slug: model/service name
        return False                                    # e.g. qwen3-coder, in 38 transcripts
    classes = sum(bool(re.search(p, v)) for p in (r"[a-z]", r"[A-Z]", r"\d", r"[^A-Za-z0-9]"))
    return classes >= 3


def scrub(text, secrets):
    hits = 0
    for v in sorted(secrets, key=len, reverse=True):
        if v in text:
            text = text.replace(v, "[REDACTED:known-credential]")
            hits += 1
    for label, pat in PATTERNS:
        text, n = pat.subn("[REDACTED:%s]" % label, text)
        hits += n
    return text, hits


def load_state():
    if STATE.exists():
        try:
            return json.loads(STATE.read_text())
        except Exception:
            pass
    return {}


def main():
    secrets = known_secrets()
    print("loaded %d known secret values" % len(secrets))
    STAGE.mkdir(parents=True, exist_ok=True)
    state = load_state()
    new_state = {}
    changed = 0
    redactions = 0
    failures = []
    sent = []          # relative paths to ship this run

    for src in SRC.rglob("*.jsonl"):
        rel = src.relative_to(SRC)
        stat = src.stat()
        sig = "%d:%d" % (stat.st_mtime_ns, stat.st_size)
        new_state[str(rel)] = sig
        if state.get(str(rel)) == sig:
            continue  # unchanged since last run

        raw = src.read_text(errors="replace")
        clean, hits = scrub(raw, secrets)
        redactions += hits

        # Fail closed: never stage a file that still contains a known value.
        leaked = [v for v in secrets if v in clean]
        if leaked:
            failures.append(str(rel))
            new_state.pop(str(rel), None)  # retry next run
            continue

        dst = STAGE / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_text(clean)
        sent.append(str(rel))
        changed += 1

    if failures:
        print("ERROR: %d file(s) still contained known secrets after scrubbing:"
              % len(failures), file=sys.stderr)
        for f in failures[:10]:
            print("   " + f, file=sys.stderr)
        return 2

    print("scrubbed %d changed file(s); %d redactions applied" % (changed, redactions))
    if changed == 0 and STATE.exists():
        print("nothing new to sync")
        STATE.write_text(json.dumps(new_state))
        return 0

    # tar-over-ssh, not rsync: macOS ships openrsync (protocol 29), which cannot
    # negotiate with the NAS's GNU rsync 3.1.2 (protocol 31). COPYFILE_DISABLE
    # stops bsdtar emitting ._AppleDouble sidecars into the archive.
    # Paths are passed via -T, not as argv: project dirs start with "-"
    # (e.g. "-Users-nwilliams-GitHub..."), which tar would parse as flags.
    # It also keeps the invocation clear of ARG_MAX as history grows.
    listfile = STAGE.parent / "filelist.txt"
    listfile.write_text("".join(p + "\n" for p in sent))
    tar_cmd = ["tar", "czf", "-", "-C", str(STAGE), "-T", str(listfile)]
    env = dict(os.environ, COPYFILE_DISABLE="1")
    ssh_cmd = [
        "ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", NAS,
        "mkdir -p %s && tar xzf - -C %s" % (NAS_PATH, NAS_PATH),
    ]
    tar = subprocess.Popen(tar_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    ssh = subprocess.Popen(ssh_cmd, stdin=tar.stdout, stderr=subprocess.PIPE)
    tar.stdout.close()
    ssh_err = ssh.communicate()[1]
    tar.wait()
    if tar.returncode != 0 or ssh.returncode != 0:
        print("sync failed: tar=%d ssh=%d %s"
              % (tar.returncode, ssh.returncode, (ssh_err or b"").decode().strip()),
              file=sys.stderr)
        return 1  # state not saved -> retried next run

    STATE.parent.mkdir(parents=True, exist_ok=True)
    STATE.write_text(json.dumps(new_state))
    print("synced %d file(s) to %s:%s" % (changed, NAS, NAS_PATH))
    return 0


if __name__ == "__main__":
    sys.exit(main())
