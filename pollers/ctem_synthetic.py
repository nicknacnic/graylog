"""Persistent CTEM synthetic-finding emitter.

Keeps the Infoblox Operations / CTEM Scanner dashboard's Darknetian
page from going blank now that the real DMARC/SPF/DKIM misconfigs are
fixed in Cloudflare (no real findings = empty dashboard).

Emits five curated synthetic findings as GELF to the same
127.0.0.1:12202/gelf input the real scanner uses, matching the
envelope shape in
  /opt/ctem-scanner/src/ctem_scanner/sinks/graylog.py
so they land in the existing CTEM Scanner stream + index set with no
new plumbing.

Filtering knob: every event ships with `_synthetic: true` and
`_adapter: synthetic`. Dashboard widgets that want the "real picture"
can `NOT _synthetic:true` to hide; widgets that want demo persistence
(or full population) include them.

Safety:
  - All non-darknetian.com hosts use the IANA-reserved .example TLD
    so a curious analyst clicking through never lands on a real
    target.
  - `_bounty_eligible: false` so the Bounty page stays clean.
  - Source label is the same as the real scanner ('ctem-scanner') —
    that's what the existing stream rule matches.
"""

from __future__ import annotations

import json
import os
import sys
import time
import socket
from datetime import datetime, timezone
from urllib import error, request

GELF_URL = os.environ.get("GELF_URL", "http://127.0.0.1:12202/gelf")
SOURCE = os.environ.get("CTEM_SYNTHETIC_HOST", "ctem-scanner").strip()

# Cadence-derived run id (UTC hour). Lets the dashboard detect "is
# this fresh" without us needing UUIDs.
RUN_ID = "synthetic-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H")


def _level(sev: str) -> int:
    return {"critical": 2, "high": 3, "medium": 4, "low": 5, "info": 6}.get(sev, 6)


# (kind, severity, asset, short_message, evidence, external_id)
SYNTHETIC: list[tuple[str, str, str, str, str, str]] = [
    (
        "dangling_dns", "high",
        "demo-dangle.darknetian.example",
        "Dangling CNAME demo: → nonexistent.s3.amazonaws.com (NoSuchBucket)",
        "CNAME demo-dangle.darknetian.example -> nonexistent-bucket-1.s3.amazonaws.com; "
        "S3 returns <Code>NoSuchBucket</Code>",
        "synthetic:dangling:demo-dangle",
    ),
    (
        "lookalike_domain", "high",
        "darknetian.com",
        "Lookalike demo: darknetían.com (Latin Small Letter I With Acute)",
        "Registered 2026-04-12 via NameSilo, MX configured to mailgun.org, "
        "homograph distance 1 from darknetian.com",
        "synthetic:lookalike:darknetian-i-acute",
    ),
    (
        "admin_panel_exposed", "critical",
        "demo-jenkins.darknetian.example",
        "Admin panel demo: Jenkins /login reachable on public DNS",
        "GET https://demo-jenkins.darknetian.example/login -> 200, "
        "X-Jenkins: 2.426.3, anonymous read enabled",
        "synthetic:admin_panel:demo-jenkins",
    ),
    (
        "weak_tls", "critical",
        "demo-api.darknetian.example",
        "Demo high-severity exposure: TLS 1.0 enabled",
        "openssl s_client -tls1 demo-api.darknetian.example:443 returned a valid "
        "handshake; cipher TLS_RSA_WITH_AES_128_CBC_SHA negotiated",
        "synthetic:weak_tls:demo-api",
    ),
    (
        "brand_impersonation", "medium",
        "darknetian.com",
        "Demo brand-impersonation ticket (resolved)",
        "Axur ticket #DEMO-4012: phishing kit hosted at darknetian-login.example "
        "served Darknetian-branded login page; resolved 2026-05-15",
        "synthetic:brand:demo-4012",
    ),
]


def emit_one(kind, severity, asset, short, evidence, external_id) -> bool:
    payload = {
        "version": "1.1",
        "host": SOURCE,
        "short_message": short[:1024],
        "level": _level(severity),
        "timestamp": time.time(),
        # ── match the real scanner's envelope ────────────────────────
        "_customer": "Darknetian",
        "_kind": kind,
        "_severity": severity,
        "_asset": asset,
        "_evidence": evidence,
        "_adapter": "synthetic",
        "_external_id": external_id,
        "_finding_id": external_id,
        "_bounty_eligible": False,
        "_bounty_platform": "",
        "_bounty_policy_url": "",
        "_run_id": RUN_ID,
        # ── the differentiator ────────────────────────────────────────
        "_synthetic": True,
    }
    try:
        req = request.Request(
            GELF_URL, data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
        )
        with request.urlopen(req, timeout=10) as r:
            r.read()
        return True
    except (error.URLError, socket.timeout, OSError) as e:
        print(f"  emit failed for {external_id}: {e}", file=sys.stderr)
        return False


def main() -> None:
    print(f"== ctem-synthetic emitter run_id={RUN_ID} ==")
    ok = sum(emit_one(*row) for row in SYNTHETIC)
    print(f"  emitted={ok}/{len(SYNTHETIC)}")


if __name__ == "__main__":
    main()
