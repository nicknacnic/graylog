"""Persistent CTEM synthetic-finding emitter.

Keeps the CTEM Scanner dashboard's Darknetian + per-adapter pages
populated now that the real DMARC/SPF/DKIM misconfigs on darknetian.com
are fixed (no real findings = empty pages).

Emits a curated set of synthetic findings as GELF to the same
127.0.0.1:12202/gelf input the real scanner uses, matching the
envelope shape in /opt/ctem-scanner/src/ctem_scanner/sinks/graylog.py
so they land in the existing CTEM Scanner stream + index set.

Coverage — one row per (adapter, kind) the dashboard widgets crosstab:

  infoblox_ctem          dns_hygiene
  infoblox_ctem          admin_panel_exposed
  infoblox_ctem          weak_tls
  infoblox_ctem          dangling_dns
  infoblox_lookalikes    lookalike_domain     × 2 (homograph + typo)
  axur                   brand_impersonation
  axur                   phishing_kit
  axur_ioc               ioc_reputation
  axur_ioc               malware_indicator
  virustotal             reputation_hit
  virustotal             sibling_domain
  dangling_dns           dangling_dns

Every row ships with:
  _synthetic: true             single source of truth for filter toggles
  _adapter:   <adapter>        matches the real scanner's adapter field
  _customer:  Darknetian
  _bounty_eligible: false      so the Bounty page stays clean

Safety: non-darknetian.com hosts use the IANA-reserved .example TLD
so a curious analyst clicking through never lands on a real target.
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

RUN_ID = "synthetic-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H")


def _level(sev: str) -> int:
    return {"critical": 2, "high": 3, "medium": 4, "low": 5, "info": 6}.get(sev, 6)


# (adapter, kind, severity, asset, short_message, evidence, external_id_suffix)
SYNTHETIC: list[tuple[str, str, str, str, str, str, str]] = [
    # ── infoblox_ctem (EASM crawler) ─────────────────────────────────
    ("infoblox_ctem", "dns_hygiene", "medium",
     "darknetian.com",
     "DNS hygiene demo: SPF missing on subdomain",
     "dig +short TXT support.darknetian.example returned no SPF record; "
     "inbound mail from this subdomain would pass weakly",
     "ctem:hygiene:spf-support"),
    ("infoblox_ctem", "admin_panel_exposed", "critical",
     "demo-jenkins.darknetian.example",
     "Admin panel demo: Jenkins /login reachable on public DNS",
     "GET https://demo-jenkins.darknetian.example/login -> 200, "
     "X-Jenkins: 2.426.3, anonymous read enabled",
     "ctem:admin:jenkins"),
    ("infoblox_ctem", "weak_tls", "high",
     "demo-api.darknetian.example",
     "Weak TLS demo: TLS 1.0 + RC4 cipher accepted",
     "openssl s_client -tls1 demo-api.darknetian.example:443 returned a "
     "valid handshake; cipher TLS_RSA_WITH_RC4_128_SHA negotiated",
     "ctem:tls:demo-api"),
    ("infoblox_ctem", "dangling_dns", "high",
     "demo-dangle.darknetian.example",
     "Dangling CNAME demo: → nonexistent.s3.amazonaws.com (NoSuchBucket)",
     "CNAME demo-dangle.darknetian.example -> nonexistent-bucket-1.s3.amazonaws.com; "
     "S3 returns <Code>NoSuchBucket</Code>",
     "ctem:dangling:demo-dangle"),

    # ── infoblox_lookalikes ──────────────────────────────────────────
    ("infoblox_lookalikes", "lookalike_domain", "high",
     "darknetian.com",
     "Lookalike demo: darknetían.com (Latin Small Letter I With Acute)",
     "Registered 2026-04-12 via NameSilo, MX configured to mailgun.org, "
     "homograph distance 1 from darknetian.com",
     "lookalikes:darknet-i-acute"),
    ("infoblox_lookalikes", "lookalike_domain", "medium",
     "darknetian.com",
     "Lookalike demo: darknet1an.com (digit-1-for-i substitution)",
     "Registered 2026-03-04 via Namecheap, no MX configured, parked nameservers; "
     "typosquat-for-resale profile (no phishing posture yet)",
     "lookalikes:darknet1an"),

    # ── axur (brand protection / ticket platform) ────────────────────
    ("axur", "brand_impersonation", "medium",
     "darknetian.com",
     "Demo brand-impersonation ticket: phishing kit (resolved)",
     "Axur ticket #DEMO-4012: phishing kit hosted at darknetian-login.example "
     "served Darknetian-branded login page; resolved 2026-05-15",
     "axur:ticket:demo-4012"),
    ("axur", "phishing_kit", "high",
     "darknetian.com",
     "Demo phishing-kit detection: credential harvester live",
     "Axur ticket #DEMO-4128: WordPress-hosted page at "
     "darknetian-secure-login.example/wp-login.php cloning Darknetian "
     "login template; reported to host for takedown",
     "axur:phish:demo-4128"),

    # ── axur_ioc (IOC feed) ──────────────────────────────────────────
    ("axur_ioc", "ioc_reputation", "medium",
     "203.0.113.42",
     "Demo IOC: IP appeared in Axur threat feed",
     "Axur IOC export 2026-05-17: 203.0.113.42 tagged as 'phishing-c2', "
     "first-seen 2026-05-09, observed serving a Darknetian phishing kit",
     "axur_ioc:ip:203.0.113.42"),
    ("axur_ioc", "malware_indicator", "high",
     "darknetian.com",
     "Demo malware IOC: SHA256 referenced in phish kit",
     "Axur IOC export: SHA256 d41d8cd98f00b204e9800998ecf8427e found in "
     "phishing-kit archive that targeted Darknetian login flow",
     "axur_ioc:sha256:d41d8cd"),

    # ── virustotal ───────────────────────────────────────────────────
    ("virustotal", "reputation_hit", "medium",
     "darknetian.com",
     "VT demo: 2 engines flagged darknetian-typo.example",
     "VirusTotal /domains lookup for darknetian-typo.example: "
     "ESET-NOD32:Phishing, Sophos:Suspicious (last_analysis_stats.malicious=2)",
     "vt:reputation:darknetian-typo"),
    ("virustotal", "sibling_domain", "low",
     "darknetian.com",
     "VT demo: sibling-domain discovery",
     "VirusTotal subdomain enumeration surfaced demo-shadow.darknetian.example "
     "(not present in our zone), TLS observed on CT logs 2026-05-10",
     "vt:sibling:demo-shadow"),

    # ── dangling_dns (built-in dangling-DNS detector) ────────────────
    ("dangling_dns", "dangling_dns", "critical",
     "demo-heroku.darknetian.example",
     "Dangling DNS demo: → vanished-app.herokuapp.com (No such app)",
     "CNAME demo-heroku.darknetian.example -> vanished-app.herokuapp.com; "
     "Heroku returns 'No such app' fingerprint — high-confidence takeover candidate",
     "dangling:heroku:vanished-app"),
]


def emit_one(adapter, kind, severity, asset, short, evidence, ext_id) -> bool:
    payload = {
        "version": "1.1",
        "host": SOURCE,
        "short_message": short[:1024],
        "level": _level(severity),
        "timestamp": time.time(),
        "_customer": "Darknetian",
        "_kind": kind,
        "_severity": severity,
        "_asset": asset,
        "_evidence": evidence,
        "_adapter": adapter,
        "_external_id": ext_id,
        "_finding_id": ext_id,
        # GELF additional fields must be string/number per spec — Graylog
        # silently drops bool values. Emit as "true"/"false" strings.
        "_bounty_eligible": "false",
        "_bounty_platform": "",
        "_bounty_policy_url": "",
        "_run_id": RUN_ID,
        "_synthetic": "true",
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
        print(f"  emit failed for {ext_id}: {e}", file=sys.stderr)
        return False


def main() -> None:
    print(f"== ctem-synthetic emitter run_id={RUN_ID} ==")
    ok = sum(emit_one(*row) for row in SYNTHETIC)
    print(f"  emitted={ok}/{len(SYNTHETIC)} across "
          f"{len({r[0] for r in SYNTHETIC})} adapters, "
          f"{len({r[1] for r in SYNTHETIC})} kinds")


if __name__ == "__main__":
    main()
