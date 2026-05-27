"""Persistent CTEM synthetic-finding emitter.

Keeps the CTEM Scanner dashboard populated now that the real DMARC/SPF/
DKIM misconfigs on darknetian.com are fixed. Two modes:

  live (default)
    Runs hourly via systemd timer. Emits a variable number of events
    (~3-10/cycle) sampled mostly from the baseline pool, with the
    occasional attack-flavored finding so trendlines aren't flat.

  backfill
    One-shot. Walks the last 30 days hourly, emits baseline noise that
    follows business-hour + weekend rhythms, AND injects a curated
    attack-staging narrative on day -7 that the dashboard can tell as
    a demo story. Re-running with the same RNG seed reproduces the
    same shape — but Graylog doesn't dedup at index time so DO NOT
    backfill twice unless you also wipe the existing synthetic events.

All events ship with:
  source           ctem-scanner
  _adapter         <real adapter name>   (infoblox_ctem, axur, etc.)
  _customer        Darknetian
  _synthetic       "true"                (string — Graylog drops bool)
  _bounty_eligible "false"
  _run_id          synthetic-<UTC-hour>  or  synthetic-backfill

Filter the synthetic set on/off from any widget with:
    synthetic:true       (include only synthetic)
    NOT synthetic:true   (real findings only)
"""

from __future__ import annotations

import argparse
import json
import os
import random
import socket
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from urllib import error, request

GELF_URL = os.environ.get("GELF_URL", "http://127.0.0.1:12202/gelf")
SOURCE = os.environ.get("CTEM_SYNTHETIC_HOST", "ctem-scanner").strip()


def _level(sev: str) -> int:
    return {"critical": 2, "high": 3, "medium": 4, "low": 5, "info": 6}.get(sev, 6)


@dataclass
class T:
    """Synthetic finding template."""
    adapter: str
    kind: str
    severity: str
    asset: str
    short: str
    evidence: str
    category: str        # "baseline" or "attack"
    bounty: bool = False  # in-scope for the Darknetian VDP


BOUNTY_PLATFORM = "hackerone"
BOUNTY_POLICY_URL = "https://hackerone.com/darknetian"


# ─── Template pool ────────────────────────────────────────────────────────
# Baseline = mundane findings every grid sees (hygiene, slow-burn dangling
# DNS, reputation noise). Attack = signals of an active campaign
# (admin-panel probing, weak TLS, lookalike registrations during staging,
# phishing kits going live, IOC hits).

TEMPLATES: list[T] = [
    # baseline
    T("infoblox_ctem", "dns_hygiene", "medium", "darknetian.com",
      "DNS hygiene: SPF missing on subdomain",
      "dig +short TXT support.darknetian.example returned no SPF record",
      "baseline"),
    T("infoblox_ctem", "dns_hygiene", "low", "darknetian.com",
      "DNS hygiene: DMARC p=none on subdomain",
      "DMARC record present but policy is p=none — visibility only, no enforcement",
      "baseline"),
    T("infoblox_ctem", "dns_hygiene", "low", "darknetian.com",
      "DNS hygiene: missing CAA record",
      "No CAA record on darknetian.example — any CA can issue certs for this label",
      "baseline"),
    T("infoblox_ctem", "dangling_dns", "high", "demo-dangle.darknetian.example",
      "Dangling CNAME → nonexistent S3 bucket",
      "CNAME → nonexistent-bucket-1.s3.amazonaws.com; <Code>NoSuchBucket</Code>",
      "baseline", bounty=True),
    T("infoblox_lookalikes", "lookalike_domain", "medium", "darknetian.com",
      "Lookalike: darknet1an.com (digit-1-for-i)",
      "Registered via Namecheap, no MX, parked nameservers — typosquat-for-resale profile",
      "baseline"),
    T("axur_ioc", "ioc_reputation", "low", "darknetian.com",
      "IOC: hash referenced in low-confidence feed",
      "Axur IOC export: SHA256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4 — historical match",
      "baseline"),
    T("virustotal", "reputation_hit", "low", "darknetian.com",
      "VT reputation: 1 vendor flagged a related sibling",
      "VT /domains lookup surfaced 1/91 malicious vote on a sibling domain",
      "baseline"),
    T("virustotal", "sibling_domain", "info", "darknetian.com",
      "VT sibling-domain discovery",
      "VT subdomain enumeration surfaced demo-shadow.darknetian.example (CT logs)",
      "baseline"),
    T("dangling_dns", "dangling_dns", "high", "demo-cf.darknetian.example",
      "Dangling DNS: CNAME → vanished CloudFront distribution",
      "CNAME → d1234567890.cloudfront.net; returns NoSuchDistribution",
      "baseline", bounty=True),

    # attack-flavored
    T("infoblox_ctem", "admin_panel_exposed", "critical",
      "demo-jenkins.darknetian.example",
      "Admin panel: Jenkins /login reachable on public DNS",
      "GET /login → 200, X-Jenkins: 2.426.3, anonymous read enabled",
      "attack", bounty=True),
    T("infoblox_ctem", "admin_panel_exposed", "high",
      "demo-grafana.darknetian.example",
      "Admin panel: Grafana /login reachable on public DNS",
      "GET /login → 200, Grafana 10.4.0, basic-auth required",
      "attack", bounty=True),
    T("infoblox_ctem", "weak_tls", "high", "demo-api.darknetian.example",
      "Weak TLS: TLS 1.0 + RC4 cipher accepted",
      "openssl s_client -tls1 → handshake OK, cipher TLS_RSA_WITH_RC4_128_SHA",
      "attack", bounty=True),
    T("infoblox_ctem", "weak_tls", "medium", "demo-mail.darknetian.example",
      "Weak TLS: SHA-1 cert chain",
      "openssl s_client → leaf cert signature algorithm = sha1WithRSAEncryption",
      "attack", bounty=True),
    T("infoblox_lookalikes", "lookalike_domain", "high", "darknetian.com",
      "Lookalike: darknetían.com (Latin Small Letter I With Acute)",
      "Registered via NameSilo, MX → mailgun.org — phishing posture",
      "attack"),
    T("infoblox_lookalikes", "lookalike_domain", "high", "darknetian.com",
      "Lookalike: darknetiian.com (double-i)",
      "Registered, MX configured, A points to a known-bad shared host",
      "attack"),
    T("axur", "brand_impersonation", "high", "darknetian.com",
      "Brand-impersonation: phishing-kit live",
      "Axur ticket: WordPress page at darknetian-secure-login.example/wp-login.php "
      "clones Darknetian login template",
      "attack"),
    T("axur", "phishing_kit", "critical", "darknetian.com",
      "Phishing kit: credential harvester active",
      "Axur ticket: page at darknetian-login.example posts to /collect.php; "
      "credentials forwarded to telegram bot",
      "attack"),
    T("axur_ioc", "ioc_reputation", "medium", "203.0.113.42",
      "IOC: IP in phishing-c2 feed",
      "Axur IOC: 203.0.113.42 tagged 'phishing-c2', first-seen recent, "
      "observed serving Darknetian phishing kit",
      "attack"),
    T("axur_ioc", "ioc_reputation", "high", "203.0.113.99",
      "IOC: IP in active-campaign feed",
      "Axur IOC: 203.0.113.99 tagged 'campaign-darknet-may', "
      "co-resolves with multiple lookalike domains",
      "attack"),
    T("axur_ioc", "malware_indicator", "high", "darknetian.com",
      "Malware IOC: SHA256 from phishing-kit archive",
      "Axur IOC export: SHA256 d41d8cd98f00b204e9800998ecf8427e — "
      "Darknetian-themed phishing kit",
      "attack"),
    T("virustotal", "reputation_hit", "high", "darknetian.com",
      "VT reputation: multiple engines flagged darknetian-typo.example",
      "VT /domains: 6/91 malicious (ESET, Sophos, Forcepoint, Kaspersky, "
      "Bitdefender, Avast)",
      "attack"),
]

BASELINE = [t for t in TEMPLATES if t.category == "baseline"]
ATTACK = [t for t in TEMPLATES if t.category == "attack"]


# ─── Story timeline (peak around day -7) ──────────────────────────────────
# Each entry: (days_ago, utc_hour, template_index) — hand-curated so the
# 30d backfill tells a kill-chain shape rather than random burst. These
# fire IN ADDITION TO the random baseline noise on those hours.

@dataclass
class StoryEvent:
    days_ago: int
    hour: int
    tpl: T


# Lookup by a semantic key so the story doesn't break when the template
# list is reordered or extended.
_by_key = {f"{t.adapter}:{t.kind}:{t.severity}:{t.asset}": t for t in TEMPLATES}


def _t(adapter: str, kind: str, sev: str, asset: str) -> T:
    k = f"{adapter}:{kind}:{sev}:{asset}"
    if k not in _by_key:
        raise KeyError(f"template missing: {k}")
    return _by_key[k]


STORY: list[StoryEvent] = [
    # T-8: early IOC warning (something's coming)
    StoryEvent(8, 14, _t("axur_ioc", "ioc_reputation", "medium", "203.0.113.42")),
    StoryEvent(8, 22, _t("axur_ioc", "ioc_reputation", "high",   "203.0.113.99")),

    # T-7 morning: lookalike-domain staging
    StoryEvent(7, 4,  _t("infoblox_lookalikes", "lookalike_domain", "high", "darknetian.com")),
    StoryEvent(7, 8,  _t("infoblox_lookalikes", "lookalike_domain", "high", "darknetian.com")),
    StoryEvent(7, 11, _t("axur_ioc", "malware_indicator", "high", "darknetian.com")),

    # T-7 afternoon: scanning / probing
    StoryEvent(7, 14, _t("infoblox_ctem", "admin_panel_exposed", "critical", "demo-jenkins.darknetian.example")),
    StoryEvent(7, 15, _t("infoblox_ctem", "admin_panel_exposed", "high",     "demo-grafana.darknetian.example")),
    StoryEvent(7, 15, _t("infoblox_ctem", "weak_tls", "high",   "demo-api.darknetian.example")),
    StoryEvent(7, 16, _t("infoblox_ctem", "weak_tls", "medium", "demo-mail.darknetian.example")),

    # T-7 evening: live phishing + brand-impersonation cascade
    StoryEvent(7, 17, _t("axur", "brand_impersonation", "high",     "darknetian.com")),
    StoryEvent(7, 17, _t("axur", "phishing_kit",        "critical", "darknetian.com")),
    StoryEvent(7, 18, _t("virustotal", "reputation_hit", "high",    "darknetian.com")),
    StoryEvent(7, 19, _t("infoblox_ctem", "admin_panel_exposed", "critical", "demo-jenkins.darknetian.example")),
    StoryEvent(7, 20, _t("axur", "phishing_kit",        "critical", "darknetian.com")),

    # T-6: trailing fallout
    StoryEvent(6, 3,  _t("infoblox_ctem", "dangling_dns", "high", "demo-dangle.darknetian.example")),
    StoryEvent(6, 10, _t("axur_ioc", "ioc_reputation", "low", "darknetian.com")),
]


# ─── Shape for baseline noise ─────────────────────────────────────────────
PEAK_DAYS_AGO = 7   # Backfill story spike anchor: 7 days back from now.

# Recurring spike days-of-month for the live cron. Set to multiple
# DoM values to get multiple peaks per month — defaults to {12, 26}
# so the dashboard's 30d window always shows ~2 peaks ~14 days apart.
PEAK_DAYS_OF_MONTH = {
    int(x) for x in os.environ.get("CTEM_SYNTHETIC_PEAK_DOM", "12,26").split(",")
    if x.strip()
}


def baseline_count(t: datetime, days_ago: int) -> int:
    """Events to emit for a given hour. Quiet most of the time so the
    PEAK_DAYS_AGO day stands out against noise."""
    n = random.choices([0, 1, 2], weights=[3, 5, 2])[0]
    if 14 <= t.hour < 22:           # 8am-4pm MDT bump
        n += random.choices([0, 1, 2], weights=[4, 4, 2])[0]
    if t.weekday() >= 5:
        n = max(0, n - 1)
    # Slight rise the day before + after the spike so the peak has
    # context rather than appearing as a single isolated tower.
    if days_ago in (PEAK_DAYS_AGO - 1, PEAK_DAYS_AGO + 1):
        n += random.randint(0, 2)
    return n


def peak_burst_count(t: datetime, days_ago: int) -> int:
    """Additional attack-pool events to layer on top of baseline during
    the peak window. Concentrates the spike in the 14-22 UTC window
    (8a-4p MDT) so it tells the 'business-hour campaign' story."""
    if days_ago != PEAK_DAYS_AGO:
        return 0
    if 14 <= t.hour < 22:
        return random.randint(8, 15)   # heavy
    if 10 <= t.hour < 14 or 22 <= t.hour < 24:
        return random.randint(2, 5)    # shoulders
    return 0


# ─── Emit ─────────────────────────────────────────────────────────────────
def emit_one(tpl: T, when: datetime, suffix: str = "") -> bool:
    # Stable per-template external_id so the dashboard can use
    # cardinality(external_id) or cardinality(asset) for the headline
    # "distinct findings" count. The `suffix` arg is honored only when
    # the caller explicitly wants a unique-per-emission id (story
    # events use it for traceability).
    if suffix:
        ext_id = f"{tpl.adapter}:{tpl.kind}:{suffix}"
    else:
        ext_id = f"{tpl.adapter}:{tpl.kind}:{tpl.asset}"
    run_id = "synthetic-" + when.strftime("%Y%m%dT%H")
    payload = {
        "version": "1.1",
        "host": SOURCE,
        "short_message": tpl.short[:1024],
        "level": _level(tpl.severity),
        "timestamp": when.timestamp(),
        "_customer": "Darknetian",
        "_kind": tpl.kind,
        "_severity": tpl.severity,
        "_asset": tpl.asset,
        "_evidence": tpl.evidence,
        "_adapter": tpl.adapter,
        "_external_id": ext_id,
        "_finding_id": ext_id,
        "_bounty_eligible": "true" if tpl.bounty else "false",
        "_bounty_platform": BOUNTY_PLATFORM if tpl.bounty else "",
        "_bounty_policy_url": BOUNTY_POLICY_URL if tpl.bounty else "",
        "_run_id": run_id,
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


# ─── Modes ────────────────────────────────────────────────────────────────
def run_live() -> None:
    """Current-time emit, variable count. Recurring monthly peak: on
    PEAK_DAY_OF_MONTH the cron amplifies into an attack-pool burst
    during business hours so the 30d trendline always shows one
    visible spike."""
    now = datetime.now(timezone.utc)
    dom = now.day

    is_peak_day = dom in PEAK_DAYS_OF_MONTH
    is_peak_hour = is_peak_day and 14 <= now.hour < 22
    is_shoulder = any(dom in (p - 1, p + 1) for p in PEAK_DAYS_OF_MONTH)

    if is_peak_hour:
        n = random.randint(12, 20)
        attack_p = 0.75
        label = "PEAK"
    elif is_peak_day:
        n = random.randint(6, 12)
        attack_p = 0.50
        label = "peak-day"
    elif is_shoulder:
        n = random.randint(5, 10)
        attack_p = 0.30
        label = "shoulder"
    else:
        n = random.randint(3, 8)
        attack_p = 0.15
        label = "baseline"

    print(f"== ctem-synthetic live n={n} mode={label} ts={now.isoformat()} ==")
    ok = 0
    for _ in range(n):
        pool = ATTACK if random.random() < attack_p else BASELINE
        tpl = random.choice(pool)
        if emit_one(tpl, now + timedelta(seconds=random.randint(0, 3590))):
            ok += 1
    print(f"  emitted={ok}/{n}")


def run_backfill() -> None:
    """Walk 30d hourly, emit shaped baseline + curated story events."""
    random.seed(42)  # deterministic shape on re-run
    now = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
    start = now - timedelta(days=30)
    print(f"== ctem-synthetic backfill {start.date()} → {now.date()} ==")

    # Index story events by (days_ago, hour) for O(1) lookup per cycle
    story_by_hour: dict[tuple[int, int], list[T]] = {}
    for s in STORY:
        story_by_hour.setdefault((s.days_ago, s.hour), []).append(s.tpl)

    total = 0
    cur = start
    while cur <= now:
        days_ago = (now.date() - cur.date()).days
        # Baseline noise
        for _ in range(baseline_count(cur, days_ago)):
            tpl = random.choice(BASELINE)
            offset = random.randint(0, 3599)
            if emit_one(tpl, cur + timedelta(seconds=offset)):
                total += 1
        # Peak-day burst — sampled from the attack pool for that
        # "active campaign" silhouette
        for _ in range(peak_burst_count(cur, days_ago)):
            tpl = random.choice(ATTACK)
            offset = random.randint(0, 3599)
            if emit_one(tpl, cur + timedelta(seconds=offset)):
                total += 1
        # Story events — curated narrative beats anchored to specific
        # (days_ago, hour). Small jitter inside the hour.
        for tpl in story_by_hour.get((days_ago, cur.hour), []):
            offset = random.randint(60, 3540)
            if emit_one(tpl, cur + timedelta(seconds=offset),
                        suffix=f"story-d{days_ago}-h{cur.hour}-{offset}"):
                total += 1
        cur += timedelta(hours=1)

    print(f"  emitted={total} events across 30d "
          f"(story events: {len(STORY)})")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["live", "backfill"], default="live")
    args = ap.parse_args()
    if args.mode == "backfill":
        run_backfill()
    else:
        run_live()


if __name__ == "__main__":
    main()
