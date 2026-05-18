"""Cloudflare → NIOS darknetian.com sync (additive, idempotent).

Pulls all DNS records from the Cloudflare-hosted `darknetian.com` zone and
writes anything NIOS doesn't already have. Existing NIOS records — both
internal-only (`vsphere`, `equinox`, ...) AND records previously synced
from CF — are left alone.

The defaults are conservative on purpose. After the lookalike-wipe incident
on a different platform we treat zone APIs as "read everything; write the
*minimum* delta; never delete." This script will never:

  - delete a NIOS record
  - update a NIOS record (even if the CF value differs — see CONFLICT below)
  - touch zone-level objects (SOA, NS, glue)
  - touch SVCB / TLSA records (NIOS WAPI v2.13 has no native support;
    the `darknetian-ans` agent zoo and DANE records stay CF-only)

What it does:

  - GET all CF records for `darknetian.com`
  - GET all NIOS records per type (A, AAAA, CNAME, MX, TXT)
  - For each CF record:
      MISSING in NIOS → POST it (dry-run by default)
      SAME value      → skip (idempotent re-run)
      DIFFERENT value → log as CONFLICT, do NOT overwrite

Run dry-run (default):

    set -a; . /etc/cf-to-nios-sync/env; set +a
    python3 /opt/cf-to-nios-sync/cf_to_nios_sync.py

Run for real (write mode):

    SYNC_DRY_RUN=0 python3 /opt/cf-to-nios-sync/cf_to_nios_sync.py

Env vars (all required):

    CF_API_TOKEN        Cloudflare API token with Zone Read on the zone
    NIOS_HOST           e.g. gm.darknetian.com
    NIOS_USER           e.g. admin
    NIOS_PASS
    NIOS_WAPI_VER       default v2.13
    NIOS_VIEW           default 'default'

Optional:

    CF_ZONE             default 'darknetian.com'
    SYNC_DRY_RUN        '1' (default) or '0'
    SYNC_TYPES          CSV, default 'A,AAAA,CNAME,MX,TXT'
    GELF_URL            if set, emit one GELF summary event per run
"""

from __future__ import annotations

import json
import os
import ssl
import sys
import time
from typing import Any
from urllib import error, parse, request

CF_TOKEN = os.environ["CF_API_TOKEN"]
CF_ZONE = os.environ.get("CF_ZONE", "darknetian.com").strip().lower().rstrip(".")

NIOS_HOST = os.environ["NIOS_HOST"]
NIOS_USER = os.environ["NIOS_USER"]
NIOS_PASS = os.environ["NIOS_PASS"]
NIOS_WAPI = os.environ.get("NIOS_WAPI_VER", "v2.13").strip()
NIOS_VIEW = os.environ.get("NIOS_VIEW", "default").strip()

DRY_RUN = os.environ.get("SYNC_DRY_RUN", "1") == "1"
TYPES = {t.strip().upper() for t in os.environ.get("SYNC_TYPES", "A,AAAA,CNAME,MX,TXT").split(",") if t.strip()}
GELF_URL = os.environ.get("GELF_URL", "").strip()

NIOS_BASE = f"https://{NIOS_HOST}/wapi/{NIOS_WAPI}"
SUPPORTED = {"A", "AAAA", "CNAME", "MX", "TXT"}


# ── HTTP helpers ──────────────────────────────────────────────────────────
def _ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def cf_get(path: str) -> dict:
    req = request.Request(
        f"https://api.cloudflare.com/client/v4/{path}",
        headers={"Authorization": f"Bearer {CF_TOKEN}",
                 "Accept": "application/json"},
    )
    with request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())


def nios_call(method: str, path: str, body: dict | None = None) -> Any:
    import base64
    auth = base64.b64encode(f"{NIOS_USER}:{NIOS_PASS}".encode()).decode()
    headers = {"Authorization": f"Basic {auth}",
               "Accept": "application/json"}
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    req = request.Request(f"{NIOS_BASE}/{path}", method=method,
                          data=data, headers=headers)
    try:
        with request.urlopen(req, context=_ctx(), timeout=30) as r:
            txt = r.read().decode()
            return json.loads(txt) if txt else None
    except error.HTTPError as e:
        body_txt = e.read().decode("utf-8", "replace")[:500]
        raise RuntimeError(f"{method} {path} -> {e.code}: {body_txt}") from None


# ── Cloudflare side ───────────────────────────────────────────────────────
def cf_fetch_zone() -> list[dict]:
    zones = cf_get(f"zones?name={parse.quote(CF_ZONE)}")
    if not zones.get("result"):
        sys.exit(f"ERROR: CF zone {CF_ZONE!r} not found")
    zone_id = zones["result"][0]["id"]
    out: list[dict] = []
    page = 1
    while True:
        resp = cf_get(f"zones/{zone_id}/dns_records?per_page=100&page={page}")
        out.extend(resp["result"])
        info = resp.get("result_info") or {}
        if page * info.get("per_page", 100) >= info.get("total_count", 0):
            break
        page += 1
    return out


# ── NIOS side ─────────────────────────────────────────────────────────────
_NIOS_TYPE_MAP = {
    "A": ("record:a", "ipv4addr"),
    "AAAA": ("record:aaaa", "ipv6addr"),
    "CNAME": ("record:cname", "canonical"),
    "MX": ("record:mx", "mail_exchanger"),
    "TXT": ("record:txt", "text"),
}


def nios_fetch(rtype: str) -> list[dict]:
    obj, _ = _NIOS_TYPE_MAP[rtype]
    return nios_call("GET", f"{obj}?zone={CF_ZONE}&view={NIOS_VIEW}&_max_results=2000") or []


def _norm_name(name: str) -> str:
    return name.lower().rstrip(".")


def _nios_value(rec: dict, rtype: str) -> str:
    obj, value_field = _NIOS_TYPE_MAP[rtype]
    v = rec.get(value_field, "")
    if rtype == "CNAME":
        v = str(v).rstrip(".").lower()
    elif rtype == "MX":
        v = f"{rec.get('preference', 0)} {str(v).rstrip('.').lower()}"
    elif rtype == "TXT":
        # NIOS returns text without surrounding quotes; collapse spaces
        # nothing
        pass
    return str(v)


# ── CF record → comparable shape ──────────────────────────────────────────
def _cf_normalize(r: dict) -> tuple[str, str, str] | None:
    """Returns (name, type, normalized_value) or None if unsupported."""
    rtype = r["type"]
    if rtype not in SUPPORTED:
        return None
    name = _norm_name(r["name"])
    content = r.get("content", "")
    if rtype == "CNAME":
        v = str(content).rstrip(".").lower()
    elif rtype == "MX":
        v = f"{r.get('priority', 0)} {str(content).rstrip('.').lower()}"
    elif rtype == "TXT":
        # CF returns single-string TXTs as the literal payload (no
        # quotes), and multi-string TXTs as the quoted segments
        # concatenated with `" "` between them, e.g.
        #   "capabilities=foo" "version=1.0.0" "description=bar"
        # NIOS' record:txt has a single `text` field; collapsing the
        # segments loses the on-wire boundaries (changes the meaning
        # for any reader that does segment-aware parsing). Surface
        # those as "multi-string unsupported" rather than corrupting
        # the value.
        v = str(content)
        if '" "' in v:
            return None  # caller treats None as unsupported
        if v.startswith('"') and v.endswith('"'):
            v = v[1:-1]
    else:
        v = str(content)
    return (name, rtype, v)


def _cf_body_for_nios(r: dict) -> dict:
    rtype = r["type"]
    name = _norm_name(r["name"])
    common = {"name": name, "view": NIOS_VIEW,
              "comment": "synced from Cloudflare"}
    content = r.get("content", "")
    if rtype == "A":
        return {**common, "ipv4addr": content}
    if rtype == "AAAA":
        return {**common, "ipv6addr": content}
    if rtype == "CNAME":
        return {**common, "canonical": str(content).rstrip(".")}
    if rtype == "MX":
        return {**common, "mail_exchanger": str(content).rstrip("."),
                "preference": int(r.get("priority") or 0)}
    if rtype == "TXT":
        # Preserve the literal payload (strip outer quotes if present)
        v = str(content)
        if v.startswith('"') and v.endswith('"'):
            v = v[1:-1]
        v = v.replace('" "', '')
        return {**common, "text": v}
    raise ValueError(rtype)


# ── GELF ──────────────────────────────────────────────────────────────────
def gelf(short: str, **fields: Any) -> None:
    if not GELF_URL:
        return
    msg = {"version": "1.1", "host": "cf-to-nios-sync",
           "short_message": short[:1024], "level": 6,
           "timestamp": time.time()}
    for k, v in fields.items():
        if v is None:
            continue
        msg[k if k.startswith("_") else f"_{k}"] = v
    try:
        req = request.Request(GELF_URL, data=json.dumps(msg).encode(),
                              headers={"Content-Type": "application/json"})
        with request.urlopen(req, timeout=5) as r:
            r.read()
    except Exception as exc:
        print(f"GELF failed: {exc}", file=sys.stderr)


# ── main ──────────────────────────────────────────────────────────────────
def main() -> int:
    print(f"== cf-to-nios sync zone={CF_ZONE!r} dry_run={DRY_RUN} types={sorted(TYPES)} ==")

    cf_records = cf_fetch_zone()
    print(f"  CF records: {len(cf_records)}")

    # Build NIOS index keyed by (name, type) → list of values
    nios_index: dict[tuple[str, str], list[str]] = {}
    for rtype in sorted(TYPES & SUPPORTED):
        recs = nios_fetch(rtype)
        for r in recs:
            n = _norm_name(r["name"])
            nios_index.setdefault((n, rtype), []).append(_nios_value(r, rtype))
        print(f"  NIOS {rtype}: {len(recs)}")

    created: list[str] = []
    skipped_same: list[str] = []
    conflicts: list[str] = []
    skipped_type: list[str] = []
    skipped_apex_ns: list[str] = []

    for r in cf_records:
        if r["type"] not in SUPPORTED:
            skipped_type.append(f"{r['type']:6} {r['name']} (type unsupported)")
            continue
        norm = _cf_normalize(r)
        if norm is None:
            skipped_type.append(f"{r['type']:6} {r['name']} (multi-string TXT)")
            continue
        name, rtype, cf_value = norm

        # Skip apex NS/SOA-equivalents (CF doesn't expose SOA via this API
        # but does expose NS) — NIOS owns those for its own view.
        if rtype == "CNAME" and name == CF_ZONE:
            # CNAME at apex is unusual but if CF has one, skip.
            skipped_apex_ns.append(f"{rtype} apex {name}")
            continue

        key = (name, rtype)
        existing_values = nios_index.get(key, [])

        if cf_value in existing_values:
            skipped_same.append(f"{rtype:6} {name} = {cf_value[:60]}")
            continue

        if existing_values and rtype in ("A", "CNAME"):
            # For singleton-style types (A, CNAME) at the same name,
            # disagreement is a CONFLICT — do NOT overwrite. Operator
            # decides.
            conflicts.append(
                f"{rtype:6} {name}: NIOS={existing_values!r} CF={cf_value!r}")
            continue

        # MX and TXT allow multiple values per name — if value missing,
        # add it. (A also allows multiple per name in NIOS, but the
        # convention here is treat A/CNAME singleton to avoid surprises.)
        if not DRY_RUN:
            obj = _NIOS_TYPE_MAP[rtype][0]
            body = _cf_body_for_nios(r)
            try:
                nios_call("POST", obj, body)
            except RuntimeError as exc:
                conflicts.append(f"{rtype:6} {name} POST failed: {exc}")
                continue
        created.append(f"{rtype:6} {name} = {cf_value[:80]}")

    print()
    print(f"== summary ==")
    print(f"  would-create: {len(created)}" if DRY_RUN else f"  created:     {len(created)}")
    for line in created: print(f"    + {line}")
    print(f"  skipped (same value, already in NIOS): {len(skipped_same)}")
    for line in skipped_same: print(f"    = {line}")
    if conflicts:
        print(f"  CONFLICTS (NOT touched): {len(conflicts)}")
        for line in conflicts: print(f"    ! {line}")
    if skipped_type:
        print(f"  skipped (unsupported type): {len(skipped_type)}")
        for line in skipped_type: print(f"    ~ {line}")
    if skipped_apex_ns:
        print(f"  skipped (apex/ns): {len(skipped_apex_ns)}")
        for line in skipped_apex_ns: print(f"    ~ {line}")

    gelf(f"cf-to-nios sync: {len(created)} created, {len(conflicts)} conflicts",
         created=len(created), skipped_same=len(skipped_same),
         conflicts=len(conflicts), skipped_unsupported=len(skipped_type),
         dry_run=str(DRY_RUN).lower())

    return 0 if not conflicts else 1


if __name__ == "__main__":
    sys.exit(main())
