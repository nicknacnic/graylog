#!/usr/bin/env python3
"""One-command rebuild of the homelab Graylog from this repo.

Runs every script in the right order:

  1. Index sets        — create dedicated index sets per source so each
                         can be retained / sharded independently and so
                         high-cardinality sources don't push the default
                         index past OpenSearch's 1000-field cap.
  2. Streams           — created or repointed to the new index sets.
  3. Inputs            — GELF HTTP input for the iLO poller; Raw UDP
                         input for Aruba (latent fallback).
  4. Lookups           — MAC → DHCP hostname lookup chain.
  5. Pipelines + rules — extraction for Cradlepoint, Aruba, VMware
                         (vmware_app); MAC normalization + enrichment;
                         destination_fqdn splice into user's Enrichment.
  6. Dashboards        — per-platform multi-page dashboards.

Idempotent. Re-running on a healthy instance is a no-op for index sets,
streams, inputs, lookups, and pipelines (everything is PUT-if-exists).
Dashboards delete the prior view with the same title and recreate (the
only way to keep widget layouts under code control until Graylog has a
real PUT /views).

Requires GRAYLOG_URL and GRAYLOG_TOKEN in the environment.

Usage:
    source env.sh && python3 apply_all.py
    python3 apply_all.py --dry-run        # print steps but don't run
    python3 apply_all.py --only=dashboards   # subset
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def step(group: str, desc: str, cmd: list[str]) -> tuple[str, str, list[str]]:
    return (group, desc, cmd)


STEPS = [
    # ── 1. Index sets ──────────────────────────────────────────────────────
    step("indexing", "iLO Redfish index set + Redfish stream + default-index rotation",
         ["python3", "indexing/ilo_redfish.py"]),
    step("indexing", "iDRAC Redfish index set + Redfish stream",
         ["python3", "indexing/idrac_redfish.py"]),
    step("indexing", "VMware index set + repoint ESXi stream",
         ["python3", "indexing/vmware.py"]),
    step("indexing", "Palo Alto Networks index set + repoint both PANOS streams",
         ["python3", "indexing/panos.py"]),
    step("indexing", "Infoblox UDDI index set + repoint UDDI/PAN-MGT streams",
         ["python3", "indexing/uddi.py"]),
    step("indexing", "Infoblox NIOS index set + repoint all 5 NIOS streams",
         ["python3", "indexing/nios.py"]),
    step("indexing", "Split NIOS per-host streams by service (NIOS DNS auth + NIOS DHCP)",
         ["python3", "indexing/nios_split.py"]),
    step("indexing", "Aruba index set + native AP syslog stream",
         ["python3", "indexing/aruba.py"]),
    step("indexing", "NAS stream (default index — syslog from 10.10.0.50)",
         ["python3", "indexing/nas.py"]),
    step("indexing", "Cloudflare index set + stream",
         ["python3", "indexing/cloudflare.py"]),
    step("indexing", "Infoblox CSP (CubeJS / IQ metrics) index set + stream",
         ["python3", "indexing/csp.py"]),
    step("indexing", "NIOS dnstap index set + stream (per-query GELF via dnscollector bridge)",
         ["python3", "indexing/nios_dnstap.py"]),

    # ── 2. Inputs ──────────────────────────────────────────────────────────
    step("inputs", "GELF HTTP input on 127.0.0.1:12202 (for iLO poller)",
         ["python3", "pollers/setup_input.py"]),
    step("inputs", "Raw UDP input on 0.0.0.0:5514 (Aruba latent fallback)",
         ["python3", "pollers/setup_aruba_input.py"]),

    # ── 3. Lookups ─────────────────────────────────────────────────────────
    step("lookups", "MAC → DHCP hostname adapter + cache + table",
         ["python3", "lookups/mac_to_hostname.py"]),

    # ── 4. Pipelines + rules ───────────────────────────────────────────────
    step("pipelines", "Cradlepoint extraction rules + pipeline",
         ["python3", "pipelines/apply.py", "pipelines/cradlepoint.json"]),
    step("pipelines", "UDDI CEF normalize rule + pipeline (restores dns_event_type/rcode/qname/dns_is_nxdomain on UDDI)",
         ["python3", "pipelines/apply.py", "pipelines/uddi.json"]),
    step("pipelines", "NIOS Grid (GM admin event + NI module/summary extraction)",
         ["python3", "pipelines/apply.py", "pipelines/nios_grid.json"]),
    step("pipelines", "NIOS DNS Role (auth vs forward tagging on darknetian.com)",
         ["python3", "pipelines/apply.py", "pipelines/nios_dns_role.json"]),
    step("pipelines", "Synology DSM (nas_category + connection + AFP) + connect to NAS streams",
         ["python3", "pipelines/apply.py", "pipelines/synology.json",
          "--connect=NAS", "--connect=NAS (IP-form)"]),
    step("pipelines", "Aruba extraction rules + pipeline",
         ["python3", "pipelines/apply.py", "pipelines/aruba.json"]),
    step("pipelines", "VMware vmware_app extraction rules + ESXI pipeline",
         ["python3", "pipelines/apply.py", "pipelines/vmware.json"]),
    step("pipelines", "MAC enrichment pipeline (cp_/aruba_mac → client_mac → DHCP host)",
         ["python3", "pipelines/apply.py", "pipelines/mac_enrichment.json"]),
    step("pipelines", "Splice destination_fqdn rule into Enrichment pipeline",
         ["python3", "pipelines/extend_enrichment_destination.py"]),
    step("pipelines", "Splice dfp_qip normalize rule + wire CSP stream to Enrichment",
         ["python3", "pipelines/extend_enrichment_csp.py"]),
    step("pipelines", "Splice dns_client_ip normalize rule + wire NIOS dnstap stream to Enrichment",
         ["python3", "pipelines/extend_enrichment_dnstap.py"]),

    # ── 5. Dashboards ──────────────────────────────────────────────────────
    step("dashboards", "Cradlepoint E300",
         ["python3", "dashboards/cradlepoint.py"]),
    step("dashboards", "HPE iLO — esxi2",
         ["python3", "dashboards/ilo.py"]),
    step("dashboards", "Dell iDRAC",
         ["python3", "dashboards/idrac.py"]),
    step("dashboards", "Cloudflare",
         ["python3", "dashboards/cloudflare.py"]),
    step("dashboards", "VMware — vCenter & ESXi",
         ["python3", "dashboards/vmware.py"]),
    step("dashboards", "Aruba — AP225",
         ["python3", "dashboards/aruba.py"]),
    step("dashboards", "Palo Alto Networks",
         ["python3", "dashboards/palo_alto.py"]),
    step("dashboards", "Infoblox — Operations",
         ["python3", "dashboards/infoblox_ops.py"]),
    step("dashboards", "Synology — DSM",
         ["python3", "dashboards/synology.py"]),
    step("dashboards", "Home Assistant — logs",
         ["python3", "dashboards/ha_logs.py"]),
]


def check_env() -> None:
    missing = [k for k in ("GRAYLOG_URL", "GRAYLOG_TOKEN") if not os.environ.get(k)]
    if missing:
        print(f"ERROR: required env vars not set: {', '.join(missing)}", file=sys.stderr)
        print("  Run `source env.sh` first.", file=sys.stderr)
        sys.exit(2)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--dry-run", action="store_true", help="print steps without running")
    p.add_argument("--only", metavar="GROUP",
                   help="run only one group (indexing|inputs|lookups|pipelines|dashboards)")
    p.add_argument("--continue-on-error", action="store_true",
                   help="don't stop at the first failure")
    args = p.parse_args()

    if not args.dry_run:
        check_env()

    selected = [s for s in STEPS if not args.only or s[0] == args.only]
    if not selected:
        print(f"no steps match --only={args.only!r}", file=sys.stderr)
        return 2

    failures: list[str] = []
    started = time.time()
    cur_group = None
    for group, desc, cmd in selected:
        if group != cur_group:
            print(f"\n## {group} ##")
            cur_group = group
        print(f"  → {desc}")
        if args.dry_run:
            print(f"     {' '.join(cmd)}")
            continue
        t0 = time.time()
        r = subprocess.run(cmd, cwd=ROOT)
        dt = time.time() - t0
        if r.returncode != 0:
            print(f"     FAILED in {dt:.1f}s (exit {r.returncode})", file=sys.stderr)
            failures.append(desc)
            if not args.continue_on_error:
                print(f"\nstopped after first failure. Re-run with --continue-on-error to see all.",
                      file=sys.stderr)
                return r.returncode
        else:
            print(f"     ok ({dt:.1f}s)")

    elapsed = time.time() - started
    print()
    if failures:
        print(f"DONE with {len(failures)} failure(s) in {elapsed:.1f}s:")
        for f in failures:
            print(f"  - {f}")
        return 1
    print(f"DONE — {len(selected)} step(s) in {elapsed:.1f}s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
