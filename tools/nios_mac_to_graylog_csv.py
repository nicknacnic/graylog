#!/usr/bin/env python3
"""Export Infoblox NIOS DHCP MAC→hostname mappings as a Graylog CSV lookup.

Pulls two NIOS WAPI sources and merges them by MAC:

  - record:fixedaddress  — static DHCP reservations (mac, ipv4addr, name)
  - lease (binding_state=ACTIVE) — current dynamic leases (hardware, client_hostname,
                                    address)

Fixed-address `name` is preferred when present; otherwise lease `client_hostname`.
The resulting CSV is `mac,hostname` ready for a Graylog CSV file data adapter
to drive MAC enrichment in pipeline rules.

Sister script to /usr/local/sbin/nios_ptr_to_graylog_csv.py — same env vars
(NIOS_HOST/USER/PASS/...) but with its own OUT_PATH and additional MAC-source
tuning.
"""

from __future__ import annotations

import csv
import ipaddress
import os
import sys

import requests
import urllib3
from requests.auth import HTTPBasicAuth


# Comma-separated list of NIOS hosts, tried in order. NIOS_HOSTS takes
# precedence; NIOS_HOST is read as a fallback for compatibility with the
# existing PTR-export env file.
NIOS_HOSTS_RAW = os.environ.get("NIOS_HOSTS") or os.environ.get("NIOS_HOST", "")
NIOS_HOSTS = [h.strip() for h in NIOS_HOSTS_RAW.split(",") if h.strip()]
NIOS_USER = os.environ.get("NIOS_USER", "").strip()
NIOS_PASS = os.environ.get("NIOS_PASS", "").strip()
WAPI_VER = os.environ.get("NIOS_WAPI_VER", "v2.13").strip()
VERIFY_TLS = os.environ.get("NIOS_VERIFY_TLS", "true").lower() in ("1", "true", "yes")

DOMAIN_SUFFIX = os.environ.get("DOMAIN_SUFFIX", "darknetian.com").strip().lower().rstrip(".")
SUBNET_CIDR = os.environ.get("SUBNET_CIDR", "10.10.0.0/24").strip()

OUT_PATH = os.environ.get(
    "MAC_OUT_PATH",
    os.environ.get("OUT_PATH", "/etc/graylog/server/lookups/mac_to_hostname.csv"),
).strip()

PAGE_SIZE = int(os.environ.get("PAGE_SIZE", "5000").strip())
TIMEOUT_S = int(os.environ.get("TIMEOUT_S", "60").strip())

# Skip lease entries whose hostname is junk. Aruba sets default hostnames like
# "*", "android-...", "iPhone" — keep those, but filter blank/known-bogus.
HOSTNAME_BLACKLIST = {"", "unknown", "*", "-"}


def die(msg: str, code: int = 1) -> None:
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(code)


def norm_mac(mac: str) -> str:
    """Lowercase, colon-separated. Pipeline rules also normalize before lookup."""
    m = (mac or "").strip().lower()
    # NIOS sometimes returns dashes; convert to colons
    m = m.replace("-", ":")
    return m


def norm_hostname(h: str) -> str:
    h = (h or "").strip().rstrip(".").lower()
    return h


def in_subnet(ip_str: str, subnet: ipaddress.IPv4Network) -> bool:
    try:
        return ipaddress.IPv4Address(ip_str) in subnet
    except Exception:
        return False


def extract_paged_result(resp_json):
    if isinstance(resp_json, dict) and "result" in resp_json:
        return resp_json.get("result") or [], resp_json.get("next_page_id")
    if isinstance(resp_json, list):
        return resp_json, None
    return None, None


def wapi_list(session: requests.Session, base_url: str, obj_type: str,
              return_fields: str, extra_params: dict | None = None) -> list[dict]:
    url = f"{base_url}/{obj_type}"
    params = {
        "_return_fields": return_fields,
        "_paging": "1",
        "_return_as_object": "1",
        "_max_results": str(PAGE_SIZE),
    }
    if extra_params:
        params.update(extra_params)

    all_objs: list[dict] = []
    page_id = None
    while True:
        p = dict(params)
        if page_id:
            p["_page_id"] = page_id
        resp = session.get(url, params=p, timeout=TIMEOUT_S)
        if resp.status_code >= 400:
            print(f"WAPI error {resp.status_code} for {resp.url}", file=sys.stderr)
            print(resp.text, file=sys.stderr)
            resp.raise_for_status()
        result, next_id = extract_paged_result(resp.json())
        if result is None:
            die(f"Unexpected WAPI response shape from {obj_type}")
        all_objs.extend(result)
        if not next_id:
            break
        page_id = next_id
    return all_objs


def main() -> None:
    if not (NIOS_HOSTS and NIOS_USER and NIOS_PASS):
        die("Set env vars: NIOS_HOSTS (or NIOS_HOST), NIOS_USER, NIOS_PASS")
    try:
        subnet = ipaddress.ip_network(SUBNET_CIDR, strict=False)
    except Exception as e:
        die(f"Invalid SUBNET_CIDR '{SUBNET_CIDR}': {e}")

    sess = requests.Session()
    sess.auth = HTTPBasicAuth(NIOS_USER, NIOS_PASS)
    sess.verify = VERIFY_TLS
    sess.headers.update({"Accept": "application/json"})
    if not VERIFY_TLS:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # Try each NIOS host in order. NB on this NIOS WAPI:
    #   - `fixedaddress` is the bare object name (no `record:` prefix —
    #     `record:fixedaddress` is rejected as Unknown object type).
    #   - `binding_state` is not a server-side searchable field; filter
    #     client-side after pulling all lease records.
    fixedaddrs = leases = None
    used_host = None
    for host in NIOS_HOSTS:
        base = f"https://{host}/wapi/{WAPI_VER}"
        try:
            fixedaddrs = wapi_list(
                sess, base, "fixedaddress",
                return_fields="mac,ipv4addr,name",
            )
            leases = wapi_list(
                sess, base, "lease",
                return_fields="hardware,client_hostname,address,binding_state",
            )
            used_host = host
            break
        except (requests.ConnectionError, requests.Timeout) as e:
            print(f"  NIOS host {host} unreachable: {e}", file=sys.stderr)
            continue
    if fixedaddrs is None or leases is None:
        die(f"None of NIOS hosts reachable: {NIOS_HOSTS}")
    # Client-side filter: only keep ACTIVE leases (binding_state isn't searchable)
    leases = [ls for ls in leases if (ls.get("binding_state") or "").upper() == "ACTIVE"]
    print(f"  WAPI source: {used_host}")

    # Merge: prefer fixedaddress.name; fall back to lease.client_hostname.
    # Also fall back to the lease's IP-based PTR (if we had it; not loaded here).
    mac_to_name: dict[str, str] = {}

    for fa in fixedaddrs:
        mac = norm_mac(fa.get("mac"))
        ip = (fa.get("ipv4addr") or "").strip()
        name = norm_hostname(fa.get("name"))
        if not mac or not in_subnet(ip, subnet):
            continue
        if name and name not in HOSTNAME_BLACKLIST:
            mac_to_name[mac] = name

    for ls in leases:
        mac = norm_mac(ls.get("hardware"))
        ip = (ls.get("address") or "").strip()
        host = norm_hostname(ls.get("client_hostname"))
        if not mac or not in_subnet(ip, subnet):
            continue
        if mac in mac_to_name:
            # fixedaddress.name already won — keep it
            continue
        if host and host not in HOSTNAME_BLACKLIST:
            mac_to_name[mac] = host

    if not mac_to_name:
        die(
            "No MAC→hostname mappings produced.\n"
            f"  fixedaddrs={len(fixedaddrs)} leases={len(leases)}\n"
            f"  SUBNET_CIDR={SUBNET_CIDR}\n"
            "  Check that NIOS has DHCP entries in this subnet."
        )

    tmp_path = OUT_PATH + ".tmp"
    os.makedirs(os.path.dirname(OUT_PATH), exist_ok=True)
    with open(tmp_path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["mac", "hostname"])
        for mac, host in sorted(mac_to_name.items()):
            w.writerow([mac, host])
    os.replace(tmp_path, OUT_PATH)
    print(f"Wrote {len(mac_to_name)} MAC mappings to {OUT_PATH} "
          f"(fixedaddrs={len(fixedaddrs)}, leases={len(leases)}, source={used_host})")


if __name__ == "__main__":
    main()
