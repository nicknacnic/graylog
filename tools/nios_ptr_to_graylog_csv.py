#!/usr/bin/env python3
"""Export NIOS IP→FQDN mappings to the Graylog CSV lookup file.

History: originally pulled only `record:ptr`. That misses DHCP-managed
hosts (where the PTR is auto-generated from `record:host` and may not
appear as a standalone PTR object via the WAPI), so 10.10.0.220 (HA)
and similar showed "unknown" on every dashboard.

Now pulls (in precedence order):

  1. record:host    name + ipv4addrs[].ipv4addr — DHCP-managed entries
                    (HA, Roomba, MBP, vSphere, idrac, etc.).
  2. record:ptr     ipv4addr + ptrdname — explicit PTRs (rare in this
                    grid).
  3. record:a       name + ipv4addr — static A records.

First-seen wins (host > ptr > a) so DHCP host records authoritatively
label dynamic IPs over any stale A record on the same address.

Env: NIOS_HOST, NIOS_USER, NIOS_PASS, NIOS_WAPI_VER, NIOS_VERIFY_TLS,
DNS_VIEW, DOMAIN_SUFFIX, SUBNET_CIDR, OUT_PATH, PAGE_SIZE, TIMEOUT_S.
"""

import csv
import ipaddress
import os
import sys

import requests
import urllib3
from requests.auth import HTTPBasicAuth


NIOS_HOST = os.environ.get("NIOS_HOST", "").strip()
NIOS_USER = os.environ.get("NIOS_USER", "").strip()
NIOS_PASS = os.environ.get("NIOS_PASS", "").strip()
WAPI_VER  = os.environ.get("NIOS_WAPI_VER", "v2.13").strip()
VERIFY_TLS = os.environ.get("NIOS_VERIFY_TLS", "true").lower() in ("1", "true", "yes")

DNS_VIEW = os.environ.get("DNS_VIEW", "default").strip()
DOMAIN_SUFFIX = os.environ.get("DOMAIN_SUFFIX", "darknetian.com").strip().lower().rstrip(".")
SUBNET_CIDR = os.environ.get("SUBNET_CIDR", "10.10.0.0/24").strip()

OUT_PATH = os.environ.get("OUT_PATH", "/etc/graylog/server/lookups/ip_to_ptr.csv").strip()
PAGE_SIZE = int(os.environ.get("PAGE_SIZE", "5000").strip())
TIMEOUT_S = int(os.environ.get("TIMEOUT_S", "60").strip())


def die(msg: str, code: int = 1) -> None:
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(code)


def norm_fqdn(name: str) -> str:
    return (name or "").strip().rstrip(".").lower()


def in_subnet(ip_str: str, subnet) -> bool:
    try:
        return ipaddress.IPv4Address(ip_str) in subnet
    except Exception:
        return False


def wapi_list(session, base_url: str, obj_type: str, return_fields: str,
              try_view_filter: bool = True) -> list[dict]:
    """Paged WAPI list with `_return_as_object=1`. Retries without
    view filter once if the server rejects it (some object types don't
    accept the view query param)."""
    url = f"{base_url}/{obj_type}"
    params = {
        "_return_fields": return_fields,
        "_paging": "1",
        "_return_as_object": "1",
        "_max_results": str(PAGE_SIZE),
    }
    if try_view_filter and DNS_VIEW:
        params["view"] = DNS_VIEW

    out: list[dict] = []
    page_id = None
    retried_without_view = False
    while True:
        p = dict(params)
        if page_id:
            p["_page_id"] = page_id
        r = session.get(url, params=p, timeout=TIMEOUT_S)
        if r.status_code == 400 and not retried_without_view and "view" in p:
            retried_without_view = True
            params.pop("view", None)
            continue
        if r.status_code >= 400:
            print(f"WAPI {obj_type} error {r.status_code}: {r.text[:300]}",
                  file=sys.stderr)
            r.raise_for_status()
        data = r.json()
        if isinstance(data, dict) and "result" in data:
            out.extend(data.get("result") or [])
            page_id = data.get("next_page_id")
        elif isinstance(data, list):
            out.extend(data)
            page_id = None
        else:
            die(f"unexpected WAPI response shape for {obj_type}: {type(data)}")
        if not page_id:
            break
    return out


def collect_pairs(session, base_url: str, subnet) -> list[tuple[str, str, str]]:
    """Returns list of (ip, fqdn, source_record_type) tuples."""
    pairs: list[tuple[str, str, str]] = []

    # 1) record:host — extract every ipv4addrs[].ipv4addr with the host name.
    hosts = wapi_list(session, base_url, "record:host", "name,ipv4addrs,view")
    for h in hosts:
        view = (h.get("view") or "").strip()
        if DNS_VIEW and view and view != DNS_VIEW:
            continue
        fqdn = norm_fqdn(h.get("name") or "")
        if not fqdn or not fqdn.endswith(DOMAIN_SUFFIX):
            continue
        for addr in (h.get("ipv4addrs") or []):
            ip = (addr.get("ipv4addr") or "").strip()
            if ip and in_subnet(ip, subnet):
                pairs.append((ip, fqdn, "host"))

    # 2) record:ptr — keep the explicit PTR set as second source.
    ptrs = wapi_list(session, base_url, "record:ptr", "ipv4addr,ptrdname,view")
    for o in ptrs:
        view = (o.get("view") or "").strip()
        if DNS_VIEW and view and view != DNS_VIEW:
            continue
        ip = (o.get("ipv4addr") or "").strip()
        fqdn = norm_fqdn(o.get("ptrdname") or "")
        if not ip or not fqdn or not fqdn.endswith(DOMAIN_SUFFIX):
            continue
        if not in_subnet(ip, subnet):
            continue
        pairs.append((ip, fqdn, "ptr"))

    # 3) record:a — static A records.
    a_recs = wapi_list(session, base_url, "record:a", "name,ipv4addr,view")
    for r in a_recs:
        view = (r.get("view") or "").strip()
        if DNS_VIEW and view and view != DNS_VIEW:
            continue
        ip = (r.get("ipv4addr") or "").strip()
        fqdn = norm_fqdn(r.get("name") or "")
        if not ip or not fqdn or not fqdn.endswith(DOMAIN_SUFFIX):
            continue
        if not in_subnet(ip, subnet):
            continue
        pairs.append((ip, fqdn, "a"))

    return pairs


def main() -> None:
    if not (NIOS_HOST and NIOS_USER and NIOS_PASS):
        die("Set env vars: NIOS_HOST, NIOS_USER, NIOS_PASS")

    try:
        subnet = ipaddress.ip_network(SUBNET_CIDR, strict=False)
    except Exception as e:
        die(f"Invalid SUBNET_CIDR '{SUBNET_CIDR}': {e}")

    base = f"https://{NIOS_HOST}/wapi/{WAPI_VER}"

    sess = requests.Session()
    sess.auth = HTTPBasicAuth(NIOS_USER, NIOS_PASS)
    sess.verify = VERIFY_TLS
    sess.headers.update({"Accept": "application/json"})
    if not VERIFY_TLS:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    pairs = collect_pairs(sess, base, subnet)
    if not pairs:
        die("No host/ptr/a records matched filters — check subnet/view/domain.")

    # Precedence: host > ptr > a (host records authoritatively label
    # DHCP-leased IPs over any stale A record on the same address).
    order = {"host": 0, "ptr": 1, "a": 2}
    pairs.sort(key=lambda t: (t[0], order.get(t[2], 9)))
    dedup: dict[str, str] = {}
    src_counts = {"host": 0, "ptr": 0, "a": 0}
    for ip, fqdn, src in pairs:
        if ip not in dedup:
            dedup[ip] = fqdn
            src_counts[src] += 1

    os.makedirs(os.path.dirname(OUT_PATH), exist_ok=True)
    tmp = OUT_PATH + ".tmp"
    with open(tmp, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["ip", "fqdn"])
        for ip in sorted(dedup, key=lambda x: ipaddress.IPv4Address(x)):
            w.writerow([ip, dedup[ip]])
    os.replace(tmp, OUT_PATH)
    print(f"Wrote {len(dedup)} IP→fqdn mappings to {OUT_PATH} "
          f"(host={src_counts['host']} ptr={src_counts['ptr']} a={src_counts['a']})")


if __name__ == "__main__":
    main()
