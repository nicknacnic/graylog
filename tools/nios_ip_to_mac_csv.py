#!/usr/bin/env python3
"""Export NIOS IP→MAC mappings to a Graylog CSV lookup file.

Used by the MAC Enrichment pipeline to derive client_mac from a known
client_ip (e.g. dnstap events that carry dns_client_ip but no MAC).
Once client_mac is set, the existing `mac enrich client_mac` rule looks
up the DHCP hostname via infoblox-nios-mac.

Pull sources (in precedence order, first-seen wins per IP):

  1. record:host with ipv4addrs[].mac — DHCP-managed hosts that have
     a configured MAC (HA, vSphere, idrac, Roomba, ...).
  2. record:fixedaddress — static IP/MAC pairs (some grid-managed
     reservations live here instead of as record:host).

Env: NIOS_HOST, NIOS_USER, NIOS_PASS, NIOS_WAPI_VER, NIOS_VERIFY_TLS,
DNS_VIEW, DOMAIN_SUFFIX (unused — IP-side filter only), SUBNET_CIDR,
OUT_PATH (default /etc/graylog/server/lookups/ip_to_mac.csv),
PAGE_SIZE, TIMEOUT_S.
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
SUBNET_CIDR = os.environ.get("SUBNET_CIDR", "10.10.0.0/24").strip()

OUT_PATH = os.environ.get(
    "IP_TO_MAC_OUT_PATH",
    "/etc/graylog/server/lookups/ip_to_mac.csv",
).strip()
PAGE_SIZE = int(os.environ.get("PAGE_SIZE", "5000").strip())
TIMEOUT_S = int(os.environ.get("TIMEOUT_S", "60").strip())


def die(msg: str, code: int = 1) -> None:
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(code)


def norm_mac(m: str) -> str:
    """Lowercase, colon-separated. Empty string if invalid."""
    m = (m or "").strip().lower()
    if not m:
        return ""
    # Accept aa:bb:cc:dd:ee:ff or aa-bb-... or aabbccddeeff
    hex_only = "".join(c for c in m if c in "0123456789abcdef")
    if len(hex_only) != 12:
        return ""
    return ":".join(hex_only[i:i+2] for i in range(0, 12, 2))


def in_subnet(ip_str: str, subnet) -> bool:
    try:
        return ipaddress.IPv4Address(ip_str) in subnet
    except Exception:
        return False


def wapi_list(session, base_url: str, obj_type: str, return_fields: str,
              try_view_filter: bool = True) -> list[dict]:
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
    pairs: list[tuple[str, str, str]] = []

    # 1) record:host — DHCP-managed hosts with MAC.
    hosts = wapi_list(session, base_url, "record:host", "ipv4addrs")
    for h in hosts:
        for addr in (h.get("ipv4addrs") or []):
            ip = (addr.get("ipv4addr") or "").strip()
            mac = norm_mac(addr.get("mac"))
            if ip and mac and in_subnet(ip, subnet):
                pairs.append((ip, mac, "host"))

    # 2) record:fixedaddress — reservations (no view filter; that param
    # is rejected by some grids for fixedaddress).
    fixed = wapi_list(session, base_url, "fixedaddress",
                      "ipv4addr,mac", try_view_filter=False)
    for f in fixed:
        ip = (f.get("ipv4addr") or "").strip()
        mac = norm_mac(f.get("mac"))
        if ip and mac and in_subnet(ip, subnet):
            pairs.append((ip, mac, "fixedaddress"))

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
        die("No IP→MAC pairs matched filters — check subnet/view.")

    # host > fixedaddress on duplicate IPs.
    order = {"host": 0, "fixedaddress": 1}
    pairs.sort(key=lambda t: (t[0], order.get(t[2], 9)))
    dedup: dict[str, str] = {}
    src_counts = {"host": 0, "fixedaddress": 0}
    for ip, mac, src in pairs:
        if ip not in dedup:
            dedup[ip] = mac
            src_counts[src] = src_counts.get(src, 0) + 1

    os.makedirs(os.path.dirname(OUT_PATH), exist_ok=True)
    tmp = OUT_PATH + ".tmp"
    with open(tmp, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["ip", "mac"])
        for ip in sorted(dedup, key=lambda x: ipaddress.IPv4Address(x)):
            w.writerow([ip, dedup[ip]])
    os.replace(tmp, OUT_PATH)
    print(f"Wrote {len(dedup)} IP→MAC mappings to {OUT_PATH} "
          f"(host={src_counts.get('host',0)} fixed={src_counts.get('fixedaddress',0)})")


if __name__ == "__main__":
    main()
