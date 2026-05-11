# graylog homelab

Version-controlled pipeline rules, dashboards, and source-pollers for the
darknetian Graylog instance.

## Setup

```sh
cp env.sh.example env.sh   # edit with your Graylog token + URL
source env.sh
```

Requires Python 3.10+ (stdlib only — no `pip install` needed).

## Layout

```
pipelines/
  cradlepoint.json         declarative spec (rules + pipeline-stage wiring)
  apply.py                 idempotent applier (POST new rules, PUT existing)

dashboards/
  cradlepoint.py           single-page widget spec + build()
  ilo.py                   multi-page (Operational / Inventory / Trends) build
  idrac.py                 multi-page (Operational / Inventory / Trends) — Dell mirror of ilo.py
  vmware.py                multi-page (Operational / Hosts / vCenter / Inventory)

indexing/
  ilo_redfish.py           creates dedicated 'iLO Redfish' index set + stream
                           and rotates the default index.
  idrac_redfish.py         creates 'iDRAC Redfish' index set + stream
                           (mirrors iLO setup for the Dell iDRAC poller).
  vmware.py                creates 'VMware' index set and repoints the existing
                           ESXi stream to it (2.2M msgs/day firehose offload).
  panos.py                 'Palo Alto Networks' index set + both PANOS streams.
  uddi.py                  'Infoblox UDDI' index set + UDDI/Aruba/PAN-MGT streams.
  nios.py                  'Infoblox NIOS' index set + all five NIOS streams.
  aruba.py                 'Aruba' index set + new 'Aruba AP' stream (native syslog
                           from the AP), plus rename of the existing UDDI-DNS-cut stream.

pollers/
  ilo_redfish.py           HPE iLO Redfish → GELF HTTP poller (snapshot + logs)
  idrac_redfish.py         Dell iDRAC Redfish → GELF HTTP poller (snapshot + Lclog/Sel)
  setup_input.py           creates the GELF HTTP input on Graylog (one-time)

tools/
  nios_mac_to_graylog_csv.py    Infoblox NIOS (fixedaddrs+leases) → CSV of mac,hostname
                                 (mirrors the user's existing nios_ptr_to_graylog_csv.py)

lookups/
  mac_to_hostname.py            creates the Graylog data-adapter+cache+lookup-table chain
                                 named `infoblox-nios-mac` over the CSV above

pipelines/
  mac_enrichment.json           'MAC Enrichment' pipeline: normalizes
                                 cp_new_client_mac / aruba_client_mac into
                                 client_mac, then lookup_value() → client_hostname.
                                 Connected to Cradlepoint + Aruba AP streams.

systemd/
  ilo-poller-{health,logs}.{service,timer}
  idrac-poller-{health,logs}.{service,timer}
  install.sh               installs both Redfish pollers (iLO + iDRAC) to
                           /opt + /etc on the Graylog VM, with separate
                           env files and dedicated system users per poller.
  nios-mac-export.{service,timer}
                           hourly Infoblox MAC export, lives at
                           /usr/local/sbin/nios_mac_to_graylog_csv.py on the VM.
                           Shares /etc/graylog/nios-export.env with the user's
                           existing PTR exporter; adds NIOS_HOSTS for failover
                           between Grid Master + secondary nodes.

lib/
  graylog.py               stdlib HTTP client + widget/search/view JSON builders
                           (single-page and multi-page view builders)
```

## Apply

### One-shot rebuild

```sh
source env.sh
python3 apply_all.py                 # everything, in the right order
python3 apply_all.py --dry-run       # print what would run, don't execute
python3 apply_all.py --only=indexing # just one group
python3 apply_all.py --only=dashboards
python3 apply_all.py --continue-on-error
```

Idempotent. Anything that already exists is updated in place; nothing is
deleted except dashboards (which are delete-then-recreate by title, the
only way to keep widget layouts under code control until Graylog ships a
real `PUT /views`).

The order matters and `apply_all.py` enforces it:

1. **Index sets** — created first so streams can be repointed.
2. **Streams** — created or repointed (some scripts do both atomically).
3. **Inputs** — GELF HTTP + Raw UDP so data has somewhere to land.
4. **Lookups** — `infoblox-nios-mac` data-adapter chain (needs to exist
   before pipeline rules can reference it).
5. **Pipelines + rules** — Cradlepoint, Aruba, VMware, MAC Enrichment,
   plus the `destination_fqdn` splice into the user-managed `Enrichment`
   pipeline.
6. **Dashboards** — last, because they reference everything above.

### Individual scripts

```sh
source env.sh
python3 pipelines/apply.py pipelines/cradlepoint.json
python3 dashboards/cradlepoint.py
```

Re-running each is idempotent (rules: PUT-if-exists; dashboards: delete-prior-then-recreate).

## iLO Redfish poller

The poller is one Python file with two modes. Health snapshot runs every 60s
(power/thermal/fans/drives/system status), log tail runs every 5min (IEL
log entries on iLO 4, deduped via a state file).

**Bootstrap (once):**

```sh
source env.sh
python3 pollers/setup_input.py        # creates the GELF HTTP input on 127.0.0.1:12202
python3 indexing/ilo_redfish.py       # creates dedicated index set + stream, rotates default
python3 dashboards/ilo.py             # builds the 3-page dashboard
```

**Deploy to the Graylog VM:**

```sh
# from your workstation
scp -r . graylog-vm:/tmp/graylog-repo
ssh graylog-vm 'sudo bash /tmp/graylog-repo/systemd/install.sh'
# then on the VM, edit /etc/ilo-poller/env to fill in ILO_USER / ILO_PASS
ssh graylog-vm 'sudo nano /etc/ilo-poller/env'
ssh graylog-vm 'sudo systemctl restart ilo-poller-health.timer ilo-poller-logs.timer'
```

**One-off test (from your workstation against an iLO you can reach):**

```sh
export ILO_HOST=ilo-esxi2.darknetian.com
export ILO_USER=...
export ILO_PASS=...
export GELF_URL=http://localhost:12202/gelf      # SSH-tunnel: ssh -L 12202:127.0.0.1:12202 graylog-vm
python3 pollers/ilo_redfish.py health
```

## Conventions

- Field-name prefix per source: `cp_*` for Cradlepoint, `ilo_*` for iLO,
  `aruba_*` for Aruba, `vmware_*` for VMware. Lets widgets filter cleanly
  across the default stream.
- Each rule sets a categorical `<prefix>_event_type` so dashboards slice
  without re-matching text in `message`.
- Stream routing on the iLO side relies on Graylog mapping GELF `host`
  field → `source` field, and the existing iLO stream already filters on
  `source = ilo-esxi2.darknetian.com`.

### DDI-normalized identifier fields (use these on dashboards)

The Enrichment + MAC-Enrichment pipelines produce a small, unified set of
identifier fields. Dashboards should reach for the most readable variant
when displaying a client / sender:

| Field | Source | Meaning |
|---|---|---|
| `client_hostname` | MAC Enrichment pipeline → `infoblox-nios-mac` lookup | DHCP-assigned hostname for the unified `client_mac` |
| `client_fqdn` | Enrichment pipeline → `infoblox-nios-ptr` lookup | Reverse-DNS name for `client_ip` |
| `client_mac` | MAC Enrichment normalize rules | Unified MAC, coalesced from `cp_new_client_mac`, `aruba_client_mac`, ... |
| `client_ip` | Enrichment normalize rules | Unified IP, coalesced from `deviceAddress`, `source_ip`, ... |
| `sender_fqdn` | Enrichment pipeline → `infoblox-nios-ptr` lookup | Reverse-DNS name for the message-sender IP |
| `destination_fqdn` | Enrichment pipeline (stage 2 add-in) → `infoblox-nios-ptr` lookup | Reverse-DNS name for `destination_ip`. Covers internal LAN destinations; external IPs return 'unknown'. Defined in `pipelines/destination_fqdn_enrich.json`. |

Order of preference when picking a display value:
**`client_hostname` → `client_fqdn` → `client_mac` → `client_ip`** (or
`sender_fqdn` for sender-side context).
