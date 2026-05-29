#!/usr/bin/env bash
# Install the homelab pollers on the Graylog Ubuntu VM.
# Run as root on the Graylog VM after copying this whole repo there.
#
#   sudo bash systemd/install.sh
#
# Then fill in the env files (each is gitignored; install.sh creates an
# empty template if missing):
#   /etc/ilo-poller/env       — ILO_HOST / ILO_USER / ILO_PASS
#   /etc/idrac-poller/env     — IDRAC_HOST / IDRAC_USER / IDRAC_PASS
#   /etc/cf-poller/env        — CF_API_TOKEN (scoped read-only token)

set -euo pipefail
cd "$(dirname "$0")/.."

install_poller() {
  # install_poller <slug> <env-prefix>
  #   slug         e.g. "ilo"   -> /opt/ilo-poller, /var/lib/ilo-poller, ilo-poller user
  #   env-prefix   e.g. "ILO"   -> ILO_HOST/ILO_USER/ILO_PASS/ILO_INSECURE
  local slug="$1"
  local prefix="$2"
  local user="${slug}-poller"
  local opt_dir="/opt/${slug}-poller"
  local etc_dir="/etc/${slug}-poller"
  local lib_dir="/var/lib/${slug}-poller"
  local src="pollers/${slug}_redfish.py"

  if [[ ! -f "$src" ]]; then
    echo "skip $slug (no $src in repo)"
    return
  fi

  # Account
  if ! id -u "$user" >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin "$user"
  fi

  # Code
  install -d -o root -g root -m 0755 "$opt_dir"
  install -m 0755 "$src" "$opt_dir/"

  # State
  install -d -o "$user" -g "$user" -m 0750 "$lib_dir"

  # Config
  install -d -o root -g "$user" -m 0750 "$etc_dir"
  if [[ ! -f "$etc_dir/env" ]]; then
    cat > "$etc_dir/env" <<EOF
# Fill in then \`systemctl restart ${slug}-poller-health.timer ${slug}-poller-logs.timer\`
${prefix}_HOST=
${prefix}_USER=
${prefix}_PASS=
GELF_URL=http://127.0.0.1:12202/gelf
${prefix}_INSECURE=1
EOF
    chmod 0640 "$etc_dir/env"
    chown root:"$user" "$etc_dir/env"
    echo "NOTE: edit $etc_dir/env to add ${prefix}_HOST/${prefix}_USER/${prefix}_PASS"
  fi

  # Units
  install -m 0644 "systemd/${slug}-poller-health.service" /etc/systemd/system/
  install -m 0644 "systemd/${slug}-poller-health.timer"   /etc/systemd/system/
  install -m 0644 "systemd/${slug}-poller-logs.service"   /etc/systemd/system/
  install -m 0644 "systemd/${slug}-poller-logs.timer"     /etc/systemd/system/
}

install_poller ilo   ILO
install_poller idrac IDRAC

# Cloudflare poller — different shape (single unit, not health+logs pair).
install_cf_poller() {
  local user=cf-poller
  local src=pollers/cloudflare_poller.py

  if [[ ! -f "$src" ]]; then
    echo "skip cf-poller (no $src in repo)"
    return
  fi
  if ! id -u "$user" >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin "$user"
  fi
  install -d -o root -g root -m 0755 /opt/cf-poller
  install -m 0755 "$src" /opt/cf-poller/
  install -d -o "$user" -g "$user" -m 0750 /var/lib/cf-poller
  install -d -o root -g "$user" -m 0750 /etc/cf-poller
  if [[ ! -f /etc/cf-poller/env ]]; then
    cat > /etc/cf-poller/env <<'EOF'
# Cloudflare API token (Zone Read + Analytics Read + Firewall Read +
# Account Audit Logs Read). Generate at
# https://dash.cloudflare.com/profile/api-tokens
CF_API_TOKEN=
GELF_URL=http://127.0.0.1:12202/gelf
# Optional CSV override; otherwise the poller auto-discovers all zones
# the token can see:
# CF_ZONES=darknetian.com,darknetian.net
EOF
    chmod 0640 /etc/cf-poller/env
    chown root:"$user" /etc/cf-poller/env
    echo "NOTE: edit /etc/cf-poller/env to add CF_API_TOKEN"
  fi
  install -m 0644 systemd/cf-poller.service /etc/systemd/system/
  install -m 0644 systemd/cf-poller.timer   /etc/systemd/system/
}

install_cf_poller

# CSP CubeJS / Infoblox IQ poller — single-unit shape like cf-poller.
install_csp_poller() {
  local user=csp-poller
  local src=pollers/csp_poller.py

  if [[ ! -f "$src" ]]; then
    echo "skip csp-poller (no $src in repo)"
    return
  fi
  if ! id -u "$user" >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin "$user"
  fi
  install -d -o root -g root -m 0755 /opt/csp-poller
  install -m 0755 "$src" /opt/csp-poller/
  install -d -o "$user" -g "$user" -m 0750 /var/lib/csp-poller
  install -d -o root -g "$user" -m 0750 /etc/csp-poller
  if [[ ! -f /etc/csp-poller/env ]]; then
    cat > /etc/csp-poller/env <<'EOF'
# Infoblox CSP read-scope API token (csp.infoblox.com).
# Get from https://csp.infoblox.com -> User Profile -> User API Keys.
INFOBLOX_API_KEY=
# Optional per-host scope. Empty = skip per-host metrics.
# For LAYER8-NIOSX the UUID is 0b788e8f925d96fdc8d0001de05800a1
CSP_HOST_UUID=
CSP_HOST_LABEL=NIOS-X
CSP_LOOKBACK_MIN=60
GELF_URL=http://127.0.0.1:12202/gelf
EOF
    chmod 0640 /etc/csp-poller/env
    chown root:"$user" /etc/csp-poller/env
    echo "NOTE: edit /etc/csp-poller/env to add INFOBLOX_API_KEY (and optionally CSP_HOST_UUID)"
  fi
  install -m 0644 systemd/csp-poller.service /etc/systemd/system/
  install -m 0644 systemd/csp-poller.timer   /etc/systemd/system/
}

install_csp_poller

# MCP poller — Portunus DNS logs (per-DFP query attribution) for the
# "Infoblox IQ - MCP" dashboard page. Same single-unit shape as cf-poller.
install_mcp_poller() {
  local user=mcp-poller
  local src=pollers/mcp_poller.py

  if [[ ! -f "$src" ]]; then
    echo "skip mcp-poller (no $src in repo)"
    return
  fi
  if ! id -u "$user" >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin "$user"
  fi
  install -d -o root -g root -m 0755 /opt/mcp-poller
  install -m 0755 "$src" /opt/mcp-poller/
  install -d -o "$user" -g "$user" -m 0750 /var/lib/mcp-poller
  install -d -o root -g "$user" -m 0750 /etc/mcp-poller
  if [[ ! -f /etc/mcp-poller/env ]]; then
    cat > /etc/mcp-poller/env <<'EOF'
# Infoblox CSP read-scope API key (same key the csp-poller uses).
INFOBLOX_API_KEY=
# DFP `network` value as it appears in PortunusDnsLogs. For the
# LAYER8 homelab NIOS-X this is exactly:
MCP_DFP_NETWORK=LAYER8 NIOS-X (DFP)
MCP_LOOKBACK_MIN=60
MCP_TOP_N=25
GELF_URL=http://127.0.0.1:12202/gelf
EOF
    chmod 0640 /etc/mcp-poller/env
    chown root:"$user" /etc/mcp-poller/env
    echo "NOTE: edit /etc/mcp-poller/env to add INFOBLOX_API_KEY"
  fi
  install -m 0644 systemd/mcp-poller.service /etc/systemd/system/
  install -m 0644 systemd/mcp-poller.timer   /etc/systemd/system/
}

install_mcp_poller

# HA core-log poller — pulls /api/hassio/core/logs from Home Assistant
# and ships WARNING+/ERROR/CRITICAL as GELF. Single-unit shape.
install_ha_log_poller() {
  local user=ha-log-poller
  local src=pollers/ha_log_poller.py

  if [[ ! -f "$src" ]]; then
    echo "skip ha-log-poller (no $src in repo)"
    return
  fi
  if ! id -u "$user" >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin "$user"
  fi
  install -d -o root -g root -m 0755 /opt/ha-log-poller
  install -m 0755 "$src" /opt/ha-log-poller/
  install -d -o "$user" -g "$user" -m 0750 /var/lib/ha-log-poller
  install -d -o root -g "$user" -m 0750 /etc/ha-log-poller
  if [[ ! -f /etc/ha-log-poller/env ]]; then
    cat > /etc/ha-log-poller/env <<'EOF'
# Home Assistant long-lived access token. Generate at:
#   HA -> Profile -> Long-lived access tokens
HA_URL=http://10.10.0.220:8123
HA_TOKEN=
# WARNING and above by default. Add INFO if you want it (chatty).
HA_LOG_LEVELS=WARNING,ERROR,CRITICAL
HA_HOST_LABEL=ha-darknetian
GELF_URL=http://127.0.0.1:12202/gelf
EOF
    chmod 0640 /etc/ha-log-poller/env
    chown root:"$user" /etc/ha-log-poller/env
    echo "NOTE: edit /etc/ha-log-poller/env to add HA_TOKEN"
  fi
  install -m 0644 systemd/ha-log-poller.service /etc/systemd/system/
  install -m 0644 systemd/ha-log-poller.timer   /etc/systemd/system/
}

install_ha_log_poller

# WAN performance probe — Ookla speedtest + canary pings + DNS timing
# + external-IP probe. Emits GELF with source=e300.darknetian.com so
# events land in the existing Cradlepoint stream and surface on the
# Cradlepoint dashboard's WAN Perf page.
install_wan_perf_poller() {
  local user=wan-perf-poller
  local src=pollers/wan_perf_poller.py

  if [[ ! -f "$src" ]]; then
    echo "skip wan-perf-poller (no $src in repo)"
    return
  fi
  if ! command -v speedtest >/dev/null 2>&1; then
    echo "NOTE: Ookla 'speedtest' binary not on PATH. Install with:"
    echo "  curl -sSL https://install.speedtest.net/app/cli/ookla-speedtest-1.2.0-linux-x86_64.tgz -o /tmp/ookla.tgz"
    echo "  tar xzf /tmp/ookla.tgz -C /tmp && install -m 0755 /tmp/speedtest /usr/local/bin/speedtest"
    echo "  (poller still runs without it; speedtest events will be skipped)"
  fi
  if ! id -u "$user" >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin "$user"
  fi
  install -d -o root -g root -m 0755 /opt/wan-perf-poller
  install -m 0755 "$src" /opt/wan-perf-poller/
  install -d -o "$user" -g "$user" -m 0750 /var/lib/wan-perf-poller
  install -d -o root -g "$user" -m 0750 /etc/wan-perf-poller
  if [[ ! -f /etc/wan-perf-poller/env ]]; then
    cat > /etc/wan-perf-poller/env <<'EOF'
GELF_URL=http://127.0.0.1:12202/gelf
# source field on emitted events — must match the Cradlepoint stream's
# source rule so the WAN Perf page picks these up.
WAN_HOST_LABEL=e300.darknetian.com
WAN_CANARIES=1.1.1.1,8.8.8.8,9.9.9.9,threatdefense.infoblox.com,ns1.darknetian.com,www.darknetian.com
WAN_DNS_RESOLVERS=1.1.1.1,8.8.8.8,9.9.9.9,ns1.darknetian.com,threatdefense.infoblox.com
# `{rand}` is replaced with 8 hex chars per cycle so resolvers can't
# serve from cache. example.com is IANA-managed; random labels NX
# cheaply.
WAN_DNS_QUERY_TEMPLATE={rand}.example.com
WAN_PING_COUNT=10
# SKIP_SPEEDTEST=1 to disable Ookla runs (e.g. on metered links)
EOF
    chmod 0640 /etc/wan-perf-poller/env
    chown root:"$user" /etc/wan-perf-poller/env
  fi
  install -m 0644 systemd/wan-perf-poller.service /etc/systemd/system/
  install -m 0644 systemd/wan-perf-poller.timer   /etc/systemd/system/
}

install_wan_perf_poller

# Cloudflare → NIOS darknetian.com sync (additive). Pulls CF zone
# records and writes anything NIOS doesn't already have. Defaults to
# dry-run; flip SYNC_DRY_RUN=0 in the env file to enable writes.
install_cf_to_nios_sync() {
  local user=cf-to-nios-sync
  local src=tools/cf_to_nios_sync.py

  if [[ ! -f "$src" ]]; then
    echo "skip cf-to-nios-sync (no $src in repo)"
    return
  fi
  if ! id -u "$user" >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin "$user"
  fi
  install -d -o root -g root -m 0755 /opt/cf-to-nios-sync
  install -m 0755 "$src" /opt/cf-to-nios-sync/
  install -d -o "$user" -g "$user" -m 0750 /var/lib/cf-to-nios-sync
  install -d -o root -g "$user" -m 0750 /etc/cf-to-nios-sync
  if [[ ! -f /etc/cf-to-nios-sync/env ]]; then
    cat > /etc/cf-to-nios-sync/env <<'EOF'
# Cloudflare API token with Zone Read on darknetian.com.
CF_API_TOKEN=
# NIOS grid master credentials.
NIOS_HOST=gm.darknetian.com
NIOS_USER=admin
NIOS_PASS=
NIOS_WAPI_VER=v2.13
NIOS_VIEW=default
# Cloudflare zone to mirror.
CF_ZONE=darknetian.com
# Start in dry-run. Flip to 0 to enable writes.
SYNC_DRY_RUN=1
# Types to sync. NIOS WAPI v2.13 doesn't have native SVCB/TLSA, those
# stay CF-only.
SYNC_TYPES=A,AAAA,CNAME,MX,TXT
GELF_URL=http://127.0.0.1:12202/gelf
EOF
    chmod 0640 /etc/cf-to-nios-sync/env
    chown root:"$user" /etc/cf-to-nios-sync/env
    echo "NOTE: edit /etc/cf-to-nios-sync/env to add CF_API_TOKEN + NIOS_PASS"
  fi
  install -m 0644 systemd/cf-to-nios-sync.service /etc/systemd/system/
  install -m 0644 systemd/cf-to-nios-sync.timer   /etc/systemd/system/
}

install_cf_to_nios_sync

# dnstap-collector — listens on :6000/tcp for NIOS dnstap (Frame Streams),
# decodes with the dnscollector Go binary, pipes JSON to a small Python
# bridge that reshapes to GELF and POSTs to the existing 12202 input.
# Output lands in the "NIOS dnstap" stream (see indexing/nios_dnstap.py).
install_dnstap_collector() {
  local user=dnstap-collector
  local cfg=pollers/dnstap_collector_config.yml
  local bridge=pollers/dnstap_bridge.py
  local svc=systemd/dnstap-collector.service

  if [[ ! -f "$cfg" || ! -f "$bridge" ]]; then
    echo "skip dnstap-collector (sources missing in repo)"
    return
  fi
  if ! command -v dnscollector >/dev/null 2>&1; then
    echo "NOTE: dnscollector binary not on PATH. Install:"
    echo "  cd /tmp && curl -sSL -o ookla.tgz https://github.com/dmachard/dns-collector/releases/download/v2.2.3/DNS-collector_2.2.3_linux_amd64.tar.gz"
    echo "  tar xzf ookla.tgz && install -m 0755 dnscollector /usr/local/bin/dnscollector"
  fi
  if ! id -u "$user" >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin "$user"
  fi
  install -d -o root -g root -m 0755 /opt/dnstap-bridge /etc/dnscollector
  install -d -o "$user" -g "$user" -m 0755 /var/log/dnscollector
  install -m 0755 "$bridge" /opt/dnstap-bridge/bridge.py
  install -m 0644 "$cfg"    /etc/dnscollector/config.yml
  install -m 0644 "$svc"    /etc/systemd/system/

  # LAN-only firewall allow for :6000 so off-network hosts can't push
  # arbitrary dnstap traffic into the collector.
  if command -v ufw >/dev/null 2>&1; then
    ufw allow from 10.10.0.0/24 to any port 6000 proto tcp comment "NIOS dnstap" >/dev/null 2>&1 || true
  fi
}

install_dnstap_collector

# Synthetic CTEM emitter — keeps the Darknetian dashboard page populated
# with fake findings now that the real DMARC/SPF/DKIM misconfigs are
# fixed on Cloudflare. Five canned events, hourly, all tagged
# _synthetic=true + _adapter=synthetic + _bounty_eligible=false.
install_ctem_synthetic() {
  local user=ctem-synthetic
  local src=pollers/ctem_synthetic.py

  if [[ ! -f "$src" ]]; then
    echo "skip ctem-synthetic (no $src in repo)"
    return
  fi
  if ! id -u "$user" >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin "$user"
  fi
  install -d -o root -g root -m 0755 /opt/ctem-synthetic
  install -m 0755 "$src" /opt/ctem-synthetic/
  install -m 0644 systemd/ctem-synthetic.service /etc/systemd/system/
  install -m 0644 systemd/ctem-synthetic.timer   /etc/systemd/system/
}

install_ctem_synthetic

# dnstap unanswered-query detector — joins CLIENT_QUERY rows against
# CLIENT_RESPONSE rows on a 4-tuple key (identity, client_ip, port,
# dns_id) and emits one GELF per orphan. Same single-unit shape as
# cf-poller.
install_dnstap_unanswered() {
  local user=dnstap-unanswered
  local src=pollers/dnstap_unanswered.py

  if [[ ! -f "$src" ]]; then
    echo "skip dnstap-unanswered (no $src in repo)"
    return
  fi
  if ! id -u "$user" >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin "$user"
  fi
  install -d -o root -g root -m 0755 /opt/dnstap-unanswered
  install -m 0755 "$src" /opt/dnstap-unanswered/
  install -d -o root -g "$user" -m 0750 /etc/dnstap-unanswered
  if [[ ! -f /etc/dnstap-unanswered/env ]]; then
    cat > /etc/dnstap-unanswered/env <<'EOF'
# Graylog API endpoint + token. The token only needs read access on
# the dnstap stream and ability to call /search/universal/absolute.
GRAYLOG_URL=https://graylog.darknetian.com/api
GRAYLOG_TOKEN=
GELF_URL=http://127.0.0.1:12202/gelf
# Optional overrides:
# DNSTAP_STREAM=6a0b235712e68f7f742811ec
# WINDOW_START_S=30      # grace for in-flight responses
# WINDOW_END_S=90        # window is [now-END, now-START]
EOF
    chmod 0640 /etc/dnstap-unanswered/env
    chown root:"$user" /etc/dnstap-unanswered/env
    echo "NOTE: edit /etc/dnstap-unanswered/env to add GRAYLOG_TOKEN"
  fi
  install -m 0644 systemd/dnstap-unanswered.service /etc/systemd/system/
  install -m 0644 systemd/dnstap-unanswered.timer   /etc/systemd/system/
}

install_dnstap_unanswered

# Auto-rotate watchdog: watches Graylog's indexer-failures count and
# rotates the offending index set when it spikes. Same single-unit
# shape as cf-poller.
install_auto_rotate() {
  local user=graylog-auto-rotate
  local src=tools/auto_rotate_on_failures.py

  if [[ ! -f "$src" ]]; then
    echo "skip graylog-auto-rotate (no $src in repo)"
    return
  fi
  if ! id -u "$user" >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin "$user"
  fi
  install -d -o root -g root -m 0755 /opt/graylog-auto-rotate
  install -m 0755 "$src" /opt/graylog-auto-rotate/
  install -d -o "$user" -g "$user" -m 0750 /var/lib/graylog-auto-rotate
  install -d -o root -g "$user" -m 0750 /etc/graylog-auto-rotate
  if [[ ! -f /etc/graylog-auto-rotate/env ]]; then
    cat > /etc/graylog-auto-rotate/env <<'EOF'
# Graylog API endpoint + token. The token must have permission to:
#   - GET /system/indexer/failures
#   - GET /system/indices/index_sets
#   - POST /system/deflector/{id}/cycle
# An admin-scope token works.
GRAYLOG_URL=https://graylog.darknetian.com/api
GRAYLOG_TOKEN=
# Threshold + cooldown — tune for your workload.
SPIKE_THRESHOLD=500
COOLDOWN_S=1800
EOF
    chmod 0640 /etc/graylog-auto-rotate/env
    chown root:"$user" /etc/graylog-auto-rotate/env
    echo "NOTE: edit /etc/graylog-auto-rotate/env to add GRAYLOG_TOKEN"
  fi
  install -m 0644 systemd/graylog-auto-rotate.service /etc/systemd/system/
  install -m 0644 systemd/graylog-auto-rotate.timer   /etc/systemd/system/
}

install_auto_rotate

systemctl daemon-reload
systemctl enable --now \
  ilo-poller-health.timer ilo-poller-logs.timer \
  idrac-poller-health.timer idrac-poller-logs.timer \
  cf-poller.timer \
  csp-poller.timer \
  mcp-poller.timer \
  ha-log-poller.timer \
  wan-perf-poller.timer \
  cf-to-nios-sync.timer \
  dnstap-collector.service \
  ctem-synthetic.timer \
  graylog-auto-rotate.timer

echo "installed. Status:"
systemctl --no-pager status \
  ilo-poller-health.timer ilo-poller-logs.timer \
  idrac-poller-health.timer idrac-poller-logs.timer \
  cf-poller.timer \
  csp-poller.timer \
  mcp-poller.timer \
  ha-log-poller.timer \
  wan-perf-poller.timer \
  cf-to-nios-sync.timer \
  dnstap-collector.service \
  ctem-synthetic.timer \
  graylog-auto-rotate.timer || true
