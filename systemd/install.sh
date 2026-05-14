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
  graylog-auto-rotate.timer

echo "installed. Status:"
systemctl --no-pager status \
  ilo-poller-health.timer ilo-poller-logs.timer \
  idrac-poller-health.timer idrac-poller-logs.timer \
  cf-poller.timer \
  graylog-auto-rotate.timer || true
