#!/usr/bin/env bash
# Install the iLO + iDRAC Redfish pollers on the Graylog Ubuntu VM.
# Run as root on the Graylog VM after copying this whole repo there.
#
#   sudo bash systemd/install.sh
#
# Then fill in the env files (each is gitignored; install.sh creates an
# empty template if missing):
#   /etc/ilo-poller/env       — ILO_HOST / ILO_USER / ILO_PASS
#   /etc/idrac-poller/env     — IDRAC_HOST / IDRAC_USER / IDRAC_PASS

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

systemctl daemon-reload
systemctl enable --now \
  ilo-poller-health.timer ilo-poller-logs.timer \
  idrac-poller-health.timer idrac-poller-logs.timer

echo "installed. Status:"
systemctl --no-pager status \
  ilo-poller-health.timer ilo-poller-logs.timer \
  idrac-poller-health.timer idrac-poller-logs.timer || true
