#!/usr/bin/env bash
# Install the iLO poller on the Graylog Ubuntu VM.
# Run as root on the Graylog VM after copying this whole repo there.
#
#   sudo bash systemd/install.sh
#
# Then create /etc/ilo-poller/env (perms 600) with:
#   ILO_HOST=ilo-esxi2.darknetian.com
#   ILO_USER=<read-only iLO user>
#   ILO_PASS=<password>
# (file is gitignored; install.sh creates an empty template if missing)

set -euo pipefail
cd "$(dirname "$0")/.."

# Account
if ! id -u ilo-poller >/dev/null 2>&1; then
  useradd --system --no-create-home --shell /usr/sbin/nologin ilo-poller
fi

# Code
install -d -o root -g root -m 0755 /opt/ilo-poller
install -m 0755 pollers/ilo_redfish.py /opt/ilo-poller/

# State
install -d -o ilo-poller -g ilo-poller -m 0750 /var/lib/ilo-poller

# Config
install -d -o root -g ilo-poller -m 0750 /etc/ilo-poller
if [[ ! -f /etc/ilo-poller/env ]]; then
  cat > /etc/ilo-poller/env <<'EOF'
# Fill in then `systemctl restart ilo-poller-health.timer ilo-poller-logs.timer`
ILO_HOST=ilo-esxi2.darknetian.com
ILO_USER=
ILO_PASS=
GELF_URL=http://127.0.0.1:12202/gelf
ILO_INSECURE=1
EOF
  chmod 0640 /etc/ilo-poller/env
  chown root:ilo-poller /etc/ilo-poller/env
  echo "NOTE: edit /etc/ilo-poller/env to add ILO_USER and ILO_PASS"
fi

# Units
install -m 0644 systemd/ilo-poller-health.service /etc/systemd/system/
install -m 0644 systemd/ilo-poller-health.timer   /etc/systemd/system/
install -m 0644 systemd/ilo-poller-logs.service   /etc/systemd/system/
install -m 0644 systemd/ilo-poller-logs.timer     /etc/systemd/system/

systemctl daemon-reload
systemctl enable --now ilo-poller-health.timer ilo-poller-logs.timer

echo "installed. Status:"
systemctl --no-pager status ilo-poller-health.timer ilo-poller-logs.timer
