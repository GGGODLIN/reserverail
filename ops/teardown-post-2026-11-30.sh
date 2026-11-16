#!/usr/bin/env bash
# Deterministic post-judging teardown routine (run after 2026-11-30).
# Stops and removes ONLY ReserveRail and zkv-gatekeeper-runner units/secrets while
# leaving any pre-existing host services untouched.
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run with sudo: sudo bash ops/teardown-post-2026-11-30.sh" >&2
  exit 1
fi

declare -a pre_active_units=()
for candidate in cloudflared.service ${PRESERVE_UNITS:-}; do
  if systemctl is-active --quiet "$candidate" 2>/dev/null; then
    pre_active_units+=("$candidate")
  fi
done

for unit in cloudflared-reserverail.service reserverail.service zkv-gatekeeper-runner.service; do
  if systemctl list-unit-files "$unit" >/dev/null 2>&1; then
    systemctl stop "$unit" || true
    systemctl disable "$unit" || true
    rm -f "/etc/systemd/system/${unit}"
  fi
done

systemctl daemon-reload

for secret_file in /etc/reserverail/reserverail.env /etc/zkv-gatekeeper/gatekeeper.env; do
  if [[ -f "$secret_file" && ! -L "$secret_file" ]]; then
    shred -u "$secret_file"
  fi
done

if [[ -d /etc/cloudflared-reserverail && ! -L /etc/cloudflared-reserverail ]]; then
  find /etc/cloudflared-reserverail -type f -name '*.json' -exec shred -u {} \;
  rm -rf /etc/cloudflared-reserverail
fi

rm -rf /etc/reserverail /etc/zkv-gatekeeper /var/lib/reserverail /var/lib/zkv-gatekeeper /opt/reserverail /opt/zkv-gatekeeper-runner

for preserved in "${pre_active_units[@]}"; do
  systemctl is-active --quiet "$preserved"
done

echo '{"ok":true,"teardown":"complete"}'
