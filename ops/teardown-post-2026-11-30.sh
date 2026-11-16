#!/usr/bin/env bash
# Deterministic post-judging teardown routine (run after 2026-11-30).
# Stops and removes ONLY ReserveRail and zkv-gatekeeper-runner units/secrets while
# preserving unrelated host services (cloudflared.service, company-mac-watch.timer).
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run with sudo: sudo bash ops/teardown-post-2026-11-30.sh" >&2
  exit 1
fi

for unit in cloudflared-reserverail.service reserverail.service zkv-gatekeeper-runner.service; do
  if systemctl list-unit-files "$unit" >/dev/null 2>&1; then
    systemctl stop "$unit" || true
    systemctl disable "$unit" || true
    rm -f "/etc/systemd/system/${unit}"
  fi
done

systemctl daemon-reload

for secret_file in /etc/reserverail/reserverail.env /etc/zkv-gatekeeper/gatekeeper.env; do
  if [[ -f "$secret_file" ]]; then
    shred -u "$secret_file"
  fi
done

if [[ -d /etc/cloudflared-reserverail ]]; then
  find /etc/cloudflared-reserverail -type f -name '*.json' -exec shred -u {} \;
  rm -rf /etc/cloudflared-reserverail
fi

rm -rf /etc/reserverail /etc/zkv-gatekeeper /var/lib/reserverail /var/lib/zkv-gatekeeper /opt/reserverail /opt/zkv-gatekeeper-runner

# Verify unrelated host services were never disrupted
systemctl is-active --quiet cloudflared.service
systemctl is-active --quiet company-mac-watch.timer

echo '{"ok":true,"teardown":"complete","preserved":["cloudflared.service","company-mac-watch.timer"]}'
