#!/bin/bash
# install-publishers.sh — install the three telemetry publishers and their timers.
#
#   drift-check       every 30 seconds   fast config integrity  -> drift-events
#   ssh-cert-expiry   every 30 seconds   certificate validity   -> cert-events
#   lynis-score       every 10 minutes   compliance index       -> lynis-metrics
#
# The two 30-second timers are the detection path. Lynis is not: a Lynis audit
# takes 60-90 seconds, so it cannot sit on a path with a 60-second response
# target. In production both demonstration intervals would be daily.

set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "run with sudo"; exit 1; }

SRC="$(cd "$(dirname "$0")/.." && pwd)"

echo "==> installing publishers"
install -m 0750 "$SRC/publishers/publish-drift-check.sh"    /usr/local/sbin/publish-drift-check.sh
install -m 0750 "$SRC/publishers/publish-lynis-score.sh"    /usr/local/sbin/publish-lynis-score.sh
install -m 0750 "$SRC/publishers/ssh-cert-expiry-check.sh"  /usr/local/sbin/ssh-cert-expiry-check.sh

echo "==> installing timers"
for unit in drift-check lynis-score ssh-cert-expiry; do
  install -m 0644 "$SRC/systemd/${unit}.service" "/etc/systemd/system/${unit}.service"
  install -m 0644 "$SRC/systemd/${unit}.timer"   "/etc/systemd/system/${unit}.timer"
done

systemctl daemon-reload
systemctl enable --now drift-check.timer lynis-score.timer ssh-cert-expiry.timer

echo
echo "Timers installed:"
systemctl list-timers drift-check.timer lynis-score.timer ssh-cert-expiry.timer --no-pager

echo
echo "Running the fast checks once now..."
/usr/local/sbin/publish-drift-check.sh
/usr/local/sbin/ssh-cert-expiry-check.sh
echo "Lynis run started in background (takes 60-90s)"
systemctl start --no-block lynis-score.service
