#!/bin/bash
# scenario1_ssh_drift.sh — Attack emulation and latency benchmark.
#
# Scenario 1: unapproved SSH configuration modification.
#
# Weakens the SSH configuration by enabling password authentication, then
# measures the full detection-to-remediation path and verifies the change
# was reverted.
#
# Run as:  sudo ./scenario1_ssh_drift.sh

set -uo pipefail

[ "$(id -u)" -eq 0 ] || { echo "run with sudo"; exit 1; }

DROPIN=/etc/ssh/sshd_config.d/00-ca-auth.conf
RESULTS=/var/log/soar-benchmark.log

ts() { date +%s.%N; }
now() { date -Is; }

echo "=============================================================="
echo " Scenario 1 — Unapproved SSH configuration modification"
echo " Started: $(now)"
echo "=============================================================="

echo
echo "[1] Pre-conditions"
before=$(grep -c '^PasswordAuthentication no' "$DROPIN" 2>/dev/null || echo 0)
echo "    PasswordAuthentication no present: ${before}"
curl -s http://127.0.0.1:8088/health || { echo "    daemon not responding"; exit 1; }
echo

echo "[2] Introducing drift — enabling password authentication"
T_DRIFT=$(ts)
sed -i 's/^PasswordAuthentication no/PasswordAuthentication yes/' "$DROPIN"
echo "    drift introduced at $(now)"
grep '^PasswordAuthentication' "$DROPIN"
echo

echo "[3] Waiting for detection and remediation (max 180s)"
elapsed=0
while [ "$elapsed" -lt 180 ]; do
  if grep -q '^PasswordAuthentication no' "$DROPIN" 2>/dev/null; then
    T_FIXED=$(ts)
    break
  fi
  sleep 2
  elapsed=$((elapsed + 2))
done
echo

if ! grep -q '^PasswordAuthentication no' "$DROPIN" 2>/dev/null; then
  echo "[4] RESULT: NOT REMEDIATED within 180s"
  echo "    Reverting manually so the host is not left weakened."
  sed -i 's/^PasswordAuthentication yes/PasswordAuthentication no/' "$DROPIN"
  systemctl reload-or-restart ssh
  exit 1
fi

TOTAL=$(echo "$T_FIXED - $T_DRIFT" | bc)

echo "[4] RESULT: REMEDIATED"
printf "    End-to-end latency: %.2f seconds\n" "$TOTAL"
echo "    Target was 60 seconds"
echo

echo "[5] Verification"
grep '^PasswordAuthentication' "$DROPIN"
sshd -t && echo "    sshd config valid"
echo

echo "[6] Daemon record"
tail -5 /var/log/soar-remediation.log
echo

{
  echo "$(now) scenario=1 result=remediated latency_seconds=$(printf '%.2f' "$TOTAL")"
} >> "$RESULTS"

echo "Recorded to ${RESULTS}"
