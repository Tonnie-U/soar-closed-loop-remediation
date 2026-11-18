#!/bin/bash
# scenario2_cert_expiry.sh — attack emulation: use of an expired SSH certificate.
#
# Mints a certificate already outside its validity window, places it in the
# monitored register, and measures the time until the pipeline revokes it and
# retires it from the register.
#
# The throwaway signing key is destroyed immediately after use: the artefact
# under test is the certificate, and a retained private key would be a
# credential lying around for no reason.
#
# Run as: sudo ./scenario2_cert_expiry.sh

set -uo pipefail
[ "$(id -u)" -eq 0 ] || { echo "run with sudo"; exit 1; }

CA=/etc/ssh/ssh_user_ca
MON=/etc/ssh/monitored-certs
RET=/etc/ssh/revoked-certs
REV=/etc/ssh/revoked_keys
BENCH=/var/log/soar-benchmark.log
MAX=300

ID="svc-expired-$(date +%H%M%S)"
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT

echo "=============================================================="
echo " Scenario 2 — use of an expired SSH certificate"
echo " Started: $(date -Is)"
echo "=============================================================="
echo
echo "[1] Pre-conditions"
curl -s http://127.0.0.1:8088/health; echo
echo "    monitored certificates: $(ls -1 "$MON" 2>/dev/null | wc -l)"

echo
echo "[2] Minting a certificate outside its validity window"
ssh-keygen -q -t ed25519 -f "$W/k" -N "" -C "$ID"
ssh-keygen -q -s "$CA" -I "$ID" -n svc-backup -V -2h:-1h "$W/k.pub"
cp "$W/k-cert.pub" "$MON/${ID}-cert.pub"
shred -u "$W/k" 2>/dev/null || true
t0=$(date +%s.%N)
echo "    planted $ID at $(date -Is)"

echo
echo "[3] Waiting for detection and revocation (max ${MAX}s)"
n=0; ok=0
while [ "$n" -lt "$MAX" ]; do
  if grep -qF "$ID" "$REV" 2>/dev/null || [ -f "$RET/${ID}-cert.pub" ]; then
    t1=$(date +%s.%N); ok=1; break
  fi
  sleep 2; n=$((n+2))
done

echo
if [ "$ok" -eq 1 ]; then
  L=$(awk -v a="$t0" -v b="$t1" 'BEGIN{printf "%.2f", b-a}')
  echo "[4] RESULT: REVOKED"
  echo "    End-to-end latency: ${L} seconds"
  echo "$(date -Is) scenario=2 result=revoked key_id=$ID latency_seconds=$L" >> "$BENCH"
else
  echo "[4] RESULT: NOT REVOKED within ${MAX}s"
  echo "$(date -Is) scenario=2 result=timeout key_id=$ID" >> "$BENCH"
  rm -f "$MON/${ID}-cert.pub"
fi

echo
echo "[5] Verification"
[ -f "$RET/${ID}-cert.pub" ] \
  && echo "    retired from monitored register: yes" \
  || echo "    retired from monitored register: NO"
sshd -t && echo "    sshd config valid" || echo "    sshd config INVALID"

echo
echo "[6] Daemon record"
tail -8 /var/log/soar-remediation.log
echo
echo "Recorded to $BENCH"
