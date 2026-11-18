#!/bin/bash
# scenario2b_expired_cert_auth.sh — attempt an SSH authentication with an
# expired certificate and verify the attempt is refused and logged.
#
# The brief requires the session be "blocked and logged". scenario2 proves the
# certificate is revoked; this proves an authentication attempt with an expired
# certificate is actually refused by the server.
#
# The key under the certificate is not in any authorized_keys file, so there is
# no path by which the attempt could succeed on a different credential.
#
# Run as: sudo ./scenario2b_expired_cert_auth.sh

set -uo pipefail
[ "$(id -u)" -eq 0 ] || { echo "run with sudo"; exit 1; }

CA=/etc/ssh/ssh_user_ca
PRINCIPAL="${1:-tonnie}"
LOG=/var/log/auth.log
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
ID="expired-auth-$(date +%H%M%S)"

ssh-keygen -q -t ed25519 -f "$W/k" -N "" -C "$ID"
ssh-keygen -q -s "$CA" -I "$ID" -n "$PRINCIPAL" -V -2h:-1h "$W/k.pub"

echo "Certificate under test:"
ssh-keygen -L -f "$W/k-cert.pub" | grep -E "Key ID|Valid"

mark=$(wc -l < "$LOG")

echo
echo "Attempting SSH authentication with the expired certificate..."
ssh -i "$W/k" -o CertificateFile="$W/k-cert.pub" -o IdentitiesOnly=yes \
    -o StrictHostKeyChecking=no -o BatchMode=yes -o ConnectTimeout=10 \
    "${PRINCIPAL}@127.0.0.1" "echo UNEXPECTED_SUCCESS" 2>&1 | tail -3
rc=${PIPESTATUS[0]}

echo
if [ "$rc" -ne 0 ]; then
  echo "RESULT: authentication REFUSED (exit $rc) - expected"
else
  echo "RESULT: authentication SUCCEEDED - FAIL"
fi

echo
echo "Authentication log evidence:"
tail -n +$((mark+1)) "$LOG" | grep -iE "cert|expired|invalid|Failed|refus" | tail -8
