#!/bin/bash
# install-ca.sh — establish the SSH user CA and the monitored certificate
# register that Trigger B depends on.
#
# Lab limitation, stated plainly: the CA private key is generated and kept on
# the monitored host. In any real deployment it belongs on an offline
# management host that the monitored fleet cannot reach, because an attacker
# who compromises a target should gain the ability to use credentials, never
# the ability to mint them.
#
# Run as: sudo ./install-ca.sh <principal> <key-id>

set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "run with sudo"; exit 1; }

PRINCIPAL="${1:?usage: install-ca.sh <principal> <key-id>}"
KEY_ID="${2:?usage: install-ca.sh <principal> <key-id>}"
USER_PUBKEY="/home/${PRINCIPAL}/.ssh/id_ed25519.pub"

echo "==> generating user CA"
[ -f /etc/ssh/ssh_user_ca ] || ssh-keygen -t ed25519 -f /etc/ssh/ssh_user_ca -C "lab-user-ca" -N ""

echo "==> trusting the CA and enabling revocation"
cat > /etc/ssh/sshd_config.d/10-ca-trust.conf <<'EOF'
TrustedUserCAKeys /etc/ssh/ssh_user_ca.pub
RevokedKeys /etc/ssh/revoked_keys
EOF
touch /etc/ssh/revoked_keys
chmod 600 /etc/ssh/revoked_keys

echo "==> creating the monitored certificate register"
mkdir -p /etc/ssh/monitored-certs /etc/ssh/revoked-certs
chmod 755 /etc/ssh/monitored-certs /etc/ssh/revoked-certs

echo "==> signing a certificate for ${PRINCIPAL}"
ssh-keygen -s /etc/ssh/ssh_user_ca -I "$KEY_ID" -n "$PRINCIPAL" -V +52w "$USER_PUBKEY"
chown "${PRINCIPAL}:${PRINCIPAL}" "/home/${PRINCIPAL}/.ssh/${KEY_ID}"*-cert.pub 2>/dev/null || \
  chown "${PRINCIPAL}:${PRINCIPAL}" "/home/${PRINCIPAL}/.ssh/id_ed25519-cert.pub"

# A copy, not a symlink. The register is the authority on what is under
# management, and it must not change because a user edited their own home
# directory.
cp "/home/${PRINCIPAL}/.ssh/id_ed25519-cert.pub" "/etc/ssh/monitored-certs/${KEY_ID}-cert.pub"

echo "==> validating"
sshd -t && systemctl reload ssh
echo "CA installed. Existing authorized_keys logins are unaffected: CA trust is additive."
