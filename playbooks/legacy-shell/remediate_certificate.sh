#!/bin/bash
# remediate_certificate.sh — Trigger B: certificate revocation and session termination.
#
# Adds an expired or compromised certificate to the OpenSSH revocation list
# and terminates any live sessions belonging to its principal.
#
# Note on scope: revoking the certificate stops future authentication, but
# an already-established session holds an open channel and is unaffected by
# the revocation list. Terminating the session is therefore a separate and
# necessary step, not a redundant one.

set -uo pipefail

REVOKED_KEYS=/etc/ssh/revoked_keys
MONITORED=/etc/ssh/monitored-certs
LOG=/var/log/soar-remediation.log

log() { echo "$(date -Is) [cert] $*" | tee -a "$LOG"; }

CERT_ID="${SOAR_CERTIFICATE_ID:-}"
PRINCIPAL="${SOAR_PRINCIPAL:-}"

log "revocation started (cert_id=${CERT_ID:-unset} principal=${PRINCIPAL:-unset})"

if [ -z "$CERT_ID" ]; then
  log "FAIL no certificate id supplied — refusing to guess"
  exit 1
fi

# Locate the certificate file whose Key ID matches. We revoke by file
# content rather than by name, because the name is ours and the Key ID is
# what the server actually checked.
cert_file=""
for candidate in "$MONITORED"/*-cert.pub; do
  [ -e "$candidate" ] || continue
  if ssh-keygen -L -f "$candidate" 2>/dev/null | grep -q "Key ID: \"${CERT_ID}\""; then
    cert_file="$candidate"
    break
  fi
done

if [ -z "$cert_file" ]; then
  log "FAIL no monitored certificate carries Key ID ${CERT_ID}"
  exit 1
fi

log "matched ${CERT_ID} to ${cert_file}"

touch "$REVOKED_KEYS"
chmod 644 "$REVOKED_KEYS"

if grep -qxFf "$cert_file" "$REVOKED_KEYS" 2>/dev/null; then
  log "already revoked"
else
  cat "$cert_file" >> "$REVOKED_KEYS"
  log "appended certificate to ${REVOKED_KEYS}"
fi

# Retire the certificate from the monitored register. Left in place it would
# keep publishing EXPIRED, the alert would never recover, and the pipeline
# would have no way to distinguish a new incident from the one just handled.
RETIRED=/etc/ssh/revoked-certs
mkdir -p "$RETIRED"
if mv "$cert_file" "$RETIRED/" 2>>"$LOG"; then
  log "retired ${cert_file##*/} to ${RETIRED}"
else
  log "WARN could not retire ${cert_file##*/} — alert will not recover"
fi

# Tell sshd to consult the list. Without this directive the file exists and
# is ignored, which is a failure mode that looks exactly like success.
DROPIN=/etc/ssh/sshd_config.d/10-revocation.conf
if ! grep -qs "^RevokedKeys" "$DROPIN" /etc/ssh/sshd_config /etc/ssh/sshd_config.d/* 2>/dev/null; then
  echo "RevokedKeys ${REVOKED_KEYS}" > "$DROPIN"
  chmod 644 "$DROPIN"
  log "enabled RevokedKeys directive"
fi

if sshd -t 2>>"$LOG"; then
  systemctl reload-or-restart ssh 2>>"$LOG" && log "ssh reloaded"
else
  log "FAIL sshd config validation — not restarting ssh"
  exit 1
fi

# Terminate live sessions for the principal.
if [ -n "$PRINCIPAL" ]; then
  if id "$PRINCIPAL" >/dev/null 2>&1; then
    sessions=$(who | awk -v u="$PRINCIPAL" '$1 == u' | wc -l)
    if [ "$sessions" -gt 0 ]; then
      log "terminating ${sessions} session(s) for ${PRINCIPAL}"
      pkill -u "$PRINCIPAL" -t "$(who | awk -v u="$PRINCIPAL" '$1 == u {print $2}' | head -1)" sshd 2>/dev/null
      log "sessions terminated"
    else
      log "no live sessions for ${PRINCIPAL}"
    fi
  else
    log "principal ${PRINCIPAL} is not a local account — nothing to terminate"
  fi
fi

log "revocation finished"
exit 0
