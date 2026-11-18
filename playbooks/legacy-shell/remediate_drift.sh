#!/bin/bash
# remediate_drift.sh — Trigger A: configuration drift remediation.
#
# Restores the approved SSH and NGINX configurations from the golden
# baseline and restarts the affected services.
#
# The golden copies live in /etc/soar/golden and are written once, by hand,
# from a configuration that has been reviewed. The daemon never writes to
# that directory: if remediation could update its own source of truth, an
# attacker who altered the live config and waited one cycle would have the
# drift adopted as the new baseline.

set -uo pipefail

GOLDEN=/etc/soar/golden
LOG=/var/log/soar-remediation.log

log() { echo "$(date -Is) [drift] $*" | tee -a "$LOG"; }

log "remediation started (rule=${SOAR_ALERT_RULE:-unset} host=${SOAR_TARGET_HOST:-unset})"

changed=0
failed=0

restore() {
  local name="$1" golden="$2" live="$3"

  if [ ! -f "$golden" ]; then
    log "SKIP $name: no golden copy at $golden"
    return 0
  fi

  if cmp -s "$golden" "$live"; then
    log "OK $name: already matches baseline"
    return 0
  fi

  # Keep what we are about to overwrite. Remediation that destroys the
  # evidence of what drifted makes the incident unanalysable afterwards.
  local stamp
  stamp=$(date +%Y%m%d-%H%M%S)
  cp -a "$live" "${live}.drift-${stamp}" 2>/dev/null \
    && log "preserved drifted copy at ${live}.drift-${stamp}"

  if cp -a "$golden" "$live"; then
    log "RESTORED $name from baseline"
    changed=$((changed + 1))
  else
    log "FAIL $name: could not restore"
    failed=$((failed + 1))
  fi
}

restore "sshd_config"   "$GOLDEN/sshd_config"   /etc/ssh/sshd_config
restore "00-ca-auth"    "$GOLDEN/00-ca-auth.conf" /etc/ssh/sshd_config.d/00-ca-auth.conf
restore "nginx.conf"    "$GOLDEN/nginx.conf"    /etc/nginx/nginx.conf
restore "lab-tls"       "$GOLDEN/lab-tls"       /etc/nginx/sites-available/lab-tls

if [ "$changed" -eq 0 ] && [ "$failed" -eq 0 ]; then
  log "no changes required"
  exit 0
fi

# Validate before restarting. Restarting sshd with a broken config on a
# remote host is how people lose access to the machine they are fixing.
if sshd -t 2>>"$LOG"; then
  if systemctl reload-or-restart ssh 2>>"$LOG"; then
    log "ssh reloaded"
  else
    log "FAIL ssh reload"
    failed=$((failed + 1))
  fi
else
  log "FAIL sshd config validation — not restarting ssh"
  failed=$((failed + 1))
fi

if nginx -t 2>>"$LOG"; then
  if systemctl reload-or-restart nginx 2>>"$LOG"; then
    log "nginx reloaded"
  else
    log "FAIL nginx reload"
    failed=$((failed + 1))
  fi
else
  log "FAIL nginx config validation — not restarting nginx"
  failed=$((failed + 1))
fi

log "remediation finished: ${changed} restored, ${failed} failures"
[ "$failed" -eq 0 ]
