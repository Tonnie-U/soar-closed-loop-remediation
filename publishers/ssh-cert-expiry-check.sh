#!/bin/bash
# ssh-cert-expiry-check.sh — publish SSH user certificate expiry state.
#
# Walks the monitored certificate register and publishes OK / EXPIRING /
# EXPIRED for each certificate to Elasticsearch, together with the Key ID and
# the principal. Those two fields are what the remediation playbook needs in
# order to act, and the webhook payload defined in the Phase 4 brief carries
# neither, so the Kibana action body has to lift them out of the matching
# document. They are published here for exactly that reason.
#
# The register is /etc/ssh/monitored-certs, not the users' home directories.
# A user can write a certificate into their own ~/.ssh; they cannot write one
# into the register, so the register is the authority on what is under
# management.

set -uo pipefail

# shellcheck disable=SC1091
source /etc/soar/soar.env 2>/dev/null || true

ES="${ES_URL:-http://localhost:9200}"
ESUSER="${ES_USER:-elastic}"
ESPASS="${ES_PASSWORD:-}"
INDEX=cert-events
WARN_DAYS=30
LOG=/var/log/ssh-cert-expiry.log

now=$(date +%s)
ts=$(date -u +%Y-%m-%dT%H:%M:%S.000Z)
host=$(hostname)

shopt -s nullglob
for cert in /etc/ssh/monitored-certs/*-cert.pub; do
  info=$(ssh-keygen -L -f "$cert" 2>/dev/null) || continue
  key_id=$(awk -F'"' '/Key ID:/{print $2}' <<<"$info")
  principal=$(awk '/Principals:/{getline; print $1; exit}' <<<"$info")
  expires=$(awk '/Valid:/' <<<"$info" | sed -n 's/.* to \(.*\)$/\1/p' | tr -d ' ')

  # A certificate with no end date ("Valid: forever") cannot expire and is
  # skipped rather than reported, so it never produces a misleading record.
  [ -n "$expires" ] || continue

  exp_epoch=$(date -d "${expires/T/ }" +%s 2>/dev/null) || continue
  days=$(( (exp_epoch - now) / 86400 ))

  if   [ "$exp_epoch" -le "$now" ];  then status=EXPIRED
  elif [ "$days" -le "$WARN_DAYS" ]; then status=EXPIRING
  else                                    status=OK
  fi

  curl -s -u "${ESUSER}:${ESPASS}" -H 'Content-Type: application/json' \
    -X POST "${ES}/${INDEX}/_doc" -d "{
    \"@timestamp\": \"${ts}\",
    \"host\": { \"name\": \"${host}\" },
    \"event\": { \"kind\": \"state\", \"category\": [\"authentication\"], \"action\": \"cert_expiry_check\" },
    \"ssh_cert\": {
      \"key_id\": \"${key_id}\",
      \"principal\": \"${principal}\",
      \"path\": \"${cert}\",
      \"expires\": \"${expires}\",
      \"days_remaining\": ${days},
      \"status\": \"${status}\"
    }
  }" >/dev/null

  echo "${ts} key_id=${key_id} principal=${principal} expires=${expires} days=${days} status=${status}" | tee -a "$LOG"
done
