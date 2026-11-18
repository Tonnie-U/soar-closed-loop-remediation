#!/bin/bash
# publish-lynis-score.sh — periodic compliance measure.
#
# Runs a Lynis audit and publishes the Hardening Index to Elasticsearch.
# Guarded by the same lock the SOAR re-audit uses, so a scheduled run and a
# post-remediation run cannot interleave and produce two different index
# values in one report file.

set -uo pipefail

# shellcheck disable=SC1091
source /etc/soar/soar.env 2>/dev/null || true

ES="${ES_URL:-http://localhost:9200}"
ESUSER="${ES_USER:-elastic}"
ESPASS="${ES_PASSWORD:-}"
INDEX=lynis-metrics
LOCK=/var/lock/lynis-audit.lock
REPORT=/var/log/lynis-report.dat

exec 9>"$LOCK"
flock -w 180 9 || { echo "lock timeout"; exit 1; }

rm -f "$REPORT"
/usr/sbin/lynis audit system --quick --cronjob >/dev/null 2>&1

idx=$(grep -E '^hardening_index=' "$REPORT" 2>/dev/null | tail -1 | cut -d= -f2)
[ -n "$idx" ] || { echo "no index produced"; exit 1; }

ts=$(date -u +%Y-%m-%dT%H:%M:%S.000Z)
host=$(hostname)

curl -s -u "${ESUSER}:${ESPASS}" -H 'Content-Type: application/json' \
  -X POST "${ES}/${INDEX}/_doc" -d "{
  \"@timestamp\": \"${ts}\",
  \"host\": { \"name\": \"${host}\" },
  \"event\": { \"kind\": \"metric\", \"category\": [\"configuration\"], \"action\": \"lynis_audit\" },
  \"lynis\": { \"hardening_index\": ${idx}, \"baseline\": ${HARDENING_BASELINE:-85} }
}" >/dev/null

echo "${ts} hardening_index=${idx}"
