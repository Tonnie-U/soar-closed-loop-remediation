#!/bin/bash
# publish-drift-check.sh — fast configuration integrity check.
#
# Compares live security configuration against the approved golden baseline
# and publishes the result to Elasticsearch. Runs in well under a second,
# which is what makes a sub-60-second detection-to-remediation path possible.
#
# Lynis remains the periodic compliance measure; it is far too slow (60-90s
# per run) to sit on the detection path for a 60-second response target.

set -uo pipefail

# shellcheck disable=SC1091
source /etc/soar/soar.env 2>/dev/null || true

ES="${ES_URL:-http://localhost:9200}"
ESUSER="${ES_USER:-elastic}"
ESPASS="${ES_PASSWORD:-}"
GOLDEN=/etc/soar/golden
INDEX=drift-events

drifted=()

check() {
  local name="$1" golden="$2" live="$3"
  [ -f "$golden" ] || return 0
  if ! cmp -s "$golden" "$live" 2>/dev/null; then
    drifted+=("$name")
  fi
}

check "sshd_config"  "$GOLDEN/sshd_config"      /etc/ssh/sshd_config
check "00-ca-auth"   "$GOLDEN/00-ca-auth.conf"  /etc/ssh/sshd_config.d/00-ca-auth.conf
check "nginx.conf"   "$GOLDEN/nginx.conf"       /etc/nginx/nginx.conf
check "lab-tls"      "$GOLDEN/lab-tls"          /etc/nginx/sites-available/lab-tls

if [ ${#drifted[@]} -eq 0 ]; then
  status="CLEAN"
  files=""
else
  status="DRIFTED"
  files=$(printf '%s,' "${drifted[@]}"); files="${files%,}"
fi

ts=$(date -u +%Y-%m-%dT%H:%M:%S.000Z)
host=$(hostname)

read -r -d '' body <<EOF
{
  "@timestamp": "${ts}",
  "host": { "name": "${host}" },
  "event": { "kind": "state", "category": ["configuration"], "action": "integrity_check" },
  "drift": {
    "status": "${status}",
    "files": "${files}",
    "file_count": ${#drifted[@]}
  }
}
EOF

curl -s -u "${ESUSER}:${ESPASS}" -H 'Content-Type: application/json' \
  -X POST "${ES}/${INDEX}/_doc" -d "${body}" >/dev/null

echo "${ts} status=${status} files=${files:-none}"
