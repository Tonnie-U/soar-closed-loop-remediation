#!/bin/bash
# test_webhook.sh — exercise the daemon's authentication and decision engine
# without involving Kibana.
#
# Run as:  sudo ./test_webhook.sh

set -uo pipefail

ENV_FILE=/etc/soar/soar.env
URL=http://127.0.0.1:8088/webhook/alert

[ -r "$ENV_FILE" ] || { echo "cannot read $ENV_FILE — run with sudo"; exit 1; }
# shellcheck disable=SC1090
source "$ENV_FILE"

pass=0; fail=0
check() {
  local name="$1" expected="$2" got="$3"
  if [ "$got" = "$expected" ]; then
    echo "  PASS  $name (HTTP $got)"; pass=$((pass+1))
  else
    echo "  FAIL  $name (expected $expected, got $got)"; fail=$((fail+1))
  fi
}

BODY='{"target_host":"siem-endpoint","alert_rule":"Lynis Hardening Index Below Baseline (85)","severity":"high","hardening_score":81,"timestamp":"2026-11-13T09:00:00Z"}'

echo "Authentication"

code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$URL" \
  -H 'Content-Type: application/json' -d "$BODY")
check "no credentials rejected" "401" "$code"

code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$URL" \
  -H 'Content-Type: application/json' -H 'X-SOAR-Token: wrong-token' -d "$BODY")
check "wrong token rejected" "401" "$code"

SIG=$(printf '%s' "$BODY" | openssl dgst -sha256 -hmac "$SOAR_HMAC_SECRET" -hex | awk '{print $2}')
code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$URL" \
  -H 'Content-Type: application/json' -H "X-SOAR-Signature: ${SIG}" -d "$BODY")
check "valid HMAC accepted" "200" "$code"

code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$URL" \
  -H 'Content-Type: application/json' -H "X-SOAR-Signature: $(printf '%064d' 0)" -d "$BODY")
check "tampered HMAC rejected" "401" "$code"

echo
echo "Decision engine"

UNKNOWN='{"target_host":"siem-endpoint","alert_rule":"Some Unrelated Rule","severity":"low"}'
out=$(curl -s -X POST "$URL" -H 'Content-Type: application/json' \
  -H "X-SOAR-Token: ${SOAR_TOKEN}" -d "$UNKNOWN")
echo "  unmatched rule -> $out"

echo
echo "End-to-end (token auth, drift playbook)"
curl -s -X POST "$URL" -H 'Content-Type: application/json' \
  -H "X-SOAR-Token: ${SOAR_TOKEN}" -d "$BODY" | tee /tmp/soar-e2e.json
echo
echo

echo "Results: ${pass} passed, ${fail} failed"
[ "$fail" -eq 0 ]
