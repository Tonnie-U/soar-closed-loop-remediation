#!/bin/bash
# reaudit.sh — post-remediation verification.
#
# Runs a fresh Lynis audit and prints the resulting Hardening Index in a
# machine-readable form for the daemon to parse:
#
#   HARDENING_INDEX=<n>
#
# A flock guard prevents this from interleaving with the nightly scheduled
# audit, which previously produced two different index values in a single
# report file.

set -uo pipefail

LOCK=/var/lock/lynis-audit.lock
REPORT=/var/log/lynis-report.dat
LOG=/var/log/soar-remediation.log

echo "$(date -Is) [reaudit] starting" >> "$LOG"

exec 9>"$LOCK"
if ! flock -w 120 9; then
  echo "$(date -Is) [reaudit] could not acquire lock within 120s" >> "$LOG"
  echo "HARDENING_INDEX_ERROR=lock_timeout"
  exit 1
fi

rm -f "$REPORT"
/usr/sbin/lynis audit system --quick --cronjob >/dev/null 2>&1

index=$(grep -E '^hardening_index=' "$REPORT" 2>/dev/null | tail -1 | cut -d= -f2)

if [ -z "$index" ]; then
  echo "$(date -Is) [reaudit] no index produced" >> "$LOG"
  echo "HARDENING_INDEX_ERROR=not_found"
  exit 1
fi

echo "$(date -Is) [reaudit] index=${index}" >> "$LOG"
echo "HARDENING_INDEX=${index}"
exit 0
