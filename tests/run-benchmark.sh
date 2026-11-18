#!/bin/bash
# run-benchmark.sh — run both attack scenarios repeatedly to build a latency
# distribution.
#
# The sleeps are not padding. A Kibana rule raises an alert that stays Active
# while any matching document sits inside its time window, and the action fires
# on status change. A second attack launched inside that window produces no
# second action, so back-to-back runs measure the suppression window rather
# than the response time. The gaps here clear the window first.
#
# Run detached so it survives the session:
#   sudo systemd-run --unit=soar-bench --service-type=oneshot /usr/local/sbin/soar-bench.sh

set -uo pipefail
[ "$(id -u)" -eq 0 ] || { echo "run with sudo"; exit 1; }

T=/home/tonnie/soar/tests

for i in 1 2 3; do
  "$T/scenario1_ssh_drift.sh"
  sleep 360
done

for i in 1 2 3; do
  "$T/scenario2_cert_expiry.sh"
  sleep 240
done
