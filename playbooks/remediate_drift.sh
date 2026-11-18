#!/bin/bash
# remediate_drift.sh — thin wrapper invoking the Ansible playbook.
#
# The privilege boundary is unchanged by the move to Ansible: sudoers grants
# exactly this absolute path, and the playbook path below is hard-coded. The
# daemon cannot choose which playbook runs, only which wrapper.
#
# Running ansible-playbook directly from sudoers would be a mistake: it takes
# a playbook path as an argument, so granting it would grant arbitrary code
# execution as root.

set -uo pipefail

LOG=/var/log/soar-remediation.log
DIR=/usr/local/share/soar/ansible

cd "$DIR" || { echo "missing $DIR"; exit 1; }

/usr/bin/ansible-playbook "$DIR/remediate_drift.yml" --extra-vars "soar_alert_rule=${SOAR_ALERT_RULE:-unset} soar_target_host=${SOAR_TARGET_HOST:-unset}" 2>&1 | tee -a "$LOG"
exit "${PIPESTATUS[0]}"
