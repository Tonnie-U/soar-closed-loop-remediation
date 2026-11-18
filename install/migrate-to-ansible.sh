#!/bin/bash
# migrate-to-ansible.sh — replace the shell remediation playbooks with the
# Ansible implementation on a host that already runs the shell version.
#
# Nothing about the privilege boundary changes: sudoers still grants the same
# three absolute wrapper paths, and the daemon, its service unit and its
# authentication are untouched.
#
# Run as: sudo ./install/migrate-to-ansible.sh

set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "run with sudo"; exit 1; }

SRC="$(cd "$(dirname "$0")/.." && pwd)"
PB=/usr/local/share/soar/playbooks
AN=/usr/local/share/soar/ansible
BK="/usr/local/share/soar/shell-backup-$(date -u +%Y%m%dT%H%M%SZ)"

echo "==> installing ansible-core if absent"
command -v ansible-playbook >/dev/null 2>&1 || {
  apt-get update -qq
  apt-get install -y -qq ansible-core >/dev/null
}
ansible-playbook --version | head -1

echo "==> backing up the shell playbooks to $BK"
mkdir -p "$BK"
for pb in remediate_drift.sh remediate_certificate.sh reaudit.sh; do
  [ -f "$PB/$pb" ] && cp -a "$PB/$pb" "$BK/$pb"
done

echo "==> installing the Ansible playbooks"
mkdir -p "$AN"
for f in remediate_drift.yml remediate_certificate.yml reaudit.yml inventory.ini ansible.cfg; do
  install -o root -g root -m 0644 "$SRC/ansible/$f" "$AN/$f"
done

echo "==> installing the wrappers over the shell versions"
for pb in remediate_drift.sh remediate_certificate.sh reaudit.sh; do
  install -o root -g root -m 0755 "$SRC/playbooks/$pb" "$PB/$pb"
done

echo "==> creating the evidence directory"
mkdir -p /var/lib/soar/evidence
chmod 750 /var/lib/soar/evidence

echo "==> checking playbook syntax"
for y in remediate_drift.yml remediate_certificate.yml reaudit.yml; do
  (cd "$AN" && ansible-playbook --syntax-check "$y" >/dev/null) && echo "    OK $y"
done

echo "==> restarting the daemon"
systemctl restart soar-remediator
sleep 2
systemctl is-active soar-remediator

cat <<'NOTE'

Migration complete.

The daemon, sudoers grant and service unit are unchanged — only the
implementation behind the three wrapper paths has moved from shell to Ansible.

Evidence copies of drifted files now land in /var/lib/soar/evidence rather
than beside the live file, so a preserved copy can never be picked up as
configuration.

To roll back, copy the scripts from the backup directory printed above over
the wrappers in /usr/local/share/soar/playbooks.

Verify with:
   sudo /home/tonnie/soar/tests/scenario1_ssh_drift.sh
NOTE
