#!/bin/bash
# install.sh — deploy the SOAR remediation daemon on siem-endpoint.
#
# Run as:  sudo ./install.sh
#
# Creates an unprivileged service account, installs the daemon and its
# playbooks, captures the current SSH and NGINX configuration as the golden
# baseline, and grants the account sudo rights to exactly three scripts.

set -euo pipefail

[ "$(id -u)" -eq 0 ] || { echo "run with sudo"; exit 1; }

SRC="$(cd "$(dirname "$0")" && pwd)"

echo "==> creating service account"
id soar >/dev/null 2>&1 || useradd --system --home /opt/soar --shell /usr/sbin/nologin soar

echo "==> installing daemon"
mkdir -p /opt/soar
install -o soar -g soar -m 0644 "$SRC/daemon/soar_remediator.py" /opt/soar/soar_remediator.py

if [ ! -d /opt/soar/venv ]; then
  apt-get update -qq
  apt-get install -y -qq python3-venv python3-pip >/dev/null
  python3 -m venv /opt/soar/venv
fi
/opt/soar/venv/bin/pip install --quiet --upgrade pip
/opt/soar/venv/bin/pip install --quiet fastapi "uvicorn[standard]" httpx
chown -R soar:soar /opt/soar

echo "==> installing Ansible"
command -v ansible-playbook >/dev/null 2>&1 || {
  apt-get update -qq
  apt-get install -y -qq ansible-core >/dev/null
}
ansible-playbook --version | head -1

echo "==> installing Ansible remediation playbooks"
mkdir -p /usr/local/share/soar/ansible
for f in remediate_drift.yml remediate_certificate.yml reaudit.yml inventory.ini ansible.cfg; do
  install -o root -g root -m 0644 "$SRC/ansible/$f" "/usr/local/share/soar/ansible/$f"
done

echo "==> installing playbook wrappers"
# The wrappers sit at the paths sudoers grants. ansible-playbook itself is
# never granted: it takes a playbook path as an argument, so granting it
# would grant arbitrary code execution as root.
mkdir -p /usr/local/share/soar/playbooks
for pb in remediate_drift.sh remediate_certificate.sh reaudit.sh; do
  install -o root -g root -m 0755 "$SRC/playbooks/$pb" "/usr/local/share/soar/playbooks/$pb"
done

mkdir -p /var/lib/soar/evidence
chmod 750 /var/lib/soar/evidence

echo "==> capturing golden baseline"
mkdir -p /etc/soar/golden
chmod 755 /etc/soar /etc/soar/golden
for pair in \
  "/etc/ssh/sshd_config:sshd_config" \
  "/etc/ssh/sshd_config.d/00-ca-auth.conf:00-ca-auth.conf" \
  "/etc/nginx/nginx.conf:nginx.conf" \
  "/etc/nginx/sites-available/lab-tls:lab-tls" ; do
  live="${pair%%:*}"; name="${pair##*:}"
  if [ -f "$live" ]; then
    cp -a "$live" "/etc/soar/golden/$name"
    echo "    captured $name"
  else
    echo "    skipped $name (not present)"
  fi
done
chmod 644 /etc/soar/golden/* 2>/dev/null || true

echo "==> writing environment file"
if [ ! -f /etc/soar/soar.env ]; then
  TOKEN=$(head -c 32 /dev/urandom | base64 | tr -d '/+=' | head -c 40)
  HMAC=$(head -c 32 /dev/urandom | base64 | tr -d '/+=' | head -c 40)
  cat > /etc/soar/soar.env <<EOF
SOAR_TOKEN=${TOKEN}
SOAR_HMAC_SECRET=${HMAC}
ES_URL=http://localhost:9200
ES_USER=elastic
ES_PASSWORD=CHANGE_ME
PLAYBOOK_DIR=/usr/local/share/soar/playbooks
AUDIT_INDEX=soar-actions
HARDENING_BASELINE=85
PLAYBOOK_TIMEOUT=300
EOF
  chown root:soar /etc/soar/soar.env
  chmod 640 /etc/soar/soar.env
  echo "    generated new secrets"
else
  echo "    kept existing /etc/soar/soar.env"
fi

echo "==> granting scoped sudo"
cat > /etc/sudoers.d/soar <<'EOF'
soar ALL=(root) NOPASSWD: /usr/local/share/soar/playbooks/remediate_drift.sh
soar ALL=(root) NOPASSWD: /usr/local/share/soar/playbooks/remediate_certificate.sh
soar ALL=(root) NOPASSWD: /usr/local/share/soar/playbooks/reaudit.sh

# sudo's env_reset strips the alert context the daemon exports. Without
# this the certificate playbook receives no SOAR_CERTIFICATE_ID and exits 1
# on every alert, while the drift playbook merely logs 'rule=unset'.
Defaults:soar env_keep += "SOAR_TARGET_HOST SOAR_ALERT_RULE SOAR_SEVERITY SOAR_CERTIFICATE_ID SOAR_PRINCIPAL"
EOF
chmod 440 /etc/sudoers.d/soar
visudo -cf /etc/sudoers.d/soar >/dev/null

echo "==> installing service"
install -m 0644 "$SRC/systemd/soar-remediator.service" /etc/systemd/system/soar-remediator.service
touch /var/log/soar-remediation.log
chown soar:soar /var/log/soar-remediation.log
chmod 640 /var/log/soar-remediation.log

systemctl daemon-reload
systemctl enable --now soar-remediator.service

echo
echo "Installed. Set ES_PASSWORD in /etc/soar/soar.env, then:"
echo "   sudo systemctl restart soar-remediator"
echo
echo "Your webhook token (Kibana needs this):"
grep '^SOAR_TOKEN=' /etc/soar/soar.env | cut -d= -f2
echo
echo "Health check:"
echo "   curl -s http://127.0.0.1:8088/health"
