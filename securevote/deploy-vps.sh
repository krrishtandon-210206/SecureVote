#!/usr/bin/env bash
# One-shot install on Ubuntu/Debian WITHOUT Docker. Run from the unzipped folder:  sudo ./deploy-vps.sh
set -e
[ "$(id -u)" = 0 ] || { echo "Run with sudo"; exit 1; }
read -rp "Domain name that points at this server: " D
[ -n "$D" ] || { echo "A domain is required for HTTPS"; exit 1; }
PW=$(python3 -c "import secrets; print(secrets.token_urlsafe(18))")
apt-get update -y && apt-get install -y python3 python3-venv caddy
id securevote >/dev/null 2>&1 || useradd --system --home /opt/securevote securevote
mkdir -p /opt/securevote /var/lib/securevote
cp -r . /opt/securevote/
python3 -m venv /opt/securevote/venv
/opt/securevote/venv/bin/pip install -r /opt/securevote/requirements.txt
chown -R securevote /opt/securevote /var/lib/securevote
printf 'ADMIN_PASSWORD=%s\nSV_STATE=/var/lib/securevote/state.pkl\n' "$PW" > /etc/securevote.env
chmod 600 /etc/securevote.env; chown securevote /etc/securevote.env
cat > /etc/systemd/system/securevote.service <<UNIT
[Unit]
Description=SecureVote
After=network.target
[Service]
User=securevote
WorkingDirectory=/opt/securevote
EnvironmentFile=/etc/securevote.env
ExecStart=/opt/securevote/venv/bin/uvicorn main:app --host 127.0.0.1 --port 8000 --workers 1
Restart=always
[Install]
WantedBy=multi-user.target
UNIT
echo "DOMAIN=$D" > /etc/caddy/caddy.env
mkdir -p /etc/systemd/system/caddy.service.d
printf '[Service]\nEnvironmentFile=/etc/caddy/caddy.env\n' > /etc/systemd/system/caddy.service.d/env.conf
cp Caddyfile.host /etc/caddy/Caddyfile
systemctl daemon-reload
systemctl enable --now securevote
systemctl restart caddy
echo
echo "Done.  Site: https://$D     Admin password: $PW"
