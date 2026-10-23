#!/usr/bin/env bash
# Creates the .env file (domain + a random admin password). Run once, before docker compose.
set -e
read -rp "Domain name that points at this server (press Enter to test on localhost): " D
D=${D:-localhost}
PW=$(python3 -c "import secrets; print(secrets.token_urlsafe(18))")
printf 'DOMAIN=%s\nADMIN_PASSWORD=%s\n' "$D" "$PW" > .env
chmod 600 .env
echo
echo "Created .env"
echo "  Site URL:        https://$D"
echo "  Admin password:  $PW     (also stored in .env - keep it secret)"
