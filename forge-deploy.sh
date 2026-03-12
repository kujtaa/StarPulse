#!/usr/bin/env bash
set -euo pipefail

# Sentinel V3 — Laravel Forge Deploy Script
# Paste this into Forge's "Deploy Script" section for your site.
# Forge variables available: $FORGE_SITE_PATH, $FORGE_SERVER_ID, etc.

SITE_PATH="${FORGE_SITE_PATH:-/home/forge/sentinel}"
CONF_PATH="/etc/sentinel/server.conf"
DB_DIR="/var/lib/sentinel-central"

cd "$SITE_PATH"

git pull origin main

# Create directories (first deploy only)
sudo mkdir -p /etc/sentinel "$DB_DIR" /var/log/sentinel
sudo chown forge:forge "$DB_DIR" /var/log/sentinel

# Generate config if it doesn't exist yet
if [ ! -f "$CONF_PATH" ]; then
    echo "[sentinel] Creating initial server config..."
    sudo tee "$CONF_PATH" > /dev/null << 'CONF'
[server]
port = 8765
db_path = /var/lib/sentinel-central/sentinel.db
offline_after = 120
session_ttl = 86400

[notifications]
email_enabled = false
smtp_host = smtp.gmail.com
smtp_port = 587
smtp_user =
smtp_password =
alert_to =
notify_offline = true
min_severity = high
slack_enabled = false
slack_webhook =
CONF
    sudo chmod 600 "$CONF_PATH"
    sudo chown forge:forge "$CONF_PATH"
    echo "[sentinel] Config created at $CONF_PATH"
fi

# Install/update systemd service
sudo tee /etc/systemd/system/sentinel-central.service > /dev/null << UNIT
[Unit]
Description=Sentinel V3 Central Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=forge
Group=forge
WorkingDirectory=$SITE_PATH
ExecStart=/usr/bin/python3 $SITE_PATH/central/server.py --config $CONF_PATH
Restart=always
RestartSec=5
StandardOutput=append:/var/log/sentinel/server.log
StandardError=append:/var/log/sentinel/server.log
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
UNIT

sudo systemctl daemon-reload
sudo systemctl enable sentinel-central
sudo systemctl restart sentinel-central

sleep 2

if sudo systemctl is-active --quiet sentinel-central; then
    echo "[sentinel] Server is running"
else
    echo "[sentinel] WARNING: Server failed to start. Check logs:"
    echo "  sudo journalctl -u sentinel-central -n 30"
fi
