#!/usr/bin/env bash
set -euo pipefail

# Sentinel V3 — SaaS Platform Setup
# Run this once on your VPS to configure the central server.
# User accounts and API tokens are created via the web UI.

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

info()  { echo -e "${CYAN}[sentinel]${NC} $*"; }
ok()    { echo -e "${GREEN}[sentinel]${NC} $*"; }
err()   { echo -e "${RED}[sentinel]${NC} $*" >&2; }
fatal() { err "$@"; exit 1; }

if [ "$(id -u)" -ne 0 ]; then
    fatal "This setup must be run as root (try: sudo bash setup.sh)"
fi

echo ""
echo -e "${CYAN}${BOLD}  ╔═══════════════════════════════════════╗${NC}"
echo -e "${CYAN}${BOLD}  ║       Sentinel V3 Setup Wizard        ║${NC}"
echo -e "${CYAN}${BOLD}  ║      SaaS Security Monitoring         ║${NC}"
echo -e "${CYAN}${BOLD}  ╚═══════════════════════════════════════╝${NC}"
echo ""

prompt() {
    local varname="$1" prompt_text="$2" default="${3:-}"
    if [ -n "$default" ]; then
        echo -en "  ${prompt_text} ${DIM}[${default}]${NC}: "
    else
        echo -en "  ${prompt_text}: "
    fi
    read -r input
    eval "$varname=\"\${input:-$default}\""
}

echo -e "${BOLD}  Server Configuration${NC}"
echo -e "  ─────────────────────"
prompt PORT "Listen port" "8765"
prompt DB_PATH "Database path" "/var/lib/sentinel-central/sentinel.db"
echo ""

echo -e "${BOLD}  Email Notifications (optional)${NC}"
echo -e "  ──────────────────────────────"
prompt EMAIL_ENABLED "Enable email alerts? (true/false)" "false"

SMTP_HOST="smtp.gmail.com"
SMTP_PORT="587"
SMTP_USER=""
SMTP_PASSWORD=""
ALERT_TO=""

if [ "$EMAIL_ENABLED" = "true" ]; then
    prompt SMTP_HOST "SMTP host" "smtp.gmail.com"
    prompt SMTP_PORT "SMTP port" "587"
    prompt SMTP_USER "SMTP username" ""
    echo -en "  SMTP password: "
    read -rs SMTP_PASSWORD
    echo ""
    prompt ALERT_TO "Alert recipient email" ""
fi
echo ""

echo -e "${BOLD}  Slack Notifications (optional)${NC}"
echo -e "  ──────────────────────────────"
prompt SLACK_ENABLED "Enable Slack alerts? (true/false)" "false"

SLACK_WEBHOOK=""
if [ "$SLACK_ENABLED" = "true" ]; then
    prompt SLACK_WEBHOOK "Slack webhook URL" ""
fi
echo ""

info "Creating directories..."
mkdir -p "$(dirname "$DB_PATH")"
mkdir -p /etc/sentinel
mkdir -p /var/log/sentinel

info "Writing server config..."
cat > /etc/sentinel/server.conf << SERVERCONF
[server]
port = ${PORT}
db_path = ${DB_PATH}
offline_after = 120
session_ttl = 86400

[notifications]
email_enabled = ${EMAIL_ENABLED}
smtp_host = ${SMTP_HOST}
smtp_port = ${SMTP_PORT}
smtp_user = ${SMTP_USER}
smtp_password = ${SMTP_PASSWORD}
alert_to = ${ALERT_TO}
notify_offline = true
min_severity = high
slack_enabled = ${SLACK_ENABLED}
slack_webhook = ${SLACK_WEBHOOK}
SERVERCONF
chmod 600 /etc/sentinel/server.conf
ok "Config saved to /etc/sentinel/server.conf"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

info "Installing systemd service..."
cat > /etc/systemd/system/sentinel-central.service << SVCUNIT
[Unit]
Description=Sentinel V3 Central Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 ${SCRIPT_DIR}/central/server.py --config /etc/sentinel/server.conf
Restart=always
RestartSec=10
StandardOutput=append:/var/log/sentinel/server.log
StandardError=append:/var/log/sentinel/server.log
ProtectSystem=strict
ReadWritePaths=$(dirname "$DB_PATH") /var/log/sentinel /etc/sentinel

[Install]
WantedBy=multi-user.target
SVCUNIT

systemctl daemon-reload
systemctl enable sentinel-central
ok "systemd service installed"

SERVER_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo 'YOUR_IP')

echo ""
echo -e "${GREEN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}${BOLD}  Sentinel V3 Platform configured!${NC}"
echo -e "${GREEN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  ${BOLD}Config:${NC}     /etc/sentinel/server.conf"
echo -e "  ${BOLD}Database:${NC}   ${DB_PATH}"
echo ""
echo -e "  ${BOLD}Start the server:${NC}"
echo -e "    systemctl start sentinel-central"
echo ""
echo -e "  ${BOLD}Then open in your browser:${NC}"
echo -e "    ${CYAN}http://${SERVER_IP}:${PORT}/register${NC}"
echo ""
echo -e "  Create your organization account and start adding servers."
echo ""
