#!/usr/bin/env bash
set -euo pipefail

# Sentinel V3 — Universal Agent Installer
# Usage: curl -sSL http://YOUR_VPS:8765/install.sh | \
#        SENTINEL_SERVER=http://YOUR_VPS:8765 SENTINEL_TOKEN=token bash

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

info()  { echo -e "${CYAN}[sentinel]${NC} $*"; }
ok()    { echo -e "${GREEN}[sentinel]${NC} $*"; }
err()   { echo -e "${RED}[sentinel]${NC} $*" >&2; }
fatal() { err "$@"; exit 1; }

if [ "$(id -u)" -ne 0 ]; then
    fatal "This installer must be run as root (try: sudo bash)"
fi

if [ -z "${SENTINEL_SERVER:-}" ]; then
    fatal "SENTINEL_SERVER is not set. Example: SENTINEL_SERVER=http://your-vps:8765"
fi

if [ -z "${SENTINEL_TOKEN:-}" ]; then
    fatal "SENTINEL_TOKEN is not set. Get it from your Sentinel central server config."
fi

SENTINEL_SERVER="${SENTINEL_SERVER%/}"

info "Sentinel V3 Agent Installer"
info "Central server: ${SENTINEL_SERVER}"
echo ""

detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS_NAME="${ID:-unknown}"
        OS_VERSION="${VERSION_ID:-unknown}"
    elif [ -f /etc/redhat-release ]; then
        OS_NAME="rhel"
        OS_VERSION="unknown"
    else
        OS_NAME="unknown"
        OS_VERSION="unknown"
    fi
    info "Detected OS: ${OS_NAME} ${OS_VERSION}"
}

detect_pkg_manager() {
    if command -v apt-get >/dev/null 2>&1; then
        PKG_MGR="apt"
    elif command -v dnf >/dev/null 2>&1; then
        PKG_MGR="dnf"
    elif command -v yum >/dev/null 2>&1; then
        PKG_MGR="yum"
    elif command -v apk >/dev/null 2>&1; then
        PKG_MGR="apk"
    elif command -v pacman >/dev/null 2>&1; then
        PKG_MGR="pacman"
    else
        PKG_MGR="unknown"
    fi
}

install_python3() {
    if command -v python3 >/dev/null 2>&1; then
        PYTHON_VER=$(python3 -c 'import sys; print("{}.{}".format(sys.version_info.major, sys.version_info.minor))')
        info "Python ${PYTHON_VER} already installed"
        return
    fi

    info "Installing Python 3..."
    case "${PKG_MGR}" in
        apt)
            apt-get update -qq
            apt-get install -y -qq python3 >/dev/null 2>&1
            ;;
        dnf)
            dnf install -y -q python3 >/dev/null 2>&1
            ;;
        yum)
            yum install -y -q python3 >/dev/null 2>&1
            ;;
        apk)
            apk add --quiet python3 >/dev/null 2>&1
            ;;
        pacman)
            pacman -Sy --noconfirm python >/dev/null 2>&1
            ;;
        *)
            fatal "Cannot install Python 3: unknown package manager. Install manually and re-run."
            ;;
    esac

    if ! command -v python3 >/dev/null 2>&1; then
        fatal "Failed to install Python 3"
    fi
    ok "Python 3 installed"
}

create_directories() {
    info "Creating directories..."
    mkdir -p /opt/sentinel/agent
    mkdir -p /etc/sentinel
    mkdir -p /var/log/sentinel
    mkdir -p /var/lib/sentinel
    ok "Directories created"
}

download_agent() {
    info "Downloading agent from ${SENTINEL_SERVER}/agent.py ..."

    if command -v curl >/dev/null 2>&1; then
        curl -sSL "${SENTINEL_SERVER}/agent.py" -o /opt/sentinel/agent/agent.py
    elif command -v wget >/dev/null 2>&1; then
        wget -q "${SENTINEL_SERVER}/agent.py" -O /opt/sentinel/agent/agent.py
    else
        python3 -c "
import urllib.request, sys
try:
    urllib.request.urlretrieve('${SENTINEL_SERVER}/agent.py', '/opt/sentinel/agent/agent.py')
except Exception as e:
    print('Download failed: {}'.format(e), file=sys.stderr)
    sys.exit(1)
"
    fi

    if [ ! -s /opt/sentinel/agent/agent.py ]; then
        fatal "Failed to download agent.py"
    fi
    chmod 755 /opt/sentinel/agent/agent.py
    ok "Agent downloaded"
}

generate_agent_id() {
    HOSTNAME_VAL=$(hostname)

    if [ -f /etc/machine-id ]; then
        MACHINE_ID=$(cat /etc/machine-id)
    elif [ -f /var/lib/dbus/machine-id ]; then
        MACHINE_ID=$(cat /var/lib/dbus/machine-id)
    else
        MACHINE_ID=$(hostname | sha256sum | awk '{print $1}')
    fi

    RAW_HASH=$(echo -n "${HOSTNAME_VAL}${MACHINE_ID}" | sha256sum | awk '{print $1}')
    AGENT_ID="${RAW_HASH:0:8}-${RAW_HASH:8:4}-${RAW_HASH:12:4}-${RAW_HASH:16:4}-${RAW_HASH:20:12}"

    info "Agent ID: ${AGENT_ID}"
}

write_config() {
    info "Writing agent config..."
    cat > /etc/sentinel/agent.conf << AGENTCONF
[agent]
server_url = ${SENTINEL_SERVER}
token = ${SENTINEL_TOKEN}
scan_interval = 30
push_interval = 30
agent_id = ${AGENT_ID}
tags = ${SENTINEL_TAGS:-}

[file_integrity]
enabled = true
watch_dirs = /etc,/usr/bin,/usr/sbin,/bin,/sbin
suspicious_dirs = /tmp,/var/tmp,/dev/shm
suspicious_extensions = .sh,.py,.pl,.php,.so,.elf,.bin
baseline_file = /var/lib/sentinel/baseline.json

[crypto_mining]
enabled = true
cpu_threshold_percent = 80
sustained_seconds = 60
known_miners = xmrig,xmr-stak,minerd,cpuminer,cgminer,bfgminer,ethminer,t-rex,gminer,nbminer,lolminer,phoenixminer
mining_ports = 3333,4444,5555,7777,8888,9999,14444,45700,3032
mining_domains = moneroocean,pool.supportxmr,xmrig.com,c3pool,2miners,nanopool,f2pool,ethermine,flypool,hiveon
check_cron = true

[http_anomaly]
enabled = true
log_paths = /var/log/nginx/access.log,/var/log/apache2/access.log,/var/log/httpd/access_log
threshold_404 = 50
threshold_403 = 30
threshold_500 = 20
threshold_same_ip = 100

[network]
enabled = true
suspicious_ports = 4444,5555,6666,7777,1337,31337,12345,54321,9001,6667
check_dns = true
alert_on_new_listening_ports = true

[resource]
enabled = true
ram_threshold = 50
cpu_threshold = 50
disk_threshold = 50
AGENTCONF
    chmod 600 /etc/sentinel/agent.conf
    ok "Config written to /etc/sentinel/agent.conf"
}

build_baseline() {
    info "Building file integrity baseline (this may take a moment)..."
    python3 /opt/sentinel/agent/agent.py --config /etc/sentinel/agent.conf --baseline || {
        err "Baseline build failed (non-fatal, will retry on first scan)"
    }
    ok "Baseline complete"
}

install_systemd_service() {
    if ! command -v systemctl >/dev/null 2>&1; then
        return 1
    fi

    info "Installing systemd service..."
    cat > /etc/systemd/system/sentinel-agent.service << 'SERVICEUNIT'
[Unit]
Description=Sentinel V3 Security Monitoring Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/sentinel/agent/agent.py --config /etc/sentinel/agent.conf
Restart=always
RestartSec=10
StandardOutput=append:/var/log/sentinel/agent.log
StandardError=append:/var/log/sentinel/agent.log
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=/var/lib/sentinel /var/log/sentinel /etc/sentinel

[Install]
WantedBy=multi-user.target
SERVICEUNIT

    systemctl daemon-reload
    systemctl enable sentinel-agent
    systemctl start sentinel-agent

    sleep 2
    if systemctl is-active --quiet sentinel-agent; then
        ok "sentinel-agent service is running"
        return 0
    else
        err "Service failed to start, check: journalctl -u sentinel-agent"
        return 1
    fi
}

install_initd_service() {
    info "systemd not found, falling back to init.d..."
    cat > /etc/init.d/sentinel-agent << 'INITSCRIPT'
#!/bin/sh
### BEGIN INIT INFO
# Provides:          sentinel-agent
# Required-Start:    $network $remote_fs
# Required-Stop:     $network $remote_fs
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Description:       Sentinel V3 Security Monitoring Agent
### END INIT INFO

PIDFILE=/var/run/sentinel-agent.pid
AGENT=/opt/sentinel/agent/agent.py
CONFIG=/etc/sentinel/agent.conf
LOG=/var/log/sentinel/agent.log

case "$1" in
    start)
        echo "Starting sentinel-agent..."
        nohup python3 "$AGENT" --config "$CONFIG" >> "$LOG" 2>&1 &
        echo $! > "$PIDFILE"
        ;;
    stop)
        echo "Stopping sentinel-agent..."
        if [ -f "$PIDFILE" ]; then
            kill "$(cat "$PIDFILE")" 2>/dev/null
            rm -f "$PIDFILE"
        fi
        ;;
    restart)
        $0 stop
        sleep 2
        $0 start
        ;;
    status)
        if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
            echo "sentinel-agent is running (PID $(cat "$PIDFILE"))"
        else
            echo "sentinel-agent is not running"
        fi
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status}"
        exit 1
        ;;
esac
INITSCRIPT
    chmod 755 /etc/init.d/sentinel-agent

    if command -v update-rc.d >/dev/null 2>&1; then
        update-rc.d sentinel-agent defaults
    elif command -v chkconfig >/dev/null 2>&1; then
        chkconfig --add sentinel-agent
        chkconfig sentinel-agent on
    fi

    /etc/init.d/sentinel-agent start
    ok "sentinel-agent started via init.d"
}

main() {
    detect_os
    detect_pkg_manager
    install_python3
    create_directories
    download_agent
    generate_agent_id
    write_config
    build_baseline

    if ! install_systemd_service; then
        install_initd_service
    fi

    echo ""
    echo -e "${GREEN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN}${BOLD}  Sentinel V3 Agent installed successfully!${NC}"
    echo -e "${GREEN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo -e "  Agent ID:  ${CYAN}${AGENT_ID}${NC}"
    echo -e "  Config:    /etc/sentinel/agent.conf"
    echo -e "  Logs:      /var/log/sentinel/agent.log"
    echo -e "  Service:   systemctl status sentinel-agent"
    echo ""
    echo -e "  This server should now appear on your dashboard at:"
    echo -e "  ${CYAN}${SENTINEL_SERVER}${NC}"
    echo ""
}

main "$@"
