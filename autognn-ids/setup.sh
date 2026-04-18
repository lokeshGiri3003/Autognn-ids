#!/bin/bash
# AutoGNN-IDS Setup Script
# Run this on your Linux server to set up the tool.
#
# Usage:
#   sudo bash setup.sh                      # Standard setup
#   sudo bash setup.sh --install-service    # Install as systemd service

set -e

echo "══════════════════════════════════════════════════════"
echo "  AutoGNN-IDS Setup"
echo "  GNN-Based Network Intrusion Detection System"
echo "══════════════════════════════════════════════════════"

INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$INSTALL_DIR/.venv"
SERVICE_NAME="autognn-ids"

# Parse arguments
INSTALL_SERVICE=false

# NOTE: Automated bridge setup has been removed for safety and portability.
# Configure bridging manually on your host after setup if required.
#
# Manual bridge setup example (replace eth0/eth1 with your interfaces):
#   sudo apt update && sudo apt install -y bridge-utils iptables-persistent
#   sudo ip link add name br0 type bridge
#   sudo ip link set eth0 master br0
#   sudo ip link set eth1 master br0
#   sudo ip link set br0 up
#   sudo iptables -A FORWARD -j LOG --log-prefix "iptables: "
#   sudo iptables-save | sudo tee /etc/iptables/rules.v4 > /dev/null
#
# Persist the bridge with your distro networking stack (netplan, ifupdown,
# NetworkManager, or systemd-networkd).

show_bridge_instructions() {
    echo "  Manual bridge setup example (replace eth0/eth1 with your interfaces):"
    echo ""
    echo "    sudo apt update && sudo apt install -y bridge-utils iptables-persistent"
    echo "    sudo ip link add name br0 type bridge"
    echo "    sudo ip link set eth0 master br0"
    echo "    sudo ip link set eth1 master br0"
    echo "    sudo ip link set br0 up"
    echo "    sudo iptables -A FORWARD -j LOG --log-prefix \"iptables: \""
    echo "    sudo iptables-save | sudo tee /etc/iptables/rules.v4 > /dev/null"
    echo ""
    echo "  Persist bridge config using netplan, ifupdown, NetworkManager,"
    echo "  or systemd-networkd for your distro."
}

# Function to display help
show_help() {
    echo ""
    echo "══════════════════════════════════════════════════════"
    echo "  AutoGNN-IDS Setup Script - Help"
    echo "══════════════════════════════════════════════════════"
    echo ""
    echo "DESCRIPTION:"
    echo "  Automated setup script for AutoGNN-IDS on a Linux server."
    echo "  Installs Python dependencies, creates virtual environment,"
    echo "  initializes database, and provides guidance for manual bridge"
    echo "  configuration for network-wide intrusion detection."
    echo ""
    echo "USAGE:"
    echo "  sudo bash setup.sh [OPTIONS]"
    echo ""
    echo "OPTIONS:"
    echo "  -h, --help                Show this help message and exit"
    echo "  --install-service         Install as systemd service for auto-start on boot"
    echo ""
    echo "EXAMPLES:"
    echo ""
    echo "  1. Standard setup (no bridge):"
    echo "     sudo bash setup.sh"
    echo ""
    echo "  2. Setup and install as systemd service:"
    echo "     sudo bash setup.sh --install-service"
    echo ""
    echo "REQUIREMENTS:"
    echo "  • Root privileges (use sudo)"
    echo "  • Python 3.10+"
    echo ""
    echo "WHAT IT DOES:"
    echo "  ✓ Checks Python version (3.10+)"
    echo "  ✓ Creates isolated Python virtual environment (.venv/)"
    echo "  ✓ Installs required dependencies (PyTorch, FastAPI, Scapy, etc.)"
    echo "  ✓ Initializes SQLite database with schema"
    echo "  ✓ (Optional) Installs systemd service for auto-start"
    echo "  ⓘ Bridge configuration is now manual (instructions in setup.sh comments)"
    echo ""
    echo "NEXT STEPS (after setup):"
    echo "  1. Activate virtual environment:"
    echo "     source ./.venv/bin/activate"
    echo "  2. Collect baseline (1-24 hours of normal traffic):"
    echo "     python autognn_ctl.py baseline start"
    echo "  3. Train GNN model:"
    echo "     python autognn_ctl.py train"
    echo "  4. Start detection:"
    echo "     python autognn_ctl.py detect"
    echo "  5. Access dashboard:"
    echo "     streamlit run dashboard/streamlit_app.py --server.port 8501"
    echo ""
    echo "TROUBLESHOOTING:"
    echo "  • Bridge is manual: Check setup.sh comments for bridge steps"
    echo "  • If permission denied: Make sure you use 'sudo'"
    echo "  • For help with commands after setup: python autognn_ctl.py --help"
    echo ""
    show_bridge_instructions
    echo ""
    echo "══════════════════════════════════════════════════════"
    echo ""
}

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_help
            exit 0
            ;;
        --install-service)
            INSTALL_SERVICE=true
            shift
            ;;
        *)
            echo "Unknown option: $1"
            echo ""
            echo "Usage: sudo bash setup.sh [OPTIONS]"
            echo "For help: sudo bash setup.sh --help"
            echo ""
            exit 1
            ;;
    esac
done

# ─── Check if running as root ────────────────────────────
if [ "$EUID" -ne 0 ]; then
    echo "ERROR: This script must be run as root (use sudo)"
    exit 1
fi

echo ""
echo "[1/5] Checking Python 3.11+..."
if command -v python3.11 &> /dev/null; then
    PYTHON=python3.11
elif command -v python3 &> /dev/null; then
    PY_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
    PY_MAJOR=$(echo $PY_VERSION | cut -d. -f1)
    PY_MINOR=$(echo $PY_VERSION | cut -d. -f2)
    if [ "$PY_MAJOR" -ge 3 ] && [ "$PY_MINOR" -ge 10 ]; then
        PYTHON=python3
    else
        echo "ERROR: Python 3.10+ required, found $PY_VERSION"
        exit 1
    fi
else
    echo "ERROR: Python 3 not found. Install python3.11 first."
    exit 1
fi
echo "  Found: $($PYTHON --version)"

# ─── Create Virtual Environment ──────────────────────────
echo ""
echo "[2/5] Creating virtual environment..."
$PYTHON -m venv "$VENV_DIR"
source "$VENV_DIR/bin/activate"
pip install --upgrade pip setuptools wheel -q

# ─── Install Dependencies ────────────────────────────────
echo ""
echo "[3/5] Installing dependencies..."
pip install -r "$INSTALL_DIR/requirements.txt" -v
echo "  Dependencies installed."

# ─── Initialize Database ─────────────────────────────────
echo ""
echo "[4/5] Initializing SQLite database..."
mkdir -p "$INSTALL_DIR/db"
mkdir -p "$INSTALL_DIR/models"
$PYTHON -c "
import sqlite3, os
db_path = os.path.join('$INSTALL_DIR', 'db', 'autognn_ids.db')
conn = sqlite3.connect(db_path)
c = conn.cursor()

c.execute('''CREATE TABLE IF NOT EXISTS devices (
    device_id TEXT PRIMARY KEY,
    ip TEXT,
    mac TEXT,
    hostname TEXT,
    vendor TEXT,
    device_type TEXT,
    anomaly_score REAL DEFAULT 0.0,
    first_seen TEXT,
    last_seen TEXT,
    is_active INTEGER DEFAULT 1
)''')

c.execute('''CREATE TABLE IF NOT EXISTS connections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    src_device TEXT,
    dst_device TEXT,
    protocol TEXT,
    bytes INTEGER,
    packets INTEGER,
    src_port INTEGER,
    dst_port INTEGER,
    first_seen TEXT,
    last_seen TEXT,
    anomaly_score REAL DEFAULT 0.0,
    FOREIGN KEY (src_device) REFERENCES devices(device_id),
    FOREIGN KEY (dst_device) REFERENCES devices(device_id)
)''')

c.execute('''CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    device_id TEXT,
    alert_type TEXT,
    severity TEXT,
    score REAL,
    description TEXT,
    attack_path TEXT,
    resolved INTEGER DEFAULT 0,
    FOREIGN KEY (device_id) REFERENCES devices(device_id)
)''')

c.execute('''CREATE TABLE IF NOT EXISTS traffic_stats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    device_id TEXT,
    bytes_in INTEGER,
    bytes_out INTEGER,
    packets_in INTEGER,
    packets_out INTEGER,
    unique_dests INTEGER,
    port_count INTEGER,
    conn_count INTEGER,
    FOREIGN KEY (device_id) REFERENCES devices(device_id)
)''')

c.execute('''CREATE TABLE IF NOT EXISTS model_state (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    model_path TEXT,
    training_epochs INTEGER,
    loss REAL,
    threshold REAL,
    notes TEXT
)''')

conn.commit()
conn.close()
print('  Database initialized: ' + db_path)
"

# ─── Install systemd service (optional) ──────────────────
echo ""
echo "[5/5] systemd service setup..."
if [ "$INSTALL_SERVICE" = true ]; then
    if [ ! -f "$INSTALL_DIR/autognn-ids.service" ]; then
        echo "  ⚠ Service file not found at $INSTALL_DIR/autognn-ids.service"
        echo "  Creating default service file..."

        cat > "$INSTALL_DIR/autognn-ids.service" << 'EOF'
[Unit]
Description=AutoGNN-IDS (Graph Neural Network Intrusion Detection)
After=network.target
Wants=network.target

[Service]
Type=simple
User=root
WorkingDirectory=__INSTALL_DIR__
ExecStart=/usr/bin/python3 __INSTALL_DIR__/main.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=autognn-ids

[Install]
WantedBy=multi-user.target
EOF
    fi

    cp "$INSTALL_DIR/autognn-ids.service" /etc/systemd/system/
    sed -i "s|__INSTALL_DIR__|$INSTALL_DIR|g" /etc/systemd/system/autognn-ids.service
    systemctl daemon-reload
    systemctl enable autognn-ids
    echo "  ✓ Service installed and enabled"
    echo ""
    echo "  To start the service now:"
    echo "    sudo systemctl start autognn-ids"
    echo ""
    echo "  To view logs:"
    echo "    sudo journalctl -u autognn-ids -f"
else
    echo "  ⓘ Skipped (optional). To install later:"
    echo "    sudo bash setup.sh --install-service"
fi

echo ""
echo "══════════════════════════════════════════════════════"
echo "  ✅ Setup Complete!"
echo "══════════════════════════════════════════════════════"
echo ""

if [ "$INSTALL_SERVICE" = true ]; then
    echo "  🚀 Systemd Service Installed"
    echo "    Status: Enabled for auto-start on boot"
    echo "    Start: sudo systemctl start autognn-ids"
    echo ""
fi

echo "  📋 Next Steps:"
echo ""
echo "  1️⃣  Activate virtual environment:"
echo "     source $VENV_DIR/bin/activate"
echo ""
echo "  2️⃣  Use sample data (for testing):"
echo "     export AUTOGNN_USE_SAMPLE=true"
echo "     python autognn_ctl.py baseline start"
echo ""
echo "  3️⃣  For real network monitoring, configure bridge manually"
echo "     (see bridge instructions in setup.sh comments near the top)."
echo ""
show_bridge_instructions
echo ""

echo "  📚 Commands Reference:"
echo ""
echo "     # Baseline collection (1-24 hours):"
echo "     python autognn_ctl.py baseline start"
echo "     python autognn_ctl.py baseline stop"
echo ""
echo "     # Model training:"
echo "     python autognn_ctl.py train [model_name]"
echo ""
echo "     # Start detection (continuous):"
echo "     python autognn_ctl.py detect"
echo ""
echo "     # Check system status:"
echo "     python autognn_ctl.py status"
echo ""
echo "     # View alerts:"
echo "     python autognn_ctl.py alerts"
echo ""
echo "     # Model management:"
echo "     python autognn_ctl.py model list"
echo "     python autognn_ctl.py model switch <name>"
echo ""
echo "  🔗 API Documentation:"
echo "     http://localhost:8000/docs"
echo ""
echo "══════════════════════════════════════════════════════"
