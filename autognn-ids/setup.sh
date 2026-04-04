#!/bin/bash
# AutoGNN-IDS Setup Script
# Run this on your Linux server to set up the tool.

set -e

echo "══════════════════════════════════════════════════════"
echo "  AutoGNN-IDS Setup"
echo "  GNN-Based Network Intrusion Detection System"
echo "══════════════════════════════════════════════════════"

INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$INSTALL_DIR/.venv"
SERVICE_NAME="autognn-ids"

# ─── Check Python ─────────────────────────────────────────
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
pip install -r "$INSTALL_DIR/requirements.txt" -q
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
if [ "\$1" = "--install-service" ]; then
    sudo cp "$INSTALL_DIR/autognn-ids.service" /etc/systemd/system/
    sudo sed -i "s|/opt/autognn-ids|$INSTALL_DIR|g" /etc/systemd/system/autognn-ids.service
    sudo systemctl daemon-reload
    sudo systemctl enable autognn-ids
    echo "  Service installed. Start with: sudo systemctl start autognn-ids"
else
    echo "  Skipped. Run with --install-service to install systemd service."
fi

echo ""
echo "══════════════════════════════════════════════════════"
echo "  Setup complete!"
echo ""
echo "  Quick start:"
echo "    source $VENV_DIR/bin/activate"
echo ""
echo "    # Start API server:"
echo "    python -m uvicorn api.fastapi_server:app --host 0.0.0.0 --port 8000"
echo ""
echo "    # Start dashboard (in another terminal):"
echo "    streamlit run dashboard/streamlit_app.py --server.port 8501"
echo ""
echo "    # Use sample data (default):"
echo "    export AUTOGNN_USE_SAMPLE=true"
echo ""
echo "    # Use real server logs:"
echo "    export AUTOGNN_USE_SAMPLE=false"
echo "    export AUTOGNN_SYSLOG_PATH=/var/log/syslog"
echo "    export AUTOGNN_NETFLOW_DIR=/var/log/netflow/"
echo "══════════════════════════════════════════════════════"
