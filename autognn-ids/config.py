"""
AutoGNN-IDS Configuration
Centralized settings for the entire system.
"""
import os
from pathlib import Path

# ─── Base Paths ───────────────────────────────────────────────
BASE_DIR = Path(__file__).parent.resolve()
DATA_DIR = BASE_DIR / "data"
MODEL_DIR = BASE_DIR / "models"
DB_DIR = BASE_DIR / "db"

# Create dirs
for d in [DATA_DIR, MODEL_DIR, DB_DIR]:
    d.mkdir(parents=True, exist_ok=True)

# ─── Log File Paths (Linux Server Defaults) ──────────────────
LOG_PATHS = {
    "syslog": os.getenv("AUTOGNN_SYSLOG_PATH", "/var/log/syslog"),
    "syslog_alt": "/var/log/messages",  # RHEL/CentOS
    "arp": "/proc/net/arp",
    "lldp_log": os.getenv("AUTOGNN_LLDP_LOG", "/var/log/lldpd.log"),
    "lldp_export": os.getenv("AUTOGNN_LLDP_EXPORT", "/tmp/lldp_neighbors.json"),
    "netflow_dir": os.getenv("AUTOGNN_NETFLOW_DIR", "/var/log/netflow/"),
    # DNS query logs
    "dns_query_log": os.getenv("AUTOGNN_DNS_LOG", "/var/log/named/query.log"),
    "dns_dnsmasq_log": "/var/log/dnsmasq.log",
    "dns_unbound_log": "/var/log/unbound/unbound.log",
    # DHCP lease files and logs
    "dhcp_leases_isc": os.getenv("AUTOGNN_DHCP_LEASES", "/var/lib/dhcp/dhcpd.leases"),
    "dhcp_leases_dnsmasq": "/var/lib/misc/dnsmasq.leases",
    "dhcp_log": os.getenv("AUTOGNN_DHCP_LOG", "/var/log/dhcpd.log"),
    "dhcp_log_alt": "/var/log/dnsmasq.log",  # dnsmasq shared log
}

# ─── Database ─────────────────────────────────────────────────
SQLITE_DB_PATH = DB_DIR / "autognn_ids.db"

# ─── Bridge Mode Detection ────────────────────────────────────
def _is_bridge_mode() -> bool:
    """Auto-detect if running in bridge mode (br0 interface exists)."""
    return Path("/sys/class/net/br0").exists()

BRIDGE_MODE = _is_bridge_mode()

# ─── Network Discovery ───────────────────────────────────────
DISCOVERY_CONFIG = {
    # Bridge mode configuration
    "bridge_mode": BRIDGE_MODE,
    "sniff_interfaces": ["br0", "ens4", "ens5"],  # Interfaces to sniff on
    "sniff_timeout": 30,                           # seconds per snapshot for sniffing

    # Per-module sniffing flags (auto-enable in bridge mode)
    "arp_sniff_enabled": BRIDGE_MODE,
    "dns_bridge_sniff": BRIDGE_MODE,
    "dhcp_bridge_sniff": BRIDGE_MODE,
    "netflow_sniff_enabled": BRIDGE_MODE,
    "lldp_sniff_enabled": BRIDGE_MODE,
    "syslog_sniff_enabled": BRIDGE_MODE,

    # Legacy log-based discovery intervals (fallback when sniffing unavailable)
    "arp_poll_interval": 10,       # seconds between ARP table reads
    "syslog_tail_interval": 1,     # seconds between syslog checks
    "netflow_watch_interval": 5,   # seconds between netflow dir scans
    "lldp_poll_interval": 30,      # seconds between LLDP exports
    "dns_poll_interval": 5,        # seconds between DNS log checks
    "dns_sniff_timeout": 10,       # seconds for passive DNS sniff
    "dhcp_poll_interval": 15,      # seconds between DHCP lease checks
    "dhcp_sniff_timeout": 30,      # seconds for passive DHCP sniff
    "snapshot_interval": 30,       # seconds per topology snapshot for GNN
    "device_timeout": 3600,        # seconds before a device is inactive
}

# ─── OUI Vendor Lookup (Top common vendors) ──────────────────
OUI_DATABASE = {
    "00:1A:2B": "Cisco", "00:50:56": "VMware", "00:0C:29": "VMware",
    "00:1C:42": "Parallels", "08:00:27": "VirtualBox", "52:54:00": "QEMU/KVM",
    "00:25:90": "Super Micro", "D8:9E:F3": "Dell", "EC:F4:BB": "Dell",
    "70:10:6F": "HP", "3C:D9:2B": "HP", "00:17:A4": "Juniper",
    "28:C6:8E": "Netgear", "A4:2B:B0": "TP-Link", "DC:A6:32": "Raspberry Pi",
    "B8:27:EB": "Raspberry Pi", "F8:1A:67": "TP-Link", "00:1B:44": "SanDisk",
}

# ─── GNN Model Hyperparameters ────────────────────────────────
MODEL_CONFIG = {
    "node_feature_dim": 12,
    "edge_feature_dim": 8,
    "gat_hidden_dim": 64,
    "gat_heads": 4,
    "sage_hidden_dim": 32,
    "output_dim": 1,
    "dropout": 0.3,
    "learning_rate": 0.001,
    "weight_decay": 1e-5,
    "epochs": 100,
    "batch_size": 32,
    "reconstruction_weight": 0.5,
    "feature_recon_weight": 0.3,
    "regularization_weight": 0.2,
}

# ─── Anomaly Detection Thresholds ─────────────────────────────
THRESHOLD_CONFIG = {
    "sigma_multiplier": 3.0,         # 3-sigma for threshold
    "isolation_forest_contamination": 0.05,
    "alert_levels": {
        "normal": (0.0, 0.3),
        "warning": (0.3, 0.7),
        "critical": (0.7, 1.0),
    },
    "pulsing_threshold": 0.95,       # nodes above this pulse in UI
}

# ─── Attack Classification ────────────────────────────────────
ATTACK_TYPES = {
    "scan": {
        "min_unique_dests": 10,
        "min_port_count": 20,
        "max_bytes_per_conn": 200,
    },
    "lateral_movement": {
        "min_new_neighbor_ratio": 0.5,
        "min_conn_freq": 50,
    },
    "exfiltration": {
        "min_bytes_out_ratio": 5.0,
        "min_duration": 300,
    },
    "c2": {
        "beacon_interval_std_max": 5.0,
        "min_conn_freq": 100,
    },
}

# ─── API Settings ─────────────────────────────────────────────
API_CONFIG = {
    "host": os.getenv("AUTOGNN_API_HOST", "0.0.0.0"),
    "port": int(os.getenv("AUTOGNN_API_PORT", "8000")),
}

# ─── Dashboard Settings ──────────────────────────────────────
DASHBOARD_CONFIG = {
    "refresh_interval": 30,          # auto-refresh seconds
    "max_graph_nodes": 500,          # max nodes to render
    "api_url": os.getenv("AUTOGNN_API_URL", "http://localhost:8000"),
}



# ─── Training Control ────────────────────────────────────────
TRAINING_CONFIG = {
    # Minimum baselines before auto-train is allowed
    "min_baseline_snapshots": int(os.getenv("AUTOGNN_MIN_BASELINES", "10")),
    # Auto-train after reaching this many snapshots (0 = never auto-train)
    "auto_train_threshold": int(os.getenv("AUTOGNN_AUTO_TRAIN", "0")),
    # Online learning: auto-adapt every N detection cycles (0 = disabled)
    "online_update_interval": int(os.getenv("AUTOGNN_ONLINE_UPDATE", "100")),
    # Online update epochs (fewer = faster, more = better adaptation)
    "online_update_epochs": 5,
}

# ─── System State ─────────────────────────────────────────────
# Modes: "baseline" | "training" | "detection" | "stopped"
STATE_FILE = BASE_DIR / "autognn_state.json"
