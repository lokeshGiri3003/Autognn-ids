"""
LLDP/CDP Parser
Parses LLDP neighbor data from log files, lldpcli JSON exports, or sample data.
Builds switch-level topology (physical layer discovery).
"""
import json
import re
import logging
from pathlib import Path
from datetime import datetime
from typing import Optional

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from config import LOG_PATHS, SAMPLE_DATA_DIR, USE_SAMPLE_DATA

logger = logging.getLogger("autognn.lldp")


class LLDPParser:
    """Parse LLDP/CDP neighbor information to discover network topology."""

    def __init__(self):
        self.neighbors: list[dict] = []
        self.devices: dict[str, dict] = {}
        self.links: list[dict] = []

    def parse_sample_data(self) -> list[dict]:
        """Load from sample JSON data."""
        sample_file = SAMPLE_DATA_DIR / "lldp_captures.json"
        if not sample_file.exists():
            logger.warning(f"Sample LLDP data not found: {sample_file}")
            return []

        with open(sample_file) as f:
            self.neighbors = json.load(f)

        logger.info(f"Loaded {len(self.neighbors)} LLDP neighbor records from sample data")
        self._process_neighbors()
        return self.neighbors

    def parse_lldpcli_json(self, filepath: Optional[str] = None) -> list[dict]:
        """
        Parse output of: lldpcli show neighbors details -f json
        Typical path: /tmp/lldp_neighbors.json or configured path.
        """
        path = Path(filepath) if filepath else Path(LOG_PATHS["lldp_export"])
        if not path.exists():
            logger.warning(f"LLDP export not found: {path}")
            return []

        with open(path) as f:
            data = json.load(f)

        # Parse lldpcli JSON format
        neighbors = []
        lldp_data = data.get("lldp", {})
        for iface_name, iface_data in lldp_data.get("interface", {}).items():
            for chassis_id, chassis_data in iface_data.get("chassis", {}).items():
                neighbor = {
                    "local_port": iface_name,
                    "remote_device": chassis_id,
                    "remote_ip": "",
                    "remote_mac": "",
                    "remote_port": "",
                    "capabilities": [],
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                }

                # Extract management address
                mgmt = chassis_data.get("mgmt-ip", "")
                if isinstance(mgmt, list):
                    neighbor["remote_ip"] = mgmt[0] if mgmt else ""
                else:
                    neighbor["remote_ip"] = mgmt

                # Extract MAC
                neighbor["remote_mac"] = chassis_data.get("id", {}).get("value", "")

                # Extract port
                port_data = iface_data.get("port", {})
                neighbor["remote_port"] = port_data.get("id", {}).get("value", "")

                # Extract capabilities
                caps = chassis_data.get("capability", [])
                if isinstance(caps, list):
                    neighbor["capabilities"] = [
                        c.get("type", "") for c in caps if c.get("enabled", False)
                    ]

                neighbors.append(neighbor)

        self.neighbors = neighbors
        logger.info(f"Parsed {len(neighbors)} LLDP neighbors from {path}")
        self._process_neighbors()
        return neighbors

    def parse_log_file(self, filepath: Optional[str] = None) -> list[dict]:
        """
        Parse LLDP entries from syslog/lldpd log.
        Looks for patterns like: LLDP: neighbor <name> detected on <port>
        """
        path = Path(filepath) if filepath else Path(LOG_PATHS["lldp_log"])
        if not path.exists():
            logger.warning(f"LLDP log not found: {path}")
            return []

        pattern = re.compile(
            r"LLDP:\s+neighbor\s+(\S+)\s+detected\s+on\s+(\S+)"
        )

        neighbors = []
        with open(path) as f:
            for line in f:
                match = pattern.search(line)
                if match:
                    neighbors.append({
                        "remote_device": match.group(1),
                        "local_port": match.group(2),
                        "remote_ip": "",
                        "remote_mac": "",
                        "remote_port": "",
                        "capabilities": [],
                        "timestamp": datetime.utcnow().isoformat() + "Z",
                    })

        self.neighbors.extend(neighbors)
        logger.info(f"Parsed {len(neighbors)} LLDP entries from log")
        self._process_neighbors()
        return neighbors

    def _process_neighbors(self):
        """Extract devices and links from neighbor records."""
        for n in self.neighbors:
            # Register local device
            local_id = n.get("local_device", n.get("local_ip", "unknown"))
            if local_id and local_id != "unknown":
                self.devices[local_id] = {
                    "device_id": local_id,
                    "ip": n.get("local_ip", ""),
                    "mac": n.get("local_mac", ""),
                    "hostname": n.get("local_device", ""),
                    "device_type": self._infer_type(n.get("capabilities", [])),
                    "source": "lldp",
                }

            # Register remote device
            remote_id = n.get("remote_device", n.get("remote_ip", "unknown"))
            if remote_id and remote_id != "unknown":
                self.devices[remote_id] = {
                    "device_id": remote_id,
                    "ip": n.get("remote_ip", ""),
                    "mac": n.get("remote_mac", ""),
                    "hostname": n.get("remote_device", ""),
                    "device_type": self._infer_type(n.get("capabilities", [])),
                    "source": "lldp",
                }

            # Register link
            if local_id and remote_id:
                self.links.append({
                    "src": local_id,
                    "dst": remote_id,
                    "src_port": n.get("local_port", ""),
                    "dst_port": n.get("remote_port", ""),
                    "protocol": "LLDP",
                    "timestamp": n.get("timestamp", ""),
                })

    @staticmethod
    def _infer_type(capabilities: list) -> str:
        """Infer device type from LLDP capabilities."""
        caps = [c.lower() for c in capabilities]
        if "router" in caps and "bridge" in caps:
            return "l3_switch"
        elif "router" in caps:
            return "router"
        elif "bridge" in caps:
            return "switch"
        elif "station" in caps:
            return "endpoint"
        return "unknown"

    def get_devices(self) -> dict:
        return self.devices

    def get_links(self) -> list:
        return self.links

    def discover(self) -> tuple[dict, list]:
        """Run discovery: returns (devices, links)."""
        if USE_SAMPLE_DATA:
            self.parse_sample_data()
        else:
            # Try lldpcli JSON first, fall back to log parsing
            if Path(LOG_PATHS["lldp_export"]).exists():
                self.parse_lldpcli_json()
            elif Path(LOG_PATHS["lldp_log"]).exists():
                self.parse_log_file()
            else:
                logger.warning("No LLDP data source available")

        return self.devices, self.links
