"""
ARP Monitor
Reads ARP tables from /proc/net/arp, arp command output, or sample data.
Maps IP addresses to MAC addresses and detects new/rogue devices.
"""
import json
import re
import subprocess
import logging
from pathlib import Path
from datetime import datetime
from typing import Optional

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from config import LOG_PATHS, OUI_DATABASE

logger = logging.getLogger("autognn.arp")


class ARPMonitor:
    """Monitor ARP tables for IP-MAC mappings and new device detection."""

    def __init__(self):
        self.entries: list[dict] = []
        self.devices: dict[str, dict] = {}
        self.known_macs: set[str] = set()
        self.new_devices: list[dict] = []


    def parse_proc_arp(self) -> list[dict]:
        """Read /proc/net/arp (Linux kernel ARP cache)."""
        arp_path = Path(LOG_PATHS["arp"])
        if not arp_path.exists():
            logger.warning(f"ARP table not found: {arp_path}")
            return []

        entries = []
        with open(arp_path) as f:
            # Skip header line
            header = f.readline()
            for line in f:
                parts = line.split()
                if len(parts) >= 6:
                    ip = parts[0]
                    mac = parts[3]
                    device = parts[5]

                    # Skip incomplete entries
                    if mac == "00:00:00:00:00:00":
                        continue

                    entries.append({
                        "ip": ip,
                        "mac": mac.upper(),
                        "device": device,
                        "type": "dynamic",
                        "hostname": "",
                        "timestamp": datetime.utcnow().isoformat() + "Z",
                    })

        self.entries = entries
        logger.info(f"Read {len(entries)} ARP entries from {arp_path}")
        self._process_entries()
        return entries

    def parse_arp_command(self) -> list[dict]:
        """Parse output of 'arp -an' command."""
        try:
            result = subprocess.run(
                ["arp", "-an"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode != 0:
                logger.warning(f"arp command failed: {result.stderr}")
                return []

            pattern = re.compile(
                r"\?\s+\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+"
                r"([\da-fA-F:]+)\s+\[(\w+)\]\s+on\s+(\S+)"
            )

            entries = []
            for line in result.stdout.splitlines():
                match = pattern.search(line)
                if match:
                    entries.append({
                        "ip": match.group(1),
                        "mac": match.group(2).upper(),
                        "device": match.group(4),
                        "type": match.group(3),
                        "hostname": "",
                        "timestamp": datetime.utcnow().isoformat() + "Z",
                    })

            self.entries = entries
            logger.info(f"Parsed {len(entries)} ARP entries from arp command")
            self._process_entries()
            return entries

        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            logger.error(f"ARP command error: {e}")
            return []

    def sniff_arp_packets(self, interfaces: list[str], timeout: int = 30) -> list[dict]:
        """Sniff ARP packets on bridge/physical interfaces to discover devices.

        This is the primary discovery method for bridge mode deployments.
        Returns same format as parse_proc_arp/parse_arp_command for compatibility.
        """
        try:
            from scapy.all import sniff, ARP
        except ImportError:
            logger.error("Scapy not installed. Cannot sniff ARP.")
            return []

        entries = []
        seen_macs = set()

        def capture_arp(pkt):
            """Callback to capture ARP packets."""
            if ARP not in pkt:
                return

            # ARP has operation: 1=request (who-has), 2=reply (is-at)
            arp_layer = pkt[ARP]

            # Both request and reply give us IP-MAC mappings
            # psrc = sender protocol address (IP), hwsrc = sender hardware address (MAC)
            src_ip = arp_layer.psrc
            src_mac = arp_layer.hwsrc.upper()

            # Skip broadcast/zero addresses
            if src_mac == "00:00:00:00:00:00" or src_ip == "0.0.0.0":
                return

            # Deduplicate
            if src_mac in seen_macs:
                return

            seen_macs.add(src_mac)
            entries.append({
                "ip": src_ip,
                "mac": src_mac,
                "device": "sniffed",
                "type": "dynamic",
                "hostname": "",
                "timestamp": datetime.utcnow().isoformat() + "Z",
            })

        try:
            # Sniff on all provided interfaces
            for iface in interfaces:
                try:
                    logger.info(f"Sniffing ARP on interface {iface} for {timeout}s")
                    sniff(
                        filter="arp",
                        prn=capture_arp,
                        timeout=timeout,
                        iface=iface,
                        store=False  # Don't store packets in memory
                    )
                except (PermissionError, OSError) as e:
                    logger.warning(f"Cannot sniff on {iface}: {e}. Requires root privileges.")
                    continue

            self.entries = entries
            logger.info(f"Sniffed {len(entries)} ARP entries from {len(interfaces)} interfaces")
            self._process_entries()
            return entries

        except Exception as e:
            logger.error(f"ARP sniffing error: {e}")
            return []

    def _process_entries(self):
        """Process ARP entries into device records with vendor lookup."""
        for entry in self.entries:
            mac = entry.get("mac", "")
            ip = entry.get("ip", "")

            if not mac or not ip:
                continue

            vendor = self._lookup_vendor(mac)
            hostname = entry.get("hostname", "")

            device = {
                "device_id": ip,
                "ip": ip,
                "mac": mac,
                "hostname": hostname or f"host-{ip.split('.')[-1]}",
                "vendor": vendor,
                "device_type": self._infer_type_from_vendor(vendor),
                "source": "arp",
                "first_seen": entry.get("timestamp", datetime.utcnow().isoformat() + "Z"),
                "last_seen": entry.get("timestamp", datetime.utcnow().isoformat() + "Z"),
            }

            # Detect new devices
            if mac not in self.known_macs:
                self.new_devices.append(device)
                self.known_macs.add(mac)

            self.devices[ip] = device

    @staticmethod
    def _lookup_vendor(mac: str) -> str:
        """Lookup vendor from MAC OUI (first 3 octets)."""
        oui = mac[:8].upper()
        return OUI_DATABASE.get(oui, "Unknown")

    @staticmethod
    def _infer_type_from_vendor(vendor: str) -> str:
        """Infer device type from vendor name."""
        vendor_lower = vendor.lower()
        if vendor_lower in ("cisco", "juniper", "hp", "netgear"):
            return "network_device"
        elif vendor_lower in ("vmware", "qemu/kvm", "virtualbox", "parallels"):
            return "virtual_machine"
        elif vendor_lower in ("dell", "super micro"):
            return "server"
        elif vendor_lower in ("raspberry pi",):
            return "iot_device"
        elif vendor_lower in ("tp-link",):
            return "consumer_device"
        return "unknown"

    def get_devices(self) -> dict:
        return self.devices

    def get_new_devices(self) -> list:
        """Return devices seen for the first time."""
        return self.new_devices

    def discover(self) -> dict:
        """Run discovery: returns devices dict.

        In bridge mode: sniff ARP packets on bridge interfaces.
        Otherwise: try /proc/net/arp, fall back to arp command.
        """
        from config import DISCOVERY_CONFIG

        # Sniff-first approach for bridge mode
        if DISCOVERY_CONFIG.get("arp_sniff_enabled", False):
            interfaces = DISCOVERY_CONFIG.get("sniff_interfaces", ["br0"])
            timeout = DISCOVERY_CONFIG.get("sniff_timeout", 30)
            self.sniff_arp_packets(interfaces, timeout=timeout)
        else:
            # Legacy: Try /proc/net/arp first, fall back to arp command
            if Path(LOG_PATHS["arp"]).exists():
                self.parse_proc_arp()
            else:
                self.parse_arp_command()

        return self.devices
