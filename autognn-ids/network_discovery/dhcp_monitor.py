"""
DHCP Monitor
Parses DHCP lease files and logs from ISC dhcpd, dnsmasq, or Kea.
Can also passively sniff DHCP traffic on ports 67-68 using Scapy.
Detects rogue DHCP servers, IP hopping, MAC spoofing, and rapid lease churn.
"""
import json
import re
import logging
from pathlib import Path
from datetime import datetime
from collections import defaultdict
from typing import Optional

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from config import LOG_PATHS, OUI_DATABASE

logger = logging.getLogger("autognn.dhcp")


# Regex patterns for DHCP log formats
DHCP_LOG_PATTERNS = {
    # ISC dhcpd: DHCPACK on 192.168.1.50 to 00:1a:2b:cc:dd:ee (hostname) via eth0
    "isc_ack": re.compile(
        r"(DHCPACK|DHCPOFFER|DHCPREQUEST|DHCPDISCOVER|DHCPNAK|DHCPRELEASE)"
        r"\s+(?:on\s+)?([\d.]+)\s+to\s+([\da-fA-F:]+)"
        r"(?:\s+\(([^)]*)\))?"
        r"(?:\s+via\s+(\S+))?"
    ),
    # dnsmasq: DHCPACK(eth0) 192.168.1.50 00:1a:2b:cc:dd:ee hostname
    "dnsmasq": re.compile(
        r"(DHCPACK|DHCPOFFER|DHCPREQUEST|DHCPDISCOVER|DHCPNAK|DHCPRELEASE)"
        r"\((\S+)\)\s+([\d.]+)\s+([\da-fA-F:]+)(?:\s+(\S+))?"
    ),
}

# ISC dhcpd lease file parser
LEASE_BLOCK_RE = re.compile(
    r"lease\s+([\d.]+)\s*\{([^}]+)\}", re.MULTILINE | re.DOTALL
)


class DHCPMonitor:
    """Monitor DHCP activity for threat detection."""

    def __init__(self):
        self.leases: list[dict] = []
        self.active_leases: dict[str, dict] = {}  # IP -> lease info
        self.mac_to_ips: dict[str, list] = defaultdict(list)  # MAC -> [IPs]
        self.known_servers: set[str] = set()
        self.threat_indicators: list[dict] = []
        self._file_position: int = 0

    # ─── Data Sources ────────────────────────────────────────

    def parse_lease_file(self, filepath: Optional[str] = None) -> list[dict]:
        """
        Parse ISC dhcpd lease file (dhcpd.leases format).
        """
        path = None
        if filepath:
            path = Path(filepath)
        else:
            for key in ["dhcp_leases_isc", "dhcp_leases_dnsmasq"]:
                p = Path(LOG_PATHS.get(key, ""))
                if p.exists():
                    path = p
                    break

        if not path or not path.exists():
            logger.warning("No DHCP lease file found")
            return []

        # Check if it's ISC format or dnsmasq format
        content = path.read_text()

        if "lease " in content and "{" in content:
            return self._parse_isc_leases(content, path)
        else:
            return self._parse_dnsmasq_leases(content, path)

    def _parse_isc_leases(self, content: str, path: Path) -> list[dict]:
        """Parse ISC dhcpd lease file format."""
        leases = []

        for match in LEASE_BLOCK_RE.finditer(content):
            ip = match.group(1)
            block = match.group(2)

            lease = {
                "client_ip": ip,
                "message_type": "DHCPACK",
                "client_mac": "",
                "hostname": "",
                "lease_time": 0,
                "server_ip": "",
                "gateway": "",
                "dns_server": "",
                "timestamp": "",
            }

            # Extract fields from lease block
            mac_match = re.search(
                r"hardware\s+ethernet\s+([\da-fA-F:]+)", block
            )
            if mac_match:
                lease["client_mac"] = mac_match.group(1).upper()

            host_match = re.search(r'client-hostname\s+"([^"]+)"', block)
            if host_match:
                lease["hostname"] = host_match.group(1)

            start_match = re.search(
                r"starts\s+\d+\s+([\d/]+\s+[\d:]+)", block
            )
            if start_match:
                try:
                    dt = datetime.strptime(
                        start_match.group(1), "%Y/%m/%d %H:%M:%S"
                    )
                    lease["timestamp"] = dt.isoformat() + "Z"
                except ValueError:
                    lease["timestamp"] = datetime.utcnow().isoformat() + "Z"

            end_match = re.search(
                r"ends\s+\d+\s+([\d/]+\s+[\d:]+)", block
            )
            if end_match and start_match:
                try:
                    end_dt = datetime.strptime(
                        end_match.group(1), "%Y/%m/%d %H:%M:%S"
                    )
                    start_dt = datetime.strptime(
                        start_match.group(1), "%Y/%m/%d %H:%M:%S"
                    )
                    lease["lease_time"] = int(
                        (end_dt - start_dt).total_seconds()
                    )
                except ValueError:
                    pass

            leases.append(lease)

        self.leases.extend(leases)
        logger.info(f"Parsed {len(leases)} leases from {path}")
        self._process_leases()
        return leases

    def _parse_dnsmasq_leases(self, content: str, path: Path) -> list[dict]:
        """
        Parse dnsmasq lease file format.
        Format: <expiry_epoch> <mac> <ip> <hostname> <client-id>
        """
        leases = []

        for line in content.strip().splitlines():
            parts = line.split()
            if len(parts) >= 4:
                try:
                    expiry = int(parts[0])
                    mac = parts[1].upper()
                    ip = parts[2]
                    hostname = parts[3] if parts[3] != "*" else ""

                    lease = {
                        "client_ip": ip,
                        "message_type": "DHCPACK",
                        "client_mac": mac,
                        "hostname": hostname,
                        "lease_time": 0,
                        "server_ip": "",
                        "gateway": "",
                        "dns_server": "",
                        "timestamp": datetime.utcnow().isoformat() + "Z",
                    }
                    leases.append(lease)
                except (ValueError, IndexError):
                    continue

        self.leases.extend(leases)
        logger.info(f"Parsed {len(leases)} leases from {path}")
        self._process_leases()
        return leases

    def parse_log_file(self, filepath: Optional[str] = None,
                       max_lines: int = 5000) -> list[dict]:
        """
        Parse DHCP server log file (ISC dhcpd or dnsmasq log).
        Tails from last-read position for continuous monitoring.
        """
        path = None
        if filepath:
            path = Path(filepath)
        else:
            for key in ["dhcp_log", "dhcp_log_alt"]:
                p = Path(LOG_PATHS.get(key, ""))
                if p.exists():
                    path = p
                    break

        if not path or not path.exists():
            logger.warning("No DHCP log file found")
            return []

        events = []
        try:
            with open(path) as f:
                f.seek(self._file_position)
                lines_read = 0

                for line in f:
                    if lines_read >= max_lines:
                        break

                    event = self._parse_dhcp_log_line(line.strip())
                    if event:
                        events.append(event)
                    lines_read += 1

                self._file_position = f.tell()

        except PermissionError:
            logger.error(f"Permission denied reading {path}")
            return []
        except IOError as e:
            logger.error(f"Error reading DHCP log: {e}")
            return []

        if events:
            self.leases.extend(events)
            logger.info(f"Parsed {len(events)} DHCP events from {path}")
            self._process_leases()

        return events

    def _parse_dhcp_log_line(self, line: str) -> Optional[dict]:
        """Parse a single DHCP log line."""
        if not line:
            return None

        # Try ISC dhcpd format
        m = DHCP_LOG_PATTERNS["isc_ack"].search(line)
        if m:
            return {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "message_type": m.group(1),
                "client_ip": m.group(2),
                "client_mac": m.group(3).upper(),
                "hostname": m.group(4) or "",
                "lease_time": 0,
                "server_ip": "",
                "gateway": "",
                "dns_server": "",
            }

        # Try dnsmasq format
        m = DHCP_LOG_PATTERNS["dnsmasq"].search(line)
        if m:
            return {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "message_type": m.group(1),
                "client_ip": m.group(3),
                "client_mac": m.group(4).upper(),
                "hostname": m.group(5) or "",
                "lease_time": 0,
                "server_ip": "",
                "gateway": "",
                "dns_server": "",
            }

        return None

    def sniff_dhcp(self, interface: str = "any", count: int = 50,
                   timeout: int = 60) -> list[dict]:
        """
        Passively sniff DHCP packets on ports 67/68 using Scapy.
        Requires root or CAP_NET_RAW.
        """
        try:
            from scapy.all import sniff as scapy_sniff, DHCP, BOOTP, IP, Ether
        except ImportError:
            logger.error("Scapy not installed. Cannot sniff DHCP.")
            return []

        events = []

        def process_packet(pkt):
            if not pkt.haslayer(DHCP):
                return

            bootp = pkt[BOOTP]
            dhcp_options = dict(
                (opt[0], opt[1])
                for opt in pkt[DHCP].options
                if isinstance(opt, tuple) and len(opt) >= 2
            )

            msg_type_num = dhcp_options.get("message-type", 0)
            msg_types = {
                1: "DHCPDISCOVER", 2: "DHCPOFFER", 3: "DHCPREQUEST",
                4: "DHCPDECLINE", 5: "DHCPACK", 6: "DHCPNAK",
                7: "DHCPRELEASE", 8: "DHCPINFORM",
            }

            event = {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "message_type": msg_types.get(msg_type_num, f"UNKNOWN({msg_type_num})"),
                "client_ip": bootp.ciaddr or bootp.yiaddr or "",
                "client_mac": (
                    pkt[Ether].src.upper()
                    if pkt.haslayer(Ether)
                    else ""
                ),
                "hostname": (
                    dhcp_options.get("hostname", b"").decode("utf-8", errors="ignore")
                    if isinstance(dhcp_options.get("hostname"), bytes)
                    else str(dhcp_options.get("hostname", ""))
                ),
                "lease_time": dhcp_options.get("lease_time", 0),
                "server_ip": (
                    pkt[IP].src if pkt.haslayer(IP) else
                    dhcp_options.get("server_id", "")
                ),
                "gateway": str(dhcp_options.get("router", "")),
                "dns_server": str(dhcp_options.get("name_server", "")),
            }
            events.append(event)

        try:
            scapy_sniff(
                filter="udp and (port 67 or port 68)",
                iface=interface if interface != "any" else None,
                prn=process_packet,
                count=count,
                timeout=timeout,
                store=False,
            )
        except PermissionError:
            logger.error("DHCP sniffing requires root privileges")
            return []
        except Exception as e:
            logger.error(f"DHCP sniff error: {e}")
            return []

        if events:
            self.leases.extend(events)
            logger.info(f"Sniffed {len(events)} DHCP packets")
            self._process_leases()

        return events

    # ─── Analysis ────────────────────────────────────────────

    def _process_leases(self):
        """Analyze DHCP events for threat indicators."""
        self.active_leases.clear()
        self.mac_to_ips.clear()
        self.known_servers.clear()
        self.threat_indicators.clear()

        for lease in self.leases:
            msg_type = lease.get("message_type", "")
            ip = lease.get("client_ip", "")
            mac = lease.get("client_mac", "")
            server = lease.get("server_ip", "")

            # Track active leases
            if msg_type == "DHCPACK" and ip and ip != "0.0.0.0":
                self.active_leases[ip] = lease

            # Track MAC to IP mappings
            if mac and ip and ip != "0.0.0.0":
                if ip not in self.mac_to_ips[mac]:
                    self.mac_to_ips[mac].append(ip)

            # Track known DHCP servers
            if msg_type in ("DHCPOFFER", "DHCPACK") and server:
                self.known_servers.add(server)

        # Run threat detection
        self._detect_rogue_dhcp()
        self._detect_ip_hopping()
        self._detect_rapid_churn()
        self._detect_unknown_devices()
        self._detect_dhcp_nak_patterns()

    def _detect_rogue_dhcp(self):
        """
        Detect rogue DHCP servers.
        A rogue server is one offering leases that isn't the known/legitimate server.
        """
        offers_by_server: dict[str, list] = defaultdict(list)
        for lease in self.leases:
            if lease.get("message_type") in ("DHCPOFFER", "DHCPACK"):
                server = lease.get("server_ip", "")
                if server:
                    offers_by_server[server].append(lease)

        if len(offers_by_server) <= 1:
            return  # Only one server, likely legitimate

        # The server with the most offers is likely legitimate
        legitimate = max(offers_by_server, key=lambda s: len(offers_by_server[s]))

        for server, offers in offers_by_server.items():
            if server != legitimate:
                self.threat_indicators.append({
                    "type": "rogue_dhcp_server",
                    "server_ip": server,
                    "legitimate_server": legitimate,
                    "offer_count": len(offers),
                    "risk_score": 0.95,
                    "severity": "critical",
                    "description": (
                        f"Rogue DHCP server detected at {server} "
                        f"({len(offers)} offers). Legitimate server: {legitimate}"
                    ),
                })

    def _detect_ip_hopping(self):
        """
        Detect IP hopping: a single MAC address requesting multiple
        different IP addresses. This can indicate evasion tactics.
        """
        for mac, ips in self.mac_to_ips.items():
            unique_ips = list(set(ip for ip in ips if ip != "0.0.0.0"))
            if len(unique_ips) >= 2:
                vendor = self._lookup_vendor(mac)
                self.threat_indicators.append({
                    "type": "ip_hopping",
                    "client_mac": mac,
                    "vendor": vendor,
                    "ip_addresses": unique_ips,
                    "ip_count": len(unique_ips),
                    "risk_score": min(0.8, 0.3 + len(unique_ips) * 0.15),
                    "severity": "warning",
                    "description": (
                        f"IP hopping: MAC {mac} ({vendor}) used {len(unique_ips)} "
                        f"different IPs: {', '.join(unique_ips)}"
                    ),
                })

    def _detect_rapid_churn(self):
        """
        Detect rapid DHCP churn: many DISCOVER/REQUEST/RELEASE cycles
        in a short time, possibly indicating DHCP exhaustion attack.
        """
        mac_events: dict[str, list] = defaultdict(list)
        for lease in self.leases:
            mac = lease.get("client_mac", "")
            if mac:
                mac_events[mac].append(lease)

        for mac, events in mac_events.items():
            discovers = [e for e in events if e.get("message_type") == "DHCPDISCOVER"]
            releases = [e for e in events if e.get("message_type") == "DHCPRELEASE"]

            # Many discovers from same MAC = suspicious
            if len(discovers) >= 3:
                self.threat_indicators.append({
                    "type": "dhcp_rapid_churn",
                    "client_mac": mac,
                    "discover_count": len(discovers),
                    "release_count": len(releases),
                    "risk_score": min(0.8, 0.4 + len(discovers) * 0.1),
                    "severity": "warning",
                    "description": (
                        f"Rapid DHCP churn: MAC {mac} sent {len(discovers)} "
                        f"DISCOVER, {len(releases)} RELEASE messages"
                    ),
                })

    def _detect_unknown_devices(self):
        """
        Detect devices with no hostname joining the network.
        While not inherently malicious, unknown devices warrant attention.
        """
        for lease in self.leases:
            if lease.get("message_type") == "DHCPACK":
                hostname = lease.get("hostname", "").strip()
                mac = lease.get("client_mac", "")
                ip = lease.get("client_ip", "")

                if (not hostname or hostname in ("", "unknown-device")) and mac:
                    vendor = self._lookup_vendor(mac)
                    self.threat_indicators.append({
                        "type": "unknown_device_joined",
                        "client_ip": ip,
                        "client_mac": mac,
                        "vendor": vendor,
                        "risk_score": 0.3,
                        "severity": "info",
                        "description": (
                            f"Unknown device joined: {ip} (MAC: {mac}, "
                            f"Vendor: {vendor}) with no hostname"
                        ),
                    })

    def _detect_dhcp_nak_patterns(self):
        """
        Detect DHCPNAK events. A NAK means the server rejected a client's
        request — could indicate a spoofed request or config issue.
        """
        naks = [l for l in self.leases if l.get("message_type") == "DHCPNAK"]
        for nak in naks:
            mac = nak.get("client_mac", "")
            ip = nak.get("client_ip", "")
            hostname = nak.get("hostname", "")
            self.threat_indicators.append({
                "type": "dhcp_nak",
                "client_ip": ip,
                "client_mac": mac,
                "hostname": hostname,
                "risk_score": 0.5,
                "severity": "warning",
                "description": (
                    f"DHCP NAK: Server rejected request from {mac} "
                    f"({hostname or 'no hostname'}) for IP {ip}"
                ),
            })

    # ─── Helpers ─────────────────────────────────────────────

    @staticmethod
    def _lookup_vendor(mac: str) -> str:
        """Lookup vendor from MAC OUI."""
        oui = mac[:8].upper()
        return OUI_DATABASE.get(oui, "Unknown")

    # ─── Public API ──────────────────────────────────────────

    def get_leases(self) -> list:
        return self.leases

    def get_active_leases(self) -> dict:
        return self.active_leases

    def get_mac_to_ips(self) -> dict:
        """Get MAC to IP mapping (useful for device correlation)."""
        return dict(self.mac_to_ips)

    def get_known_servers(self) -> set:
        return self.known_servers

    def get_threat_indicators(self) -> list:
        return self.threat_indicators

    def get_devices(self) -> dict:
        """
        Get discovered devices from DHCP data.
        Returns dict keyed by IP with device info.
        """
        devices = {}
        for ip, lease in self.active_leases.items():
            mac = lease.get("client_mac", "")
            vendor = self._lookup_vendor(mac) if mac else "Unknown"
            devices[ip] = {
                "device_id": ip,
                "ip": ip,
                "mac": mac,
                "hostname": lease.get("hostname", ""),
                "vendor": vendor,
                "device_type": "unknown",
                "source": "dhcp",
                "first_seen": lease.get("timestamp", ""),
                "last_seen": lease.get("timestamp", ""),
                "lease_time": lease.get("lease_time", 0),
            }
        return devices

    def get_suspicious_clients(self) -> dict:
        """Get clients with DHCP-based threat indicators."""
        client_risk: dict[str, float] = defaultdict(float)
        client_threats: dict[str, list] = defaultdict(list)

        for indicator in self.threat_indicators:
            # Use client_ip or client_mac as identifier
            key = indicator.get("client_ip") or indicator.get("client_mac", "")
            if key:
                client_risk[key] = max(
                    client_risk[key], indicator.get("risk_score", 0)
                )
                client_threats[key].append(indicator["type"])

        return {
            key: {"risk_score": score, "threat_types": client_threats[key]}
            for key, score in sorted(
                client_risk.items(), key=lambda x: x[1], reverse=True
            )
        }

    def discover(self) -> tuple[dict, list, dict]:
        """
        Run discovery: returns (devices, threat_indicators, suspicious_clients).
        """
        # Try lease file first, then log file, then sniffing
        lease_found = False
        for key in ["dhcp_leases_isc", "dhcp_leases_dnsmasq"]:
            if Path(LOG_PATHS.get(key, "")).exists():
                self.parse_lease_file()
                lease_found = True
                break

        log_found = False
        for key in ["dhcp_log", "dhcp_log_alt"]:
            if Path(LOG_PATHS.get(key, "")).exists():
                self.parse_log_file()
                log_found = True
                break

        if not lease_found and not log_found:
            logger.warning(
                "No DHCP data source found. Attempting passive sniff "
                "(requires root)..."
            )
            self.sniff_dhcp(timeout=30)

        return self.get_devices(), self.threat_indicators, self.get_suspicious_clients()
