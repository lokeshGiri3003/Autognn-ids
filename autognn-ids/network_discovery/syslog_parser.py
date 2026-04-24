"""
Syslog Parser
Tails syslog/messages files on a Linux server.
Extracts security-relevant events: failed logins, firewall drops,
suspicious connections, and device events.
"""
import json
import re
import os
import logging
from pathlib import Path
from datetime import datetime
from collections import defaultdict
from typing import Optional

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from config import LOG_PATHS

logger = logging.getLogger("autognn.syslog")


# Compiled regex patterns for common security events
PATTERNS = {
    "ssh_failed": re.compile(
        r"sshd\[\d+\]:\s+Failed\s+(?:password|publickey)\s+for\s+(\S+)\s+from\s+(\d+\.\d+\.\d+\.\d+)"
    ),
    "ssh_accepted": re.compile(
        r"sshd\[\d+\]:\s+Accepted\s+\S+\s+for\s+(\S+)\s+from\s+(\d+\.\d+\.\d+\.\d+)"
    ),
    "iptables_drop": re.compile(
        r"iptables:\s+DROP\s+.*SRC=(\d+\.\d+\.\d+\.\d+)\s+DST=(\d+\.\d+\.\d+\.\d+)\s+"
        r".*PROTO=(\S+)(?:\s+DPT=(\d+))?"
    ),
    "iptables_accept": re.compile(
        r"iptables:\s+ACCEPT\s+.*SRC=(\d+\.\d+\.\d+\.\d+)\s+DST=(\d+\.\d+\.\d+\.\d+)\s+"
        r".*PROTO=(\S+)(?:\s+DPT=(\d+))?"
    ),
    "iptables_suspect": re.compile(
        r"iptables:\s+SUSPECT\s+.*SRC=(\d+\.\d+\.\d+\.\d+)\s+DST=(\d+\.\d+\.\d+\.\d+)\s+"
        r".*PROTO=(\S+).*BYTES=(\d+)"
    ),
    "large_transfer": re.compile(
        r"(?:Large\s+data\s+export|Unusual\s+outbound\s+transfer).*?(\d+\.?\d*\s*[MKG]B).*?(\d+\.\d+\.\d+\.\d+)"
    ),
    "periodic_conn": re.compile(
        r"PERIODIC\s+SRC=(\d+\.\d+\.\d+\.\d+)\s+DST=(\d+\.\d+\.\d+\.\d+).*INTERVAL=(\S+)"
    ),
}


class SyslogParser:
    """Parse syslog files for security-relevant events."""

    def __init__(self):
        self.events: list[dict] = []
        self.security_events: list[dict] = []
        self.device_events: dict[str, list] = defaultdict(list)
        self._file_position: int = 0  # For tailing


    def tail_syslog(self, filepath: Optional[str] = None, max_lines: int = 1000) -> list[dict]:
        """
        Tail syslog file from last known position.
        Reads new lines since last call.
        """
        # Try configured path, then alternatives
        path = None
        if filepath:
            path = Path(filepath)
        else:
            for key in ["syslog", "syslog_alt"]:
                p = Path(LOG_PATHS[key])
                if p.exists():
                    path = p
                    break

        if not path or not path.exists():
            logger.warning("No syslog file found")
            return []

        events = []
        try:
            with open(path) as f:
                # Seek to last position
                f.seek(self._file_position)
                lines_read = 0

                for line in f:
                    if lines_read >= max_lines:
                        break

                    event = self._parse_syslog_line(line.strip())
                    if event:
                        events.append(event)
                    lines_read += 1

                self._file_position = f.tell()

        except PermissionError:
            logger.error(f"Permission denied reading {path}. Run as root or add user to adm group.")
            return []
        except IOError as e:
            logger.error(f"Error reading syslog: {e}")
            return []

        if events:
            self.events.extend(events)
            logger.info(f"Read {len(events)} new syslog entries")
            self._process_events()

        return events

    def _parse_syslog_line(self, line: str) -> Optional[dict]:
        """Parse a single syslog line into structured event."""
        if not line:
            return None

        # Standard syslog format: Mon DD HH:MM:SS hostname process[pid]: message
        syslog_pattern = re.compile(
            r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(.+)$"
        )

        match = syslog_pattern.match(line)
        if match:
            timestamp_str = match.group(1)
            hostname = match.group(2)
            message = match.group(3)

            # Parse timestamp (add current year)
            try:
                now = datetime.utcnow()
                ts = datetime.strptime(
                    f"{now.year} {timestamp_str}",
                    "%Y %b %d %H:%M:%S"
                )
                timestamp = ts.isoformat() + "Z"
            except ValueError:
                timestamp = datetime.utcnow().isoformat() + "Z"

            severity = self._classify_severity(message)

            return {
                "timestamp": timestamp,
                "host": hostname,
                "facility": "",
                "severity": severity,
                "message": message,
            }

        return None

    def _process_events(self):
        """Extract security-relevant events from parsed syslog entries."""
        self.security_events.clear()
        self.device_events.clear()

        for event in self.events:
            message = event.get("message", "")
            host = event.get("host", "")
            timestamp = event.get("timestamp", "")
            severity = event.get("severity", "info")

            # Track per-device events
            self.device_events[host].append(event)

            # Check each pattern
            sec_event = None

            # SSH failed login
            m = PATTERNS["ssh_failed"].search(message)
            if m:
                sec_event = {
                    "type": "ssh_failed_login",
                    "timestamp": timestamp,
                    "host": host,
                    "user": m.group(1),
                    "src_ip": m.group(2),
                    "severity": "warning",
                    "risk_score": 0.4,
                }

            # SSH accepted (could be suspicious depending on source)
            m = PATTERNS["ssh_accepted"].search(message)
            if m:
                sec_event = {
                    "type": "ssh_accepted",
                    "timestamp": timestamp,
                    "host": host,
                    "user": m.group(1),
                    "src_ip": m.group(2),
                    "severity": severity,
                    "risk_score": 0.1,
                }

            # Firewall drops
            m = PATTERNS["iptables_drop"].search(message)
            if m:
                sec_event = {
                    "type": "firewall_drop",
                    "timestamp": timestamp,
                    "host": host,
                    "src_ip": m.group(1),
                    "dst_ip": m.group(2),
                    "protocol": m.group(3),
                    "dst_port": int(m.group(4)) if m.group(4) else 0,
                    "severity": "warning",
                    "risk_score": 0.5,
                }

            # Suspect traffic
            m = PATTERNS["iptables_suspect"].search(message)
            if m:
                sec_event = {
                    "type": "suspect_traffic",
                    "timestamp": timestamp,
                    "host": host,
                    "src_ip": m.group(1),
                    "dst_ip": m.group(2),
                    "protocol": m.group(3),
                    "bytes": int(m.group(4)),
                    "severity": "alert",
                    "risk_score": 0.8,
                }

            # Large data transfer
            m = PATTERNS["large_transfer"].search(message)
            if m:
                sec_event = {
                    "type": "large_transfer",
                    "timestamp": timestamp,
                    "host": host,
                    "transfer_size": m.group(1),
                    "dst_ip": m.group(2),
                    "severity": "alert",
                    "risk_score": 0.7,
                }

            # Periodic connections (C2 indicator)
            m = PATTERNS["periodic_conn"].search(message)
            if m:
                sec_event = {
                    "type": "periodic_connection",
                    "timestamp": timestamp,
                    "host": host,
                    "src_ip": m.group(1),
                    "dst_ip": m.group(2),
                    "interval": m.group(3),
                    "severity": "warning",
                    "risk_score": 0.6,
                }

            if sec_event:
                self.security_events.append(sec_event)

    @staticmethod
    def _classify_severity(message: str) -> str:
        """Classify message severity from content."""
        msg_lower = message.lower()
        if any(w in msg_lower for w in ["alert", "critical", "emerg"]):
            return "alert"
        elif any(w in msg_lower for w in ["error", "fail", "denied"]):
            return "error"
        elif any(w in msg_lower for w in ["warn", "suspect", "drop"]):
            return "warning"
        return "info"

    def get_security_events(self) -> list:
        return self.security_events

    def get_device_events(self) -> dict:
        return dict(self.device_events)

    def get_failed_logins(self) -> list:
        """Get all failed SSH login attempts."""
        return [e for e in self.security_events if e["type"] == "ssh_failed_login"]

    def get_firewall_drops(self) -> list:
        """Get all firewall drop events."""
        return [e for e in self.security_events if e["type"] == "firewall_drop"]

    def get_suspicious_ips(self) -> dict:
        """Get IPs with high-risk activity, sorted by risk."""
        ip_risk: dict[str, float] = defaultdict(float)
        ip_events: dict[str, list] = defaultdict(list)

        for event in self.security_events:
            src_ip = event.get("src_ip", "")
            if src_ip:
                ip_risk[src_ip] = max(ip_risk[src_ip], event.get("risk_score", 0))
                ip_events[src_ip].append(event["type"])

        return {
            ip: {"risk_score": score, "event_types": ip_events[ip]}
            for ip, score in sorted(ip_risk.items(), key=lambda x: x[1], reverse=True)
        }

    def sniff_security_packets(self, interfaces: list[str], timeout: int = 30) -> list[dict]:
        """Sniff packets for security-related events in bridge mode.

        Detects:
        - SSH connection attempts (port 22)
        - TCP connection resets (firewall blocks)
        - Port scanning patterns
        - Unusual traffic
        """
        try:
            from scapy.all import sniff, IP, TCP, UDP
        except ImportError:
            logger.error("Scapy not installed. Cannot sniff security events.")
            return []

        events = []
        port_attempts = defaultdict(lambda: defaultdict(int))  # src_ip -> dst_port -> count

        def capture_packet(pkt):
            """Callback to detect security-relevant packets."""
            if IP not in pkt:
                return

            ip_layer = pkt[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst

            # Skip loopback
            if src_ip.startswith("127.") or dst_ip.startswith("127."):
                return

            timestamp = datetime.utcnow().isoformat() + "Z"

            if TCP in pkt:
                tcp_layer = pkt[TCP]
                dst_port = tcp_layer.dport
                flags = tcp_layer.flags

                # SSH attempt detection
                if dst_port == 22:
                    event_type = "ssh_connection_attempt"
                    if flags & 0x01:  # SYN flag
                        events.append({
                            "type": event_type,
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "dst_port": dst_port,
                            "severity": "low",
                            "risk_score": 0.1,
                            "timestamp": timestamp,
                        })

                # Connection reset (RST flag) - possible firewall drop
                if flags & 0x04:  # RST flag
                    events.append({
                        "type": "connection_reset",
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "dst_port": dst_port,
                        "severity": "medium",
                        "risk_score": 0.3,
                        "timestamp": timestamp,
                    })

                # Track port attempts for scanning detection
                port_attempts[src_ip][dst_port] += 1

        try:
            # Sniff on all provided interfaces
            for iface in interfaces:
                try:
                    logger.info(f"Sniffing security events on interface {iface} for {timeout}s")
                    sniff(
                        filter="tcp or udp",
                        prn=capture_packet,
                        timeout=timeout,
                        iface=iface,
                        store=False
                    )
                except (PermissionError, OSError) as e:
                    logger.warning(f"Cannot sniff on {iface}: {e}. Requires root privileges.")
                    continue

            # Detect port scanning (many unique ports from same source)
            for src_ip, ports in port_attempts.items():
                if len(ports) > 20:  # Threshold for port scan
                    events.append({
                        "type": "port_scan",
                        "src_ip": src_ip,
                        "dst_ip": "*",
                        "severity": "high",
                        "risk_score": 0.7,
                        "unique_ports": len(ports),
                        "timestamp": datetime.utcnow().isoformat() + "Z",
                    })

            self.security_events = events
            logger.info(f"Sniffed {len(events)} security events from {len(interfaces)} interfaces")
            return events

        except Exception as e:
            logger.error(f"Security event sniffing error: {e}")
            return []

    def discover(self) -> tuple[list, dict]:
        """Run discovery: returns (security_events, suspicious_ips).

        In bridge mode: sniff packets for security events.
        Otherwise: parse syslog file.
        """
        from config import DISCOVERY_CONFIG

        # Bridge mode: sniff first
        if DISCOVERY_CONFIG.get("syslog_sniff_enabled", False):
            interfaces = DISCOVERY_CONFIG.get("sniff_interfaces", ["br0"])
            timeout = DISCOVERY_CONFIG.get("sniff_timeout", 30)
            logger.info(f"Bridge mode: sniffing security events on {interfaces}")
            self.sniff_security_packets(interfaces, timeout=timeout)
        else:
            # Legacy: parse syslog file
            self.tail_syslog()

        return self.security_events, self.get_suspicious_ips()
