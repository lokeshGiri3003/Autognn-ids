"""
Topology Builder
Orchestrates all 4 discovery sources (LLDP, ARP, NetFlow, Syslog) into a
unified network graph. Maintains in-memory networkx graph + SQLite persistence.
Provides 30-second window snapshots for GNN inference.
"""
import json
import sqlite3
import logging
import threading
import time
from pathlib import Path
from datetime import datetime, timedelta
from collections import defaultdict
from typing import Optional

import networkx as nx

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from config import (
    SQLITE_DB_PATH, DISCOVERY_CONFIG, OUI_DATABASE,
)
from network_discovery.lldp_parser import LLDPParser
from network_discovery.arp_monitor import ARPMonitor
from network_discovery.netflow_collector import NetFlowCollector
from network_discovery.syslog_parser import SyslogParser
from network_discovery.dns_monitor import DNSMonitor
from network_discovery.dhcp_monitor import DHCPMonitor

logger = logging.getLogger("autognn.topology")


class TopologyBuilder:
    """
    Central orchestrator for network topology discovery.
    Merges data from LLDP, ARP, NetFlow, and Syslog into a unified graph.
    """

    def __init__(self, db_path: Optional[str] = None):
        self.graph = nx.DiGraph()
        self.db_path = db_path or str(SQLITE_DB_PATH)

        # Discovery modules
        self.lldp = LLDPParser()
        self.arp = ARPMonitor()
        self.netflow = NetFlowCollector()
        self.syslog = SyslogParser()
        self.dns = DNSMonitor()
        self.dhcp = DHCPMonitor()

        # State tracking
        self.devices: dict[str, dict] = {}
        self.ip_to_device: dict[str, str] = {}
        self.mac_to_device: dict[str, str] = {}
        self.alerts: list[dict] = []
        self.snapshots: list[dict] = []

        self._running = False
        self._lock = threading.Lock()

    # ─── Discovery Orchestration ────────────────────────────

    def run_discovery(self):
        """Run all discovery modules and merge results."""
        logger.info("Starting network discovery...")

        # 1. LLDP - physical topology
        lldp_devices, lldp_links = self.lldp.discover()
        self._merge_devices(lldp_devices, source="lldp")
        self._add_links(lldp_links)
        logger.info(f"LLDP: {len(lldp_devices)} devices, {len(lldp_links)} links")

        # 2. ARP - IP/MAC mapping
        arp_devices = self.arp.discover()
        self._merge_devices(arp_devices, source="arp")
        logger.info(f"ARP: {len(arp_devices)} devices")

        # 3. NetFlow - traffic flows
        netflow_edges, device_traffic = self.netflow.discover()
        self._add_traffic_edges(netflow_edges)
        self._update_traffic_stats(device_traffic)
        logger.info(f"NetFlow: {len(netflow_edges)} edges")

        # 4. Syslog - security events
        sec_events, suspicious_ips = self.syslog.discover()
        self._process_security_events(sec_events, suspicious_ips)
        logger.info(f"Syslog: {len(sec_events)} security events")

        # 5. DNS - query analysis
        dns_threats, dns_suspicious = self.dns.discover()
        self._process_dns_data(dns_threats, dns_suspicious)
        dns_stats = self.dns.get_dns_stats()
        logger.info(f"DNS: {len(self.dns.get_queries())} queries, {len(dns_threats)} threats")

        # 6. DHCP - lease tracking
        dhcp_devices, dhcp_threats, dhcp_suspicious = self.dhcp.discover()
        self._merge_devices(dhcp_devices, source="dhcp")
        self._process_dhcp_data(dhcp_threats, dhcp_suspicious)
        logger.info(f"DHCP: {len(dhcp_devices)} devices, {len(dhcp_threats)} threats")

        # Build the networkx graph
        self._build_graph()

        # Attach DNS stats to nodes
        self._attach_dns_stats(dns_stats)

        # Persist to SQLite
        self._save_to_db()

        logger.info(
            f"Discovery complete: {self.graph.number_of_nodes()} nodes, "
            f"{self.graph.number_of_edges()} edges"
        )

    def _merge_devices(self, devices: dict, source: str):
        """Merge devices from a source, correlating by IP/MAC."""
        for dev_id, dev_info in devices.items():
            ip = dev_info.get("ip", "")
            mac = dev_info.get("mac", "")

            # Find existing device by IP or MAC
            existing_id = None
            if ip and ip in self.ip_to_device:
                existing_id = self.ip_to_device[ip]
            elif mac and mac in self.mac_to_device:
                existing_id = self.mac_to_device[mac]

            if existing_id and existing_id in self.devices:
                # Merge with existing device
                existing = self.devices[existing_id]
                # Update fields only if new info is available
                for key in ["hostname", "vendor", "device_type"]:
                    if dev_info.get(key) and not existing.get(key):
                        existing[key] = dev_info[key]
                existing["sources"] = existing.get("sources", set())
                existing["sources"].add(source)
                existing["last_seen"] = datetime.utcnow().isoformat() + "Z"
            else:
                # New device
                canonical_id = ip or mac or dev_id
                vendor = dev_info.get("vendor", "")
                if not vendor and mac:
                    oui = mac[:8].upper()
                    vendor = OUI_DATABASE.get(oui, "Unknown")

                self.devices[canonical_id] = {
                    "device_id": canonical_id,
                    "ip": ip,
                    "mac": mac,
                    "hostname": dev_info.get("hostname", ""),
                    "vendor": vendor,
                    "device_type": dev_info.get("device_type", "unknown"),
                    "anomaly_score": 0.0,
                    "sources": {source},
                    "first_seen": datetime.utcnow().isoformat() + "Z",
                    "last_seen": datetime.utcnow().isoformat() + "Z",
                    "traffic_stats": {},
                }

                if ip:
                    self.ip_to_device[ip] = canonical_id
                if mac:
                    self.mac_to_device[mac] = canonical_id

    def _add_links(self, links: list):
        """Add LLDP/physical links to graph."""
        for link in links:
            src = link.get("src", "")
            dst = link.get("dst", "")
            if src and dst:
                # Resolve to canonical IDs
                src_id = self.ip_to_device.get(src, src)
                dst_id = self.ip_to_device.get(dst, dst)
                # Ensure devices exist
                for did in [src_id, dst_id]:
                    if did not in self.devices:
                        self.devices[did] = {
                            "device_id": did,
                            "ip": "",
                            "mac": "",
                            "hostname": did,
                            "vendor": "",
                            "device_type": "unknown",
                            "anomaly_score": 0.0,
                            "sources": {"lldp"},
                            "first_seen": datetime.utcnow().isoformat() + "Z",
                            "last_seen": datetime.utcnow().isoformat() + "Z",
                            "traffic_stats": {},
                        }

    def _add_traffic_edges(self, edges: list):
        """Add NetFlow traffic edges to graph."""
        for edge in edges:
            src_ip = edge.get("src", "")
            dst_ip = edge.get("dst", "")

            # Ensure devices exist for IPs
            for ip in [src_ip, dst_ip]:
                if ip and ip not in self.devices:
                    self.devices[ip] = {
                        "device_id": ip,
                        "ip": ip,
                        "mac": "",
                        "hostname": f"host-{ip.split('.')[-1]}",
                        "vendor": "Unknown",
                        "device_type": "unknown",
                        "anomaly_score": 0.0,
                        "sources": {"netflow"},
                        "first_seen": edge.get("first_seen", ""),
                        "last_seen": edge.get("last_seen", ""),
                        "traffic_stats": {},
                    }
                    self.ip_to_device[ip] = ip

    def _update_traffic_stats(self, device_traffic: dict):
        """Update per-device traffic statistics from NetFlow."""
        for ip, stats in device_traffic.items():
            dev_id = self.ip_to_device.get(ip, ip)
            if dev_id in self.devices:
                self.devices[dev_id]["traffic_stats"] = stats

    def _process_security_events(self, events: list, suspicious_ips: dict):
        """Process syslog security events and update device risk scores."""
        for ip, risk_info in suspicious_ips.items():
            dev_id = self.ip_to_device.get(ip, ip)
            if dev_id in self.devices:
                current_score = self.devices[dev_id].get("anomaly_score", 0)
                syslog_score = risk_info.get("risk_score", 0)
                # Blend syslog risk with existing score
                self.devices[dev_id]["anomaly_score"] = max(current_score, syslog_score)

        # Create alerts from high-severity events
        for event in events:
            if event.get("risk_score", 0) >= 0.5:
                self.alerts.append({
                    "id": len(self.alerts) + 1,
                    "timestamp": event.get("timestamp", ""),
                    "device_id": event.get("src_ip", event.get("host", "")),
                    "alert_type": event.get("type", "unknown"),
                    "severity": event.get("severity", "warning"),
                    "score": event.get("risk_score", 0),
                    "description": self._describe_event(event),
                    "resolved": False,
                })

    @staticmethod
    def _describe_event(event: dict) -> str:
        """Generate human-readable description for a security event."""
        event_type = event.get("type", "")
        descriptions = {
            "firewall_drop": (
                f"Firewall blocked {event.get('protocol', 'TCP')} connection from "
                f"{event.get('src_ip', '?')} to {event.get('dst_ip', '?')}:"
                f"{event.get('dst_port', '?')}"
            ),
            "ssh_failed_login": (
                f"Failed SSH login for user '{event.get('user', '?')}' from "
                f"{event.get('src_ip', '?')} on {event.get('host', '?')}"
            ),
            "suspect_traffic": (
                f"Suspicious traffic: {event.get('bytes', 0)} bytes from "
                f"{event.get('src_ip', '?')} to {event.get('dst_ip', '?')}"
            ),
            "large_transfer": (
                f"Large data transfer ({event.get('transfer_size', '?')}) "
                f"to {event.get('dst_ip', '?')} from {event.get('host', '?')}"
            ),
            "periodic_connection": (
                f"Periodic connection (interval={event.get('interval', '?')}) from "
                f"{event.get('src_ip', '?')} to {event.get('dst_ip', '?')}"
            ),
        }
        return descriptions.get(event_type, f"Security event: {event_type}")

    def _process_dns_data(self, threats: list, suspicious: dict):
        """Process DNS threat indicators and update device risk scores."""
        for ip, risk_info in suspicious.items():
            dev_id = self.ip_to_device.get(ip, ip)
            if dev_id in self.devices:
                current_score = self.devices[dev_id].get("anomaly_score", 0)
                dns_score = risk_info.get("risk_score", 0)
                self.devices[dev_id]["anomaly_score"] = max(current_score, dns_score)

        # Create alerts from DNS threats
        for threat in threats:
            if threat.get("risk_score", 0) >= 0.5:
                self.alerts.append({
                    "id": len(self.alerts) + 1,
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "device_id": threat.get("client_ip", ""),
                    "alert_type": threat.get("type", "dns_anomaly"),
                    "severity": threat.get("severity", "warning"),
                    "score": threat.get("risk_score", 0),
                    "description": threat.get("description", ""),
                    "resolved": False,
                })

    def _process_dhcp_data(self, threats: list, suspicious: dict):
        """Process DHCP threat indicators and update device risk scores."""
        for key, risk_info in suspicious.items():
            dev_id = self.ip_to_device.get(key, key)
            if dev_id in self.devices:
                current_score = self.devices[dev_id].get("anomaly_score", 0)
                dhcp_score = risk_info.get("risk_score", 0)
                self.devices[dev_id]["anomaly_score"] = max(current_score, dhcp_score)

        # Create alerts from DHCP threats
        for threat in threats:
            if threat.get("risk_score", 0) >= 0.5:
                device_id = (
                    threat.get("client_ip")
                    or threat.get("server_ip")
                    or threat.get("client_mac", "")
                )
                self.alerts.append({
                    "id": len(self.alerts) + 1,
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "device_id": device_id,
                    "alert_type": threat.get("type", "dhcp_anomaly"),
                    "severity": threat.get("severity", "warning"),
                    "score": threat.get("risk_score", 0),
                    "description": threat.get("description", ""),
                    "resolved": False,
                })

    def _attach_dns_stats(self, dns_stats: dict):
        """Attach DNS statistics to graph nodes as additional features."""
        for ip, stats in dns_stats.items():
            dev_id = self.ip_to_device.get(ip, ip)
            if dev_id in self.graph:
                self.graph.nodes[dev_id]["dns_stats"] = stats

    # ─── Graph Building ─────────────────────────────────────

    def _build_graph(self):
        """Build networkx DiGraph from discovered devices and edges."""
        self.graph.clear()

        # Add device nodes
        for dev_id, dev_info in self.devices.items():
            self.graph.add_node(
                dev_id,
                ip=dev_info.get("ip", ""),
                mac=dev_info.get("mac", ""),
                hostname=dev_info.get("hostname", ""),
                vendor=dev_info.get("vendor", ""),
                device_type=dev_info.get("device_type", ""),
                anomaly_score=dev_info.get("anomaly_score", 0.0),
                sources=list(dev_info.get("sources", set())),
                traffic_stats=dev_info.get("traffic_stats", {}),
            )

        # Add edges from NetFlow
        for edge in self.netflow.get_edges():
            src = edge.get("src", "")
            dst = edge.get("dst", "")
            if src in self.graph and dst in self.graph:
                self.graph.add_edge(
                    src, dst,
                    protocol=edge.get("protocol", ""),
                    total_bytes=edge.get("total_bytes", 0),
                    total_packets=edge.get("total_packets", 0),
                    flow_count=edge.get("flow_count", 0),
                    avg_duration=edge.get("avg_duration", 0),
                    bytes_per_packet=edge.get("bytes_per_packet", 0),
                    unique_ports=edge.get("unique_ports", 0),
                    first_seen=edge.get("first_seen", ""),
                    last_seen=edge.get("last_seen", ""),
                )

        # Add edges from LLDP links
        for link in self.lldp.get_links():
            src = link.get("src", "")
            dst = link.get("dst", "")
            if src in self.graph and dst in self.graph:
                if not self.graph.has_edge(src, dst):
                    self.graph.add_edge(
                        src, dst,
                        protocol="LLDP",
                        total_bytes=0,
                        total_packets=0,
                        flow_count=0,
                        avg_duration=0,
                        bytes_per_packet=0,
                        unique_ports=0,
                        first_seen=link.get("timestamp", ""),
                        last_seen=link.get("timestamp", ""),
                    )

    # ─── SQLite Persistence ──────────────────────────────────

    def _save_to_db(self):
        """Persist current topology to SQLite."""
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()

            # Upsert devices
            for dev_id, dev in self.devices.items():
                sources = dev.get("sources", set())
                sources_str = ",".join(sources) if isinstance(sources, set) else str(sources)
                c.execute("""
                    INSERT OR REPLACE INTO devices
                    (device_id, ip, mac, hostname, vendor, device_type,
                     anomaly_score, first_seen, last_seen, is_active)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
                """, (
                    dev_id,
                    dev.get("ip", ""),
                    dev.get("mac", ""),
                    dev.get("hostname", ""),
                    dev.get("vendor", ""),
                    dev.get("device_type", ""),
                    dev.get("anomaly_score", 0.0),
                    dev.get("first_seen", ""),
                    dev.get("last_seen", ""),
                ))

            # Insert connections
            for src, dst, data in self.graph.edges(data=True):
                c.execute("""
                    INSERT INTO connections
                    (src_device, dst_device, protocol, bytes, packets,
                     first_seen, last_seen, anomaly_score)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    src, dst,
                    data.get("protocol", ""),
                    data.get("total_bytes", 0),
                    data.get("total_packets", 0),
                    data.get("first_seen", ""),
                    data.get("last_seen", ""),
                    data.get("anomaly_score", 0.0),
                ))

            # Insert alerts
            for alert in self.alerts:
                c.execute("""
                    INSERT OR IGNORE INTO alerts
                    (timestamp, device_id, alert_type, severity, score,
                     description, resolved)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    alert.get("timestamp", ""),
                    alert.get("device_id", ""),
                    alert.get("alert_type", ""),
                    alert.get("severity", ""),
                    alert.get("score", 0),
                    alert.get("description", ""),
                    0,
                ))

            conn.commit()
            conn.close()
            logger.info("Topology saved to SQLite")

        except sqlite3.Error as e:
            logger.error(f"Database error: {e}")

    def load_from_db(self):
        """Load topology from SQLite database."""
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()

            # Load devices
            c.execute("SELECT * FROM devices WHERE is_active = 1")
            columns = [desc[0] for desc in c.description]
            for row in c.fetchall():
                dev = dict(zip(columns, row))
                dev_id = dev["device_id"]
                dev["sources"] = set()
                dev["traffic_stats"] = {}
                self.devices[dev_id] = dev
                if dev.get("ip"):
                    self.ip_to_device[dev["ip"]] = dev_id
                if dev.get("mac"):
                    self.mac_to_device[dev["mac"]] = dev_id

            # Load alerts
            c.execute("SELECT * FROM alerts WHERE resolved = 0 ORDER BY timestamp DESC")
            columns = [desc[0] for desc in c.description]
            self.alerts = [dict(zip(columns, row)) for row in c.fetchall()]

            conn.close()
            self._build_graph()
            logger.info(f"Loaded {len(self.devices)} devices from database")

        except sqlite3.Error as e:
            logger.error(f"Database load error: {e}")

    # ─── Snapshot for GNN ────────────────────────────────────

    def get_snapshot(self) -> dict:
        """
        Get current topology snapshot for GNN inference.
        Returns a dict with nodes, edges, and metadata.
        """
        nodes = []
        for node_id, data in self.graph.nodes(data=True):
            nodes.append({
                "id": node_id,
                **{k: v for k, v in data.items() if k != "traffic_stats"},
                "traffic": data.get("traffic_stats", {}),
            })

        edges = []
        for src, dst, data in self.graph.edges(data=True):
            edges.append({"src": src, "dst": dst, **data})

        snapshot = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "node_count": self.graph.number_of_nodes(),
            "edge_count": self.graph.number_of_edges(),
            "nodes": nodes,
            "edges": edges,
            "alerts": [a for a in self.alerts if not a.get("resolved")],
        }

        self.snapshots.append(snapshot)
        return snapshot

    def get_graph(self) -> nx.DiGraph:
        """Get the current networkx graph."""
        return self.graph

    def get_alerts(self) -> list:
        return [a for a in self.alerts if not a.get("resolved")]

    def get_device(self, device_id: str) -> Optional[dict]:
        """Get device info by ID or IP."""
        if device_id in self.devices:
            return self.devices[device_id]
        resolved = self.ip_to_device.get(device_id)
        if resolved:
            return self.devices.get(resolved)
        return None

    def get_stats(self) -> dict:
        """Get system-wide statistics."""
        scores = [d.get("anomaly_score", 0) for d in self.devices.values()]
        return {
            "total_devices": len(self.devices),
            "total_edges": self.graph.number_of_edges(),
            "active_alerts": len(self.get_alerts()),
            "avg_anomaly_score": sum(scores) / len(scores) if scores else 0,
            "max_anomaly_score": max(scores) if scores else 0,
            "device_types": dict(
                defaultdict(int, {
                    d.get("device_type", "unknown"): 1
                    for d in self.devices.values()
                })
            ),
        }

    # ─── Continuous Monitoring ───────────────────────────────

    def start_monitoring(self, interval: Optional[int] = None):
        """Start continuous topology monitoring in background thread."""
        self._running = True
        self._monitor_thread = threading.Thread(
            target=self._monitor_loop,
            args=(interval or DISCOVERY_CONFIG["snapshot_interval"],),
            daemon=True,
        )
        self._monitor_thread.start()
        logger.info("Topology monitoring started")

    def stop_monitoring(self):
        """Stop continuous monitoring."""
        self._running = False
        logger.info("Topology monitoring stopped")

    def _monitor_loop(self, interval: int):
        """Background monitoring loop."""
        while self._running:
            try:
                with self._lock:
                    self.run_discovery()
            except Exception as e:
                logger.error(f"Monitoring error: {e}")
            time.sleep(interval)

    # ─── Sample Data Convenience ─────────────────────────────

    def load_sample_data(self):
        """Load and process all sample data files."""
        self.run_discovery()
        return self.get_snapshot()
