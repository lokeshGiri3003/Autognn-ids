"""
NetFlow Collector
Parses NetFlow v9/sFlow export files from a log directory.
Watches for new flow files using filesystem monitoring.
Extracts traffic flow edges for the network graph.
"""
import json
import os
import logging
from pathlib import Path
from datetime import datetime
from collections import defaultdict
from typing import Optional

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from config import LOG_PATHS, SAMPLE_DATA_DIR, USE_SAMPLE_DATA

logger = logging.getLogger("autognn.netflow")


class NetFlowCollector:
    """Collect and parse NetFlow records from export files."""

    def __init__(self):
        self.flows: list[dict] = []
        self.edges: list[dict] = []
        self.device_traffic: dict[str, dict] = defaultdict(lambda: {
            "bytes_in": 0, "bytes_out": 0,
            "packets_in": 0, "packets_out": 0,
            "connections": [], "protocols": set(),
            "dest_ips": set(), "dest_ports": set(),
        })
        self._processed_files: set[str] = set()

    def parse_sample_data(self) -> list[dict]:
        """Load NetFlow records from sample JSON."""
        sample_file = SAMPLE_DATA_DIR / "netflow_records.json"
        if not sample_file.exists():
            logger.warning(f"Sample NetFlow data not found: {sample_file}")
            return []

        with open(sample_file) as f:
            self.flows = json.load(f)

        logger.info(f"Loaded {len(self.flows)} NetFlow records from sample data")
        self._process_flows()
        return self.flows

    def parse_flow_directory(self, dirpath: Optional[str] = None) -> list[dict]:
        """
        Parse all flow files in the NetFlow export directory.
        Supports JSON format. Tracks processed files to avoid re-parsing.
        """
        flow_dir = Path(dirpath) if dirpath else Path(LOG_PATHS["netflow_dir"])
        if not flow_dir.exists():
            logger.warning(f"NetFlow directory not found: {flow_dir}")
            return []

        new_flows = []
        for filepath in sorted(flow_dir.glob("*.json")):
            if str(filepath) in self._processed_files:
                continue

            try:
                with open(filepath) as f:
                    records = json.load(f)
                    if isinstance(records, list):
                        new_flows.extend(records)
                    elif isinstance(records, dict):
                        new_flows.append(records)
                self._processed_files.add(str(filepath))
            except (json.JSONDecodeError, IOError) as e:
                logger.error(f"Error parsing {filepath}: {e}")

        self.flows.extend(new_flows)
        if new_flows:
            logger.info(f"Parsed {len(new_flows)} new flow records from {flow_dir}")
            self._process_flows()

        return new_flows

    def parse_flow_file(self, filepath: str) -> list[dict]:
        """Parse a single NetFlow export file."""
        path = Path(filepath)
        if not path.exists():
            logger.warning(f"Flow file not found: {path}")
            return []

        try:
            with open(path) as f:
                records = json.load(f)
                if isinstance(records, dict):
                    records = [records]

            self.flows.extend(records)
            logger.info(f"Parsed {len(records)} flow records from {path}")
            self._process_flows()
            return records

        except (json.JSONDecodeError, IOError) as e:
            logger.error(f"Error parsing {path}: {e}")
            return []

    def _process_flows(self):
        """Process raw flows into edges and per-device traffic stats."""
        self.edges.clear()
        # Reset device traffic
        self.device_traffic = defaultdict(lambda: {
            "bytes_in": 0, "bytes_out": 0,
            "packets_in": 0, "packets_out": 0,
            "connections": [], "protocols": set(),
            "dest_ips": set(), "dest_ports": set(),
        })

        edge_aggregation: dict[tuple, dict] = {}

        for flow in self.flows:
            src_ip = flow.get("src_ip", "")
            dst_ip = flow.get("dst_ip", "")
            protocol = flow.get("protocol", "unknown")
            bytes_count = flow.get("bytes", 0)
            packets = flow.get("packets", 0)
            duration = flow.get("duration", 0)
            src_port = flow.get("src_port", 0)
            dst_port = flow.get("dst_port", 0)
            timestamp = flow.get("timestamp", "")

            if not src_ip or not dst_ip:
                continue

            # Update device traffic stats (source)
            src_traffic = self.device_traffic[src_ip]
            src_traffic["bytes_out"] += bytes_count
            src_traffic["packets_out"] += packets
            src_traffic["protocols"].add(protocol)
            src_traffic["dest_ips"].add(dst_ip)
            src_traffic["dest_ports"].add(dst_port)
            src_traffic["connections"].append({
                "dst_ip": dst_ip, "dst_port": dst_port,
                "protocol": protocol, "bytes": bytes_count,
                "duration": duration, "timestamp": timestamp,
            })

            # Update device traffic stats (destination)
            dst_traffic = self.device_traffic[dst_ip]
            dst_traffic["bytes_in"] += bytes_count
            dst_traffic["packets_in"] += packets

            # Aggregate edges
            edge_key = (src_ip, dst_ip)
            if edge_key not in edge_aggregation:
                edge_aggregation[edge_key] = {
                    "src": src_ip,
                    "dst": dst_ip,
                    "protocols": set(),
                    "total_bytes": 0,
                    "total_packets": 0,
                    "flow_count": 0,
                    "durations": [],
                    "ports": set(),
                    "first_seen": timestamp,
                    "last_seen": timestamp,
                    "bytes_per_flow": [],
                }

            edge = edge_aggregation[edge_key]
            edge["protocols"].add(protocol)
            edge["total_bytes"] += bytes_count
            edge["total_packets"] += packets
            edge["flow_count"] += 1
            edge["durations"].append(duration)
            edge["ports"].add(dst_port)
            edge["bytes_per_flow"].append(bytes_count)
            if timestamp > edge["last_seen"]:
                edge["last_seen"] = timestamp
            if timestamp < edge["first_seen"]:
                edge["first_seen"] = timestamp

        # Convert aggregated edges to list
        for key, edge in edge_aggregation.items():
            avg_duration = (
                sum(edge["durations"]) / len(edge["durations"])
                if edge["durations"] else 0
            )
            total_packets = edge["total_packets"] or 1
            self.edges.append({
                "src": edge["src"],
                "dst": edge["dst"],
                "protocol": ",".join(sorted(edge["protocols"])),
                "total_bytes": edge["total_bytes"],
                "total_packets": edge["total_packets"],
                "flow_count": edge["flow_count"],
                "avg_duration": avg_duration,
                "bytes_per_packet": edge["total_bytes"] / total_packets,
                "unique_ports": len(edge["ports"]),
                "first_seen": edge["first_seen"],
                "last_seen": edge["last_seen"],
                "source": "netflow",
            })

    def get_edges(self) -> list:
        return self.edges

    def get_device_traffic(self) -> dict:
        """Get per-device traffic statistics."""
        result = {}
        for ip, stats in self.device_traffic.items():
            result[ip] = {
                "bytes_in": stats["bytes_in"],
                "bytes_out": stats["bytes_out"],
                "packets_in": stats["packets_in"],
                "packets_out": stats["packets_out"],
                "unique_dests": len(stats["dest_ips"]),
                "port_count": len(stats["dest_ports"]),
                "conn_count": len(stats["connections"]),
                "protocol_count": len(stats["protocols"]),
                "protocols": list(stats["protocols"]),
            }
        return result

    def discover(self) -> tuple[list, dict]:
        """Run discovery: returns (edges, device_traffic)."""
        if USE_SAMPLE_DATA:
            self.parse_sample_data()
        else:
            self.parse_flow_directory()

        return self.edges, self.get_device_traffic()
