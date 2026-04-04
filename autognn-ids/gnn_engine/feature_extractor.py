"""
Feature Extractor
Converts network topology snapshots (networkx graph) into PyTorch Geometric
Data objects suitable for GNN inference.

Node features (12-dim):
  0: bytes_in, 1: bytes_out, 2: packets_in, 3: packets_out,
  4: unique_dests, 5: port_count, 6: conn_count,
  7: syslog_risk_score, 8: dns_total_queries, 9: dns_unique_domains,
  10: dns_nxdomain_ratio, 11: device_type_encoded

Edge features (8-dim):
  0: total_bytes, 1: total_packets, 2: flow_count, 3: avg_duration,
  4: bytes_per_packet, 5: unique_ports, 6: protocol_encoded,
  7: is_bidirectional
"""
import logging
from typing import Optional

import numpy as np
import networkx as nx
import torch
from torch_geometric.data import Data

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from config import MODEL_CONFIG

logger = logging.getLogger("autognn.features")

# Protocol encoding map
PROTOCOL_MAP = {
    "tcp": 0.2, "udp": 0.4, "icmp": 0.6, "lldp": 0.8,
    "arp": 1.0, "": 0.0, "unknown": 0.0,
}

# Device type encoding map
DEVICE_TYPE_MAP = {
    "router": 0.1, "l3_switch": 0.15, "switch": 0.2, "firewall": 0.25,
    "server": 0.4, "virtual_machine": 0.5, "endpoint": 0.6,
    "network_device": 0.3, "iot_device": 0.7, "consumer_device": 0.8,
    "unknown": 0.0,
}


class FeatureExtractor:
    """
    Convert network topology snapshots into PyTorch Geometric Data objects.

    The extractor:
    1. Maps networkx nodes to integer indices
    2. Extracts and normalizes node features (12-dim)
    3. Extracts and normalizes edge features (8-dim)
    4. Builds edge_index tensor (COO format)
    5. Returns a PyG Data object ready for GNN inference
    """

    def __init__(self):
        self.node_feature_dim = MODEL_CONFIG["node_feature_dim"]
        self.edge_feature_dim = MODEL_CONFIG["edge_feature_dim"]
        self.node_id_to_idx: dict[str, int] = {}
        self.idx_to_node_id: dict[int, str] = {}
        self._feature_stats: dict[str, dict] = {}  # running stats for normalization

    def extract(self, graph: nx.DiGraph) -> Optional[Data]:
        """
        Convert a networkx DiGraph into a PyG Data object.

        Args:
            graph: NetworkX directed graph from TopologyBuilder

        Returns:
            PyG Data object with x (node features), edge_index,
            edge_attr, and metadata, or None if graph is empty.
        """
        if graph.number_of_nodes() == 0:
            logger.warning("Empty graph, cannot extract features")
            return None

        # Step 1: Build node ID ↔ index mapping
        self.node_id_to_idx = {}
        self.idx_to_node_id = {}
        for idx, node_id in enumerate(graph.nodes()):
            self.node_id_to_idx[node_id] = idx
            self.idx_to_node_id[idx] = node_id

        num_nodes = graph.number_of_nodes()
        num_edges = graph.number_of_edges()

        # Step 2: Extract raw node features
        raw_node_features = np.zeros((num_nodes, self.node_feature_dim), dtype=np.float32)

        for node_id, data in graph.nodes(data=True):
            idx = self.node_id_to_idx[node_id]
            raw_node_features[idx] = self._extract_node_features(data)

        # Step 3: Normalize node features
        node_features = self._normalize_features(raw_node_features, "node")

        # Step 4: Build edge index and edge features
        if num_edges > 0:
            edge_index = np.zeros((2, num_edges), dtype=np.int64)
            raw_edge_features = np.zeros(
                (num_edges, self.edge_feature_dim), dtype=np.float32
            )

            # Track bidirectional edges
            edge_set = set()
            for edge_idx, (src, dst, data) in enumerate(graph.edges(data=True)):
                src_idx = self.node_id_to_idx[src]
                dst_idx = self.node_id_to_idx[dst]
                edge_index[0, edge_idx] = src_idx
                edge_index[1, edge_idx] = dst_idx
                edge_set.add((src, dst))

                is_bidir = 1.0 if (dst, src) in edge_set else 0.0
                raw_edge_features[edge_idx] = self._extract_edge_features(
                    data, is_bidir
                )

            # Normalize edge features
            edge_features = self._normalize_features(raw_edge_features, "edge")
        else:
            # Self-loops as fallback for isolated nodes
            edge_index = np.array([[0], [0]], dtype=np.int64)
            edge_features = np.zeros((1, self.edge_feature_dim), dtype=np.float32)

        # Step 5: Build PyG Data object
        data = Data(
            x=torch.tensor(node_features, dtype=torch.float32),
            edge_index=torch.tensor(edge_index, dtype=torch.long),
            edge_attr=torch.tensor(edge_features, dtype=torch.float32),
            num_nodes=num_nodes,
        )

        # Attach metadata for later use (explainer, dashboard)
        data.node_ids = list(self.idx_to_node_id.values())
        data.node_id_to_idx = self.node_id_to_idx

        logger.info(
            f"Extracted features: {num_nodes} nodes × {self.node_feature_dim}D, "
            f"{num_edges} edges × {self.edge_feature_dim}D"
        )

        return data

    def extract_from_snapshot(self, snapshot: dict) -> Optional[Data]:
        """
        Convert a topology snapshot dict into a PyG Data object.
        Builds a temporary networkx graph from the snapshot, then extracts.

        Args:
            snapshot: Dict with 'nodes' and 'edges' lists from TopologyBuilder

        Returns:
            PyG Data object or None
        """
        graph = nx.DiGraph()

        for node in snapshot.get("nodes", []):
            node_id = node.get("id", "")
            if not node_id:
                continue
            graph.add_node(node_id, **{
                k: v for k, v in node.items() if k != "id"
            })

        for edge in snapshot.get("edges", []):
            src = edge.get("src", "")
            dst = edge.get("dst", "")
            if src and dst:
                graph.add_edge(src, dst, **{
                    k: v for k, v in edge.items()
                    if k not in ("src", "dst")
                })

        return self.extract(graph)

    def _extract_node_features(self, data: dict) -> np.ndarray:
        """
        Extract 12-dimensional feature vector for a single node.
        """
        features = np.zeros(self.node_feature_dim, dtype=np.float32)

        # Traffic stats (features 0-6)
        traffic = data.get("traffic_stats", data.get("traffic", {}))
        if isinstance(traffic, dict):
            features[0] = float(traffic.get("bytes_in", 0))
            features[1] = float(traffic.get("bytes_out", 0))
            features[2] = float(traffic.get("packets_in", 0))
            features[3] = float(traffic.get("packets_out", 0))
            features[4] = float(traffic.get("unique_dests", 0))
            features[5] = float(traffic.get("port_count", 0))
            features[6] = float(traffic.get("conn_count", 0))

        # Syslog risk score (feature 7)
        features[7] = float(data.get("anomaly_score", 0.0))

        # DNS stats (features 8-10)
        dns = data.get("dns_stats", {})
        if isinstance(dns, dict):
            features[8] = float(dns.get("total_queries", 0))
            features[9] = float(dns.get("unique_domains", 0))
            total_q = dns.get("total_queries", 0)
            nx_count = dns.get("nxdomain_count", 0)
            features[10] = (
                float(nx_count) / float(total_q)
                if total_q > 0 else 0.0
            )

        # Device type (feature 11)
        device_type = data.get("device_type", "unknown")
        features[11] = DEVICE_TYPE_MAP.get(device_type, 0.0)

        return features

    def _extract_edge_features(self, data: dict,
                                is_bidirectional: float) -> np.ndarray:
        """
        Extract 8-dimensional feature vector for a single edge.
        """
        features = np.zeros(self.edge_feature_dim, dtype=np.float32)

        features[0] = float(data.get("total_bytes", 0))
        features[1] = float(data.get("total_packets", 0))
        features[2] = float(data.get("flow_count", 0))
        features[3] = float(data.get("avg_duration", 0))
        features[4] = float(data.get("bytes_per_packet", 0))
        features[5] = float(data.get("unique_ports", 0))

        # Protocol encoding
        protocol = str(data.get("protocol", "")).lower().split(",")[0].strip()
        features[6] = PROTOCOL_MAP.get(protocol, 0.0)

        # Bidirectional flag
        features[7] = is_bidirectional

        return features

    def _normalize_features(self, features: np.ndarray,
                            feature_type: str) -> np.ndarray:
        """
        Normalize features using min-max scaling with running statistics.
        Features that are already in [0, 1] (like ratios) are left as-is.
        """
        normalized = features.copy()
        num_features = features.shape[1]

        # Columns that are already normalized (no scaling needed)
        if feature_type == "node":
            skip_cols = {7, 10, 11}  # anomaly_score, nxdomain_ratio, device_type
        else:
            skip_cols = {6, 7}  # protocol_encoded, is_bidirectional

        for col in range(num_features):
            if col in skip_cols:
                continue

            col_data = features[:, col]
            col_min = col_data.min()
            col_max = col_data.max()

            # Update running stats
            key = f"{feature_type}_{col}"
            if key not in self._feature_stats:
                self._feature_stats[key] = {
                    "min": col_min, "max": col_max
                }
            else:
                # Exponential moving average for running stats
                stats = self._feature_stats[key]
                alpha = 0.1
                stats["min"] = min(stats["min"], col_min)
                stats["max"] = stats["max"] * (1 - alpha) + col_max * alpha

            # Use running stats for normalization
            stats = self._feature_stats[key]
            range_val = stats["max"] - stats["min"]

            if range_val > 1e-8:
                normalized[:, col] = (col_data - stats["min"]) / range_val
            else:
                normalized[:, col] = 0.0

        # Clamp to [0, 1]
        normalized = np.clip(normalized, 0.0, 1.0)

        return normalized

    def get_node_id(self, idx: int) -> str:
        """Get original node ID from integer index."""
        return self.idx_to_node_id.get(idx, "")

    def get_node_idx(self, node_id: str) -> int:
        """Get integer index from original node ID."""
        return self.node_id_to_idx.get(node_id, -1)

    def get_feature_names(self) -> dict:
        """Get human-readable feature names for explainability."""
        return {
            "node_features": [
                "bytes_in", "bytes_out", "packets_in", "packets_out",
                "unique_dests", "port_count", "conn_count",
                "syslog_risk_score", "dns_total_queries",
                "dns_unique_domains", "dns_nxdomain_ratio",
                "device_type",
            ],
            "edge_features": [
                "total_bytes", "total_packets", "flow_count",
                "avg_duration", "bytes_per_packet", "unique_ports",
                "protocol", "is_bidirectional",
            ],
        }
