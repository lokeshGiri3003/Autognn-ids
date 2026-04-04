"""
Attack Explainer
Uses GAT attention weights and node features to explain WHY a node
was flagged as anomalous and WHAT type of attack is likely occurring.

Provides:
  1. Feature importance — which features contributed most to the score
  2. Attention analysis — which neighbor connections are most suspicious
  3. Attack classification — maps behavior patterns to known attack types
  4. Attack path tracing — traces multi-hop attack paths through the graph
"""
import logging
from collections import defaultdict
from typing import Optional

import numpy as np
import torch
import networkx as nx
from torch_geometric.data import Data

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from config import ATTACK_TYPES, THRESHOLD_CONFIG
from gnn_engine.feature_extractor import FeatureExtractor
from gnn_engine.model import AutoGNNIDS

logger = logging.getLogger("autognn.explainer")


class AttackExplainer:
    """
    Explain why the GNN flagged a node as anomalous.
    Combines attention weights, feature analysis, and behavioral rules
    to produce human-readable attack explanations.
    """

    def __init__(self, model: AutoGNNIDS,
                 feature_extractor: FeatureExtractor):
        self.model = model
        self.feature_extractor = feature_extractor

        # Feature names for human-readable output
        self.feature_names = feature_extractor.get_feature_names()

    def explain_node(self, data: Data, node_id: str,
                     graph: Optional[nx.DiGraph] = None) -> dict:
        """
        Generate a full explanation for why a node was flagged.

        Args:
            data: PyG Data object from feature extractor
            node_id: The node ID to explain
            graph: Optional networkx graph for additional context

        Returns:
            Dict with feature importance, attention analysis,
            attack classification, and attack paths
        """
        node_idx = self.feature_extractor.get_node_idx(node_id)
        if node_idx < 0:
            return {"error": f"Node {node_id} not found"}

        # Run model to get attention weights and scores
        self.model.eval()
        data_device = next(self.model.parameters()).device
        data = data.to(data_device)

        with torch.no_grad():
            output = self.model(data)

        anomaly_score = float(
            self.model.get_anomaly_scores(data)[node_idx].cpu()
        )

        # 1. Feature importance
        feature_importance = self._analyze_features(data, output, node_idx)

        # 2. Attention analysis
        attention_analysis = self._analyze_attention(
            data, output, node_idx
        )

        # 3. Attack classification
        attack_type = self._classify_attack(
            data, node_idx, feature_importance, graph
        )

        # 4. Attack path tracing
        attack_paths = []
        if graph is not None:
            attack_paths = self._trace_attack_paths(
                data, output, node_idx, graph
            )

        # 5. Generate human-readable summary
        summary = self._generate_summary(
            node_id, anomaly_score, attack_type,
            feature_importance, attention_analysis
        )

        return {
            "node_id": node_id,
            "anomaly_score": round(anomaly_score, 4),
            "alert_level": self._get_alert_level(anomaly_score),
            "attack_type": attack_type,
            "summary": summary,
            "feature_importance": feature_importance,
            "suspicious_connections": attention_analysis,
            "attack_paths": attack_paths,
        }

    def _analyze_features(self, data: Data, output: dict,
                          node_idx: int) -> list[dict]:
        """
        Determine which features contributed most to the anomaly score.
        Compares the node's features against the dataset mean.
        """
        node_features = data.x[node_idx].cpu().numpy()
        mean_features = data.x.mean(dim=0).cpu().numpy()
        std_features = data.x.std(dim=0).cpu().numpy()

        # Feature reconstruction error per feature
        recon_features = output["feat_recon"][node_idx].cpu().numpy()
        recon_error = np.abs(node_features - recon_features)

        feature_names = self.feature_names["node_features"]
        importances = []

        for i, name in enumerate(feature_names):
            std = float(std_features[i]) if std_features[i] > 1e-8 else 1.0
            z_score = float(
                abs(node_features[i] - mean_features[i]) / std
            )

            importances.append({
                "feature": name,
                "value": round(float(node_features[i]), 4),
                "mean": round(float(mean_features[i]), 4),
                "z_score": round(z_score, 2),
                "recon_error": round(float(recon_error[i]), 4),
                "is_unusual": z_score > 2.0,
            })

        # Sort by z-score (most unusual first)
        importances.sort(key=lambda x: x["z_score"], reverse=True)

        return importances

    def _analyze_attention(self, data: Data, output: dict,
                           node_idx: int) -> list[dict]:
        """
        Analyze GAT attention weights to find the most suspicious
        neighbor connections for this node.
        """
        attention_data = output.get("attention_weights")
        if attention_data is None:
            return []

        edge_index, attention_weights = attention_data
        edge_index = edge_index.cpu().numpy()
        attention_weights = attention_weights.cpu().numpy()

        # Find edges involving this node
        suspicious = []
        for edge_idx in range(edge_index.shape[1]):
            src = int(edge_index[0, edge_idx])
            dst = int(edge_index[1, edge_idx])

            if src != node_idx and dst != node_idx:
                continue

            # Get the other node
            neighbor_idx = dst if src == node_idx else src
            neighbor_id = self.feature_extractor.get_node_id(neighbor_idx)
            direction = "outgoing" if src == node_idx else "incoming"

            # Attention weight for this edge
            attn_weight = float(attention_weights[edge_idx].mean())

            # Edge features if available
            edge_info = {}
            if hasattr(data, "edge_attr") and data.edge_attr is not None:
                edge_feats = data.edge_attr[edge_idx].cpu().numpy()
                edge_names = self.feature_names["edge_features"]
                for j, ename in enumerate(edge_names):
                    edge_info[ename] = round(float(edge_feats[j]), 4)

            suspicious.append({
                "neighbor_id": neighbor_id,
                "direction": direction,
                "attention_weight": round(attn_weight, 4),
                "edge_features": edge_info,
            })

        # Sort by attention weight (highest attention = most relevant)
        suspicious.sort(
            key=lambda x: x["attention_weight"], reverse=True
        )

        return suspicious[:10]  # Top 10 most attended connections

    def _classify_attack(self, data: Data, node_idx: int,
                         feature_importance: list,
                         graph: Optional[nx.DiGraph]) -> dict:
        """
        Classify the type of attack based on behavioral patterns.
        Uses rules from config.ATTACK_TYPES.
        """
        features = data.x[node_idx].cpu().numpy()
        feature_names = self.feature_names["node_features"]
        feat_dict = dict(zip(feature_names, features))

        matches = []

        # Check for port scan
        scan_rules = ATTACK_TYPES["scan"]
        if (feat_dict.get("unique_dests", 0) * 100 >= scan_rules["min_unique_dests"]
                and feat_dict.get("port_count", 0) * 100 >= scan_rules["min_port_count"]):
            confidence = min(1.0, (
                feat_dict.get("unique_dests", 0) * 50
                + feat_dict.get("port_count", 0) * 50
            ) / 100)
            matches.append({
                "type": "port_scan",
                "confidence": round(confidence, 2),
                "description": (
                    "High number of unique destinations and ports contacted, "
                    "consistent with network scanning behavior"
                ),
                "indicators": ["high unique_dests", "high port_count"],
            })

        # Check for lateral movement
        lat_rules = ATTACK_TYPES["lateral_movement"]
        if feat_dict.get("conn_count", 0) * 100 >= lat_rules["min_conn_freq"]:
            if graph is not None:
                node_id = self.feature_extractor.get_node_id(node_idx)
                if node_id in graph:
                    out_degree = graph.out_degree(node_id)
                    if out_degree >= 3:
                        matches.append({
                            "type": "lateral_movement",
                            "confidence": round(min(1.0, out_degree / 10), 2),
                            "description": (
                                f"Node connecting to {out_degree} other devices "
                                f"with high connection frequency"
                            ),
                            "indicators": [
                                "high conn_count", f"out_degree={out_degree}"
                            ],
                        })

        # Check for data exfiltration
        exfil_rules = ATTACK_TYPES["exfiltration"]
        bytes_in = max(feat_dict.get("bytes_in", 0), 1e-8)
        bytes_out = feat_dict.get("bytes_out", 0)
        out_ratio = bytes_out / bytes_in
        if out_ratio >= exfil_rules["min_bytes_out_ratio"]:
            matches.append({
                "type": "data_exfiltration",
                "confidence": round(min(1.0, out_ratio / 10), 2),
                "description": (
                    f"Outbound bytes {out_ratio:.1f}× higher than inbound, "
                    f"consistent with data exfiltration"
                ),
                "indicators": [f"bytes_out/bytes_in={out_ratio:.1f}"],
            })

        # Check for C2 beaconing
        c2_rules = ATTACK_TYPES["c2"]
        # High DNS queries + regular connections = C2 pattern
        if (feat_dict.get("dns_total_queries", 0) > 0.3
                and feat_dict.get("conn_count", 0) > 0.3):
            matches.append({
                "type": "c2_beaconing",
                "confidence": round(min(1.0, (
                    feat_dict.get("dns_total_queries", 0)
                    + feat_dict.get("conn_count", 0)
                )), 2),
                "description": (
                    "High DNS query volume combined with frequent connections, "
                    "consistent with C2 beaconing behavior"
                ),
                "indicators": [
                    "high dns_total_queries", "high conn_count"
                ],
            })

        # Check for DGA/DNS anomalies
        if feat_dict.get("dns_nxdomain_ratio", 0) > 0.3:
            matches.append({
                "type": "dga_activity",
                "confidence": round(
                    feat_dict.get("dns_nxdomain_ratio", 0), 2
                ),
                "description": (
                    f"High DNS failure rate "
                    f"({feat_dict.get('dns_nxdomain_ratio', 0):.0%} NXDOMAIN), "
                    f"consistent with Domain Generation Algorithm"
                ),
                "indicators": ["high dns_nxdomain_ratio"],
            })

        # Sort by confidence
        matches.sort(key=lambda x: x["confidence"], reverse=True)

        if matches:
            return {
                "primary": matches[0],
                "all_matches": matches,
            }
        else:
            return {
                "primary": {
                    "type": "unknown",
                    "confidence": 0.0,
                    "description": "Anomalous behavior detected but no known pattern matched",
                    "indicators": [
                        f.get("feature", "")
                        for f in feature_importance[:3]
                        if f.get("is_unusual")
                    ],
                },
                "all_matches": [],
            }

    def _trace_attack_paths(self, data: Data, output: dict,
                            node_idx: int,
                            graph: nx.DiGraph) -> list[dict]:
        """
        Trace potential multi-hop attack paths through the network graph.
        Follows high-anomaly-score nodes connected by high-attention edges.
        """
        node_id = self.feature_extractor.get_node_id(node_idx)
        if node_id not in graph:
            return []

        scores = self.model.get_anomaly_scores(data).cpu().numpy()

        paths = []

        # BFS from the anomalous node, following high-score neighbors
        visited = {node_id}
        queue = [(node_id, [node_id])]

        while queue and len(paths) < 5:
            current, path = queue.pop(0)

            if len(path) > 5:  # Max path length
                continue

            current_idx = self.feature_extractor.get_node_idx(current)
            if current_idx < 0:
                continue

            # Check all neighbors
            for neighbor in list(graph.successors(current)) + list(
                graph.predecessors(current)
            ):
                if neighbor in visited:
                    continue

                neighbor_idx = self.feature_extractor.get_node_idx(neighbor)
                if neighbor_idx < 0:
                    continue

                neighbor_score = float(scores[neighbor_idx])

                # Follow the path if neighbor also has elevated score
                if neighbor_score >= self.score_mean + self.score_std:
                    new_path = path + [neighbor]
                    visited.add(neighbor)
                    queue.append((neighbor, new_path))

                    if len(new_path) >= 2:
                        # Record this as a potential attack path
                        path_scores = []
                        for p_node in new_path:
                            p_idx = self.feature_extractor.get_node_idx(
                                p_node
                            )
                            if p_idx >= 0:
                                path_scores.append(float(scores[p_idx]))

                        paths.append({
                            "path": new_path,
                            "length": len(new_path),
                            "avg_score": round(
                                float(np.mean(path_scores)), 4
                            ),
                            "max_score": round(
                                float(np.max(path_scores)), 4
                            ),
                            "node_scores": {
                                n: round(s, 4)
                                for n, s in zip(new_path, path_scores)
                            },
                        })

        # Sort by average score
        paths.sort(key=lambda x: x["avg_score"], reverse=True)

        return paths

    def _get_alert_level(self, score: float) -> str:
        """Get alert level from score."""
        for level, (low, high) in THRESHOLD_CONFIG["alert_levels"].items():
            if low <= score < high:
                return level
        return "critical"

    def _generate_summary(self, node_id: str, score: float,
                          attack_type: dict, features: list,
                          attention: list) -> str:
        """Generate a human-readable explanation summary."""
        level = self._get_alert_level(score)
        primary = attack_type.get("primary", {})

        lines = [
            f"🚨 {level.upper()} ALERT — Node: {node_id}",
            f"   Anomaly Score: {score:.2f}",
            f"   Suspected Attack: {primary.get('type', 'unknown').replace('_', ' ').title()}",
            f"   Confidence: {primary.get('confidence', 0):.0%}",
            "",
            f"   Why: {primary.get('description', 'Unknown anomaly')}",
        ]

        # Add unusual features
        unusual = [f for f in features if f.get("is_unusual")]
        if unusual:
            lines.append("")
            lines.append("   Unusual Features:")
            for f in unusual[:5]:
                lines.append(
                    f"     • {f['feature']}: {f['value']:.4f} "
                    f"(mean={f['mean']:.4f}, {f['z_score']:.1f}σ away)"
                )

        # Add suspicious connections
        if attention:
            lines.append("")
            lines.append("   Most Suspicious Connections:")
            for conn in attention[:3]:
                lines.append(
                    f"     • {conn['direction']} → {conn['neighbor_id']} "
                    f"(attention={conn['attention_weight']:.3f})"
                )

        return "\n".join(lines)

    def explain_all_anomalies(self, data: Data,
                              detection_results: dict,
                              graph: Optional[nx.DiGraph] = None) -> list:
        """
        Explain all anomalous nodes from a detection run.

        Args:
            data: PyG Data object
            detection_results: Output from Trainer.detect()
            graph: Optional networkx graph

        Returns:
            List of explanation dicts for each anomalous node
        """
        explanations = []

        for alert in detection_results.get("alerts", []):
            node_id = alert.get("node_id", "")
            if node_id:
                explanation = self.explain_node(data, node_id, graph)
                explanations.append(explanation)

        return explanations
