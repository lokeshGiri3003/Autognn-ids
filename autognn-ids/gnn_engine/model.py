"""
AutoGNN-IDS Model
Hybrid GAT + GraphSAGE autoencoder for anomaly detection on network graphs.

Architecture:
  Encoder:
    - GATConv layer (multi-head attention → learns WHICH neighbors matter)
    - GraphSAGE layer (neighborhood aggregation → learns behavioral embeddings)
  Decoder:
    - Inner-product adjacency reconstruction
    - Feature reconstruction MLP

Anomaly = high reconstruction error = behavior doesn't match learned "normal".
"""
import logging
from typing import Optional

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import GATConv, SAGEConv
from torch_geometric.data import Data

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from config import MODEL_CONFIG

logger = logging.getLogger("autognn.model")


class GATEncoder(nn.Module):
    """
    Graph Attention Network encoder.
    Multi-head attention learns which neighbor connections are most relevant
    for characterizing a node's behavior.
    """

    def __init__(self, in_dim: int, hidden_dim: int, heads: int,
                 dropout: float, edge_dim: int):
        super().__init__()
        self.gat1 = GATConv(
            in_channels=in_dim,
            out_channels=hidden_dim,
            heads=heads,
            dropout=dropout,
            edge_dim=edge_dim,
            concat=True,
        )
        self.gat2 = GATConv(
            in_channels=hidden_dim * heads,
            out_channels=hidden_dim,
            heads=1,
            dropout=dropout,
            edge_dim=edge_dim,
            concat=False,
        )
        self.dropout = dropout

    def forward(self, x: torch.Tensor, edge_index: torch.Tensor,
                edge_attr: Optional[torch.Tensor] = None):
        # First GAT layer with multi-head attention
        x = self.gat1(x, edge_index, edge_attr=edge_attr)
        x = F.elu(x)
        x = F.dropout(x, p=self.dropout, training=self.training)

        # Second GAT layer reduces to single head
        x, attention_weights = self.gat2(
            x, edge_index, edge_attr=edge_attr,
            return_attention_weights=True,
        )
        x = F.elu(x)

        return x, attention_weights


class SAGEEncoder(nn.Module):
    """
    GraphSAGE encoder.
    Aggregates neighborhood features to learn behavior-based embeddings.
    """

    def __init__(self, in_dim: int, hidden_dim: int, dropout: float):
        super().__init__()
        self.sage1 = SAGEConv(in_dim, hidden_dim)
        self.sage2 = SAGEConv(hidden_dim, hidden_dim)
        self.dropout = dropout

    def forward(self, x: torch.Tensor, edge_index: torch.Tensor):
        x = self.sage1(x, edge_index)
        x = F.relu(x)
        x = F.dropout(x, p=self.dropout, training=self.training)

        x = self.sage2(x, edge_index)
        x = F.relu(x)

        return x


class AdjacencyDecoder(nn.Module):
    """
    Reconstructs the adjacency matrix from node embeddings.
    Uses inner product: A_reconstructed[i,j] = sigmoid(z_i · z_j)
    """

    def forward(self, z: torch.Tensor, edge_index: torch.Tensor):
        src = z[edge_index[0]]
        dst = z[edge_index[1]]
        # Inner product for each edge
        return torch.sigmoid((src * dst).sum(dim=1))


class FeatureDecoder(nn.Module):
    """
    Reconstructs original node features from embeddings.
    MLP: embedding_dim → hidden → original_feature_dim
    """

    def __init__(self, embed_dim: int, hidden_dim: int, out_dim: int):
        super().__init__()
        self.mlp = nn.Sequential(
            nn.Linear(embed_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, out_dim),
        )

    def forward(self, z: torch.Tensor):
        return self.mlp(z)


class AnomalyScorer(nn.Module):
    """
    Maps node embeddings to a per-node anomaly score in [0, 1].
    MLP: embedding_dim → hidden → 1
    """

    def __init__(self, embed_dim: int, hidden_dim: int):
        super().__init__()
        self.mlp = nn.Sequential(
            nn.Linear(embed_dim, hidden_dim),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(hidden_dim, 1),
            nn.Sigmoid(),
        )

    def forward(self, z: torch.Tensor):
        return self.mlp(z).squeeze(-1)


class AutoGNNIDS(nn.Module):
    """
    AutoGNN-IDS: Full anomaly detection model.

    Combines GAT (attention-based) and GraphSAGE (aggregation-based) encoders
    with reconstruction decoders. Anomalies are nodes where the model
    fails to reconstruct normal behavior patterns.

    Forward pass returns:
        - node_embeddings: learned representations
        - anomaly_scores: per-node anomaly scores [0, 1]
        - adj_recon: reconstructed adjacency values
        - feat_recon: reconstructed node features
        - attention_weights: GAT attention (for explainability)
    """

    def __init__(
        self,
        node_feature_dim: int = None,
        edge_feature_dim: int = None,
        gat_hidden_dim: int = None,
        gat_heads: int = None,
        sage_hidden_dim: int = None,
        dropout: float = None,
    ):
        super().__init__()

        # Use config defaults if not specified
        nfd = node_feature_dim or MODEL_CONFIG["node_feature_dim"]
        efd = edge_feature_dim or MODEL_CONFIG["edge_feature_dim"]
        ghd = gat_hidden_dim or MODEL_CONFIG["gat_hidden_dim"]
        gh = gat_heads or MODEL_CONFIG["gat_heads"]
        shd = sage_hidden_dim or MODEL_CONFIG["sage_hidden_dim"]
        do = dropout if dropout is not None else MODEL_CONFIG["dropout"]

        # Total embedding dim = GAT output + SAGE output
        self.embed_dim = ghd + shd

        # Encoders
        self.gat_encoder = GATEncoder(nfd, ghd, gh, do, efd)
        self.sage_encoder = SAGEEncoder(nfd, shd, do)

        # Fusion layer (concatenate GAT + SAGE, then project)
        self.fusion = nn.Sequential(
            nn.Linear(self.embed_dim, self.embed_dim),
            nn.ReLU(),
            nn.Dropout(do),
        )

        # Decoders
        self.adj_decoder = AdjacencyDecoder()
        self.feat_decoder = FeatureDecoder(self.embed_dim, ghd, nfd)
        self.anomaly_scorer = AnomalyScorer(self.embed_dim, ghd)

        logger.info(
            f"AutoGNN-IDS model initialized: "
            f"node_dim={nfd}, edge_dim={efd}, "
            f"GAT({ghd}×{gh}heads) + SAGE({shd}), "
            f"embed_dim={self.embed_dim}"
        )

    def forward(self, data: Data) -> dict:
        """
        Forward pass through the full model.

        Args:
            data: PyG Data object with x, edge_index, edge_attr

        Returns:
            Dict with embeddings, scores, reconstructions, attention
        """
        x = data.x
        edge_index = data.edge_index
        edge_attr = data.edge_attr if hasattr(data, "edge_attr") else None

        # Encode with GAT (attention-based)
        z_gat, attention_weights = self.gat_encoder(x, edge_index, edge_attr)

        # Encode with GraphSAGE (aggregation-based)
        z_sage = self.sage_encoder(x, edge_index)

        # Fuse both encodings
        z = torch.cat([z_gat, z_sage], dim=1)
        z = self.fusion(z)

        # Decode: reconstruct adjacency
        adj_recon = self.adj_decoder(z, edge_index)

        # Decode: reconstruct features
        feat_recon = self.feat_decoder(z)

        # Score anomalies
        anomaly_scores = self.anomaly_scorer(z)

        return {
            "embeddings": z,
            "anomaly_scores": anomaly_scores,
            "adj_recon": adj_recon,
            "feat_recon": feat_recon,
            "attention_weights": attention_weights,
        }

    def compute_loss(self, data: Data, output: dict) -> dict:
        """
        Compute the combined training loss.

        Loss = w1 * adj_recon_loss + w2 * feat_recon_loss + w3 * reg_loss

        Args:
            data: Original input data
            output: Forward pass output dict

        Returns:
            Dict with total_loss and individual loss components
        """
        w_adj = MODEL_CONFIG["reconstruction_weight"]
        w_feat = MODEL_CONFIG["feature_recon_weight"]
        w_reg = MODEL_CONFIG["regularization_weight"]

        # 1. Adjacency reconstruction loss (BCE)
        # Target: 1.0 for all existing edges (we only reconstruct observed edges)
        edge_targets = torch.ones(
            output["adj_recon"].size(0),
            device=output["adj_recon"].device,
        )
        adj_loss = F.binary_cross_entropy(output["adj_recon"], edge_targets)

        # 2. Feature reconstruction loss (MSE)
        feat_loss = F.mse_loss(output["feat_recon"], data.x)

        # 3. L2 regularization on embeddings
        reg_loss = torch.mean(output["embeddings"] ** 2)

        # Combined loss
        total_loss = w_adj * adj_loss + w_feat * feat_loss + w_reg * reg_loss

        return {
            "total_loss": total_loss,
            "adj_loss": adj_loss.item(),
            "feat_loss": feat_loss.item(),
            "reg_loss": reg_loss.item(),
        }

    def get_anomaly_scores(self, data: Data) -> torch.Tensor:
        """
        Get per-node anomaly scores without full output.
        Used during inference.
        """
        self.eval()
        with torch.no_grad():
            output = self.forward(data)

            # Combine learned score with reconstruction error
            feat_error = torch.mean(
                (output["feat_recon"] - data.x) ** 2, dim=1
            )

            # Normalize reconstruction error to [0, 1]
            if feat_error.max() > feat_error.min():
                feat_error_norm = (
                    (feat_error - feat_error.min())
                    / (feat_error.max() - feat_error.min())
                )
            else:
                feat_error_norm = torch.zeros_like(feat_error)

            # Final score = blend of learned score + reconstruction error
            scores = (
                0.6 * output["anomaly_scores"]
                + 0.4 * feat_error_norm
            )

        return scores

    def save_model(self, path: str):
        """Save model weights."""
        torch.save(self.state_dict(), path)
        logger.info(f"Model saved to {path}")

    def load_model(self, path: str):
        """Load model weights."""
        self.load_state_dict(torch.load(path, weights_only=True))
        self.eval()
        logger.info(f"Model loaded from {path}")
