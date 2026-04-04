"""
Trainer
Handles the self-learning training loop for AutoGNN-IDS.

Training strategy:
  1. Collect topology snapshots over a baseline period
  2. Train the autoencoder on "normal" traffic patterns
  3. After training, switch to inference mode
  4. Continue adapting with online learning (optional)

The model learns to reconstruct normal network behavior.
Anything it CAN'T reconstruct well is anomalous.
"""
import logging
import time
from pathlib import Path
from datetime import datetime
from typing import Optional

import numpy as np
import torch
import torch.optim as optim
from torch_geometric.data import Data
from sklearn.ensemble import IsolationForest

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from config import MODEL_CONFIG, THRESHOLD_CONFIG, MODEL_DIR, SQLITE_DB_PATH
from gnn_engine.model import AutoGNNIDS
from gnn_engine.feature_extractor import FeatureExtractor

logger = logging.getLogger("autognn.trainer")


class Trainer:
    """
    Self-learning trainer for AutoGNN-IDS.

    Phases:
        1. Baseline collection: gather N snapshots of "normal" traffic
        2. Training: train autoencoder on baseline data
        3. Inference: detect anomalies using reconstruction error
        4. Online adaptation: periodically retrain on confirmed-normal data
    """

    def __init__(self, model: Optional[AutoGNNIDS] = None,
                 feature_extractor: Optional[FeatureExtractor] = None):
        self.model = model or AutoGNNIDS()
        self.feature_extractor = feature_extractor or FeatureExtractor()

        # Training state
        self.device = torch.device(
            "cuda" if torch.cuda.is_available() else "cpu"
        )
        self.model = self.model.to(self.device)
        self.optimizer = optim.Adam(
            self.model.parameters(),
            lr=MODEL_CONFIG["learning_rate"],
            weight_decay=MODEL_CONFIG["weight_decay"],
        )

        # Baseline data
        self.baseline_snapshots: list[Data] = []
        self.is_trained = False
        self.training_history: list[dict] = []

        # Anomaly threshold (learned from training data)
        self.threshold: float = 0.5
        self.score_mean: float = 0.0
        self.score_std: float = 1.0

        # Isolation Forest for secondary anomaly detection
        self.isolation_forest: Optional[IsolationForest] = None

        logger.info(f"Trainer initialized (device: {self.device})")

    # ─── Baseline Collection ─────────────────────────────────

    def add_baseline_snapshot(self, graph_or_snapshot) -> bool:
        """
        Add a topology snapshot to the baseline collection.

        Args:
            graph_or_snapshot: Either a networkx DiGraph
                               or a snapshot dict from TopologyBuilder

        Returns:
            True if snapshot was successfully added
        """
        try:
            if isinstance(graph_or_snapshot, dict):
                data = self.feature_extractor.extract_from_snapshot(
                    graph_or_snapshot
                )
            else:
                data = self.feature_extractor.extract(graph_or_snapshot)

            if data is None:
                logger.warning("Failed to extract features from snapshot")
                return False

            self.baseline_snapshots.append(data)
            logger.info(
                f"Baseline snapshot {len(self.baseline_snapshots)} added "
                f"({data.num_nodes} nodes, {data.edge_index.size(1)} edges)"
            )
            return True

        except Exception as e:
            logger.error(f"Error adding baseline snapshot: {e}")
            return False

    def has_enough_baseline(self, min_snapshots: int = 5) -> bool:
        """Check if we have enough baseline data to start training."""
        return len(self.baseline_snapshots) >= min_snapshots

    # ─── Training ────────────────────────────────────────────

    def train(self, epochs: Optional[int] = None,
              verbose: bool = True) -> dict:
        """
        Train the model on collected baseline snapshots.

        Args:
            epochs: Number of training epochs (uses config default if None)
            verbose: Print progress every 10 epochs

        Returns:
            Dict with training metrics
        """
        if not self.baseline_snapshots:
            logger.error("No baseline data to train on")
            return {"error": "No baseline data"}

        epochs = epochs or MODEL_CONFIG["epochs"]
        self.model.train()

        logger.info(
            f"Starting training: {epochs} epochs, "
            f"{len(self.baseline_snapshots)} snapshots"
        )

        start_time = time.time()
        best_loss = float("inf")
        patience_counter = 0
        patience = 15  # Early stopping patience

        for epoch in range(epochs):
            epoch_losses = []

            for data in self.baseline_snapshots:
                data = data.to(self.device)

                self.optimizer.zero_grad()
                output = self.model(data)
                loss_dict = self.model.compute_loss(data, output)
                total_loss = loss_dict["total_loss"]

                total_loss.backward()
                torch.nn.utils.clip_grad_norm_(
                    self.model.parameters(), max_norm=1.0
                )
                self.optimizer.step()

                epoch_losses.append({
                    "total": total_loss.item(),
                    "adj": loss_dict["adj_loss"],
                    "feat": loss_dict["feat_loss"],
                    "reg": loss_dict["reg_loss"],
                })

            # Average losses for this epoch
            avg_loss = np.mean([l["total"] for l in epoch_losses])
            avg_adj = np.mean([l["adj"] for l in epoch_losses])
            avg_feat = np.mean([l["feat"] for l in epoch_losses])

            self.training_history.append({
                "epoch": epoch + 1,
                "total_loss": float(avg_loss),
                "adj_loss": float(avg_adj),
                "feat_loss": float(avg_feat),
                "timestamp": datetime.utcnow().isoformat() + "Z",
            })

            # Early stopping
            if avg_loss < best_loss:
                best_loss = avg_loss
                patience_counter = 0
            else:
                patience_counter += 1

            if patience_counter >= patience:
                logger.info(
                    f"Early stopping at epoch {epoch + 1} "
                    f"(no improvement for {patience} epochs)"
                )
                break

            if verbose and (epoch + 1) % 10 == 0:
                logger.info(
                    f"Epoch {epoch + 1}/{epochs} — "
                    f"Loss: {avg_loss:.4f} "
                    f"(adj: {avg_adj:.4f}, feat: {avg_feat:.4f})"
                )

        duration = time.time() - start_time

        # Compute anomaly threshold from training data
        self._compute_threshold()

        # Train isolation forest on embeddings
        self._train_isolation_forest()

        self.is_trained = True

        # Save model
        model_path = str(MODEL_DIR / "autognn_ids_model.pt")
        self.model.save_model(model_path)

        result = {
            "epochs_trained": len(self.training_history),
            "final_loss": float(best_loss),
            "threshold": self.threshold,
            "duration_seconds": round(duration, 1),
            "model_path": model_path,
        }

        logger.info(
            f"Training complete in {duration:.1f}s — "
            f"Final loss: {best_loss:.4f}, Threshold: {self.threshold:.4f}"
        )

        return result

    def _compute_threshold(self):
        """
        Compute anomaly threshold from training data using 3-sigma rule.
        Normal nodes should have low reconstruction error.
        The threshold is set at mean + 3*sigma.
        """
        self.model.eval()
        all_scores = []

        with torch.no_grad():
            for data in self.baseline_snapshots:
                data = data.to(self.device)
                scores = self.model.get_anomaly_scores(data)
                all_scores.extend(scores.cpu().numpy().tolist())

        all_scores = np.array(all_scores)
        self.score_mean = float(np.mean(all_scores))
        self.score_std = float(np.std(all_scores))

        sigma = THRESHOLD_CONFIG["sigma_multiplier"]
        self.threshold = min(
            self.score_mean + sigma * self.score_std,
            0.95  # Cap at 0.95 to avoid never alerting
        )

        logger.info(
            f"Threshold computed: {self.threshold:.4f} "
            f"(mean={self.score_mean:.4f}, std={self.score_std:.4f}, "
            f"sigma={sigma})"
        )

    def _train_isolation_forest(self):
        """
        Train Isolation Forest on node embeddings as secondary detector.
        This catches anomalies that the reconstruction approach might miss.
        """
        self.model.eval()
        all_embeddings = []

        with torch.no_grad():
            for data in self.baseline_snapshots:
                data = data.to(self.device)
                output = self.model(data)
                embeddings = output["embeddings"].cpu().numpy()
                all_embeddings.append(embeddings)

        if all_embeddings:
            X = np.vstack(all_embeddings)
            self.isolation_forest = IsolationForest(
                contamination=THRESHOLD_CONFIG["isolation_forest_contamination"],
                random_state=42,
                n_estimators=100,
            )
            self.isolation_forest.fit(X)
            logger.info(
                f"Isolation Forest trained on {X.shape[0]} samples "
                f"({X.shape[1]} features)"
            )

    # ─── Inference ───────────────────────────────────────────

    def detect(self, graph_or_snapshot) -> dict:
        """
        Run anomaly detection on a graph or snapshot.

        Args:
            graph_or_snapshot: networkx DiGraph or snapshot dict

        Returns:
            Dict with per-node scores, alerts, and metadata
        """
        if not self.is_trained:
            logger.warning("Model not trained yet. Using raw scores only.")

        # Extract features
        if isinstance(graph_or_snapshot, dict):
            data = self.feature_extractor.extract_from_snapshot(
                graph_or_snapshot
            )
        else:
            data = self.feature_extractor.extract(graph_or_snapshot)

        if data is None:
            return {"error": "Failed to extract features"}

        data = data.to(self.device)

        # Get anomaly scores from GNN
        self.model.eval()
        with torch.no_grad():
            output = self.model(data)
            gnn_scores = self.model.get_anomaly_scores(data)

        gnn_scores_np = gnn_scores.cpu().numpy()

        # Get Isolation Forest scores (if available)
        if self.isolation_forest is not None:
            embeddings = output["embeddings"].cpu().numpy()
            # IF returns -1 for anomalies, 1 for normal
            if_predictions = self.isolation_forest.predict(embeddings)
            # Convert to scores: -1 → 1.0 (anomaly), 1 → 0.0 (normal)
            if_scores = np.where(if_predictions == -1, 1.0, 0.0)
            # IF decision function (lower = more anomalous)
            if_raw = self.isolation_forest.decision_function(embeddings)
            if_raw_norm = 1.0 - (
                (if_raw - if_raw.min())
                / (if_raw.max() - if_raw.min() + 1e-8)
            )
        else:
            if_scores = np.zeros_like(gnn_scores_np)
            if_raw_norm = np.zeros_like(gnn_scores_np)

        # Combine GNN + IF scores
        combined_scores = 0.7 * gnn_scores_np + 0.3 * if_raw_norm

        # Classify each node
        node_results = []
        alerts = []
        alert_levels = THRESHOLD_CONFIG["alert_levels"]

        for idx in range(data.num_nodes):
            node_id = self.feature_extractor.get_node_id(idx)
            score = float(combined_scores[idx])

            # Determine alert level
            level = "normal"
            for level_name, (low, high) in alert_levels.items():
                if low <= score < high:
                    level = level_name
                    break
            if score >= alert_levels["critical"][0]:
                level = "critical"

            node_result = {
                "node_id": node_id,
                "anomaly_score": round(score, 4),
                "gnn_score": round(float(gnn_scores_np[idx]), 4),
                "if_score": round(float(if_raw_norm[idx]), 4),
                "alert_level": level,
                "is_anomalous": score >= self.threshold,
            }
            node_results.append(node_result)

            # Create alert for anomalous nodes
            if score >= self.threshold:
                alerts.append({
                    "node_id": node_id,
                    "score": round(score, 4),
                    "level": level,
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                })

        return {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "total_nodes": data.num_nodes,
            "anomalous_nodes": len(alerts),
            "threshold": self.threshold,
            "node_results": node_results,
            "alerts": alerts,
            "attention_weights": output["attention_weights"],
        }

    # ─── Online Learning ─────────────────────────────────────

    def online_update(self, graph_or_snapshot, update_epochs: int = 5):
        """
        Online adaptation: retrain on new snapshot (confirmed normal).
        Uses a lower learning rate for fine-tuning.

        Call this periodically on snapshots that the admin has confirmed
        as normal to keep the model adapted to evolving traffic patterns.
        """
        if isinstance(graph_or_snapshot, dict):
            data = self.feature_extractor.extract_from_snapshot(
                graph_or_snapshot
            )
        else:
            data = self.feature_extractor.extract(graph_or_snapshot)

        if data is None:
            return

        data = data.to(self.device)

        # Use lower learning rate for online updates
        fine_tune_lr = MODEL_CONFIG["learning_rate"] * 0.1
        fine_tune_optimizer = optim.Adam(
            self.model.parameters(),
            lr=fine_tune_lr,
            weight_decay=MODEL_CONFIG["weight_decay"],
        )

        self.model.train()
        for _ in range(update_epochs):
            fine_tune_optimizer.zero_grad()
            output = self.model(data)
            loss_dict = self.model.compute_loss(data, output)
            loss_dict["total_loss"].backward()
            fine_tune_optimizer.step()

        # Recompute threshold
        self._compute_threshold()

        logger.info(
            f"Online update complete ({update_epochs} epochs, "
            f"lr={fine_tune_lr:.6f})"
        )

    # ─── Model Management ────────────────────────────────────

    def save_state(self, path: Optional[str] = None):
        """Save full trainer state (model + threshold + stats)."""
        save_path = path or str(MODEL_DIR / "trainer_state.pt")
        state = {
            "model_state_dict": self.model.state_dict(),
            "optimizer_state_dict": self.optimizer.state_dict(),
            "threshold": self.threshold,
            "score_mean": self.score_mean,
            "score_std": self.score_std,
            "is_trained": self.is_trained,
            "training_history": self.training_history,
        }
        torch.save(state, save_path)
        logger.info(f"Trainer state saved to {save_path}")

    def load_state(self, path: Optional[str] = None):
        """Load full trainer state."""
        load_path = path or str(MODEL_DIR / "trainer_state.pt")
        if not Path(load_path).exists():
            logger.warning(f"No saved state found at {load_path}")
            return False

        state = torch.load(load_path, weights_only=False)
        self.model.load_state_dict(state["model_state_dict"])
        self.optimizer.load_state_dict(state["optimizer_state_dict"])
        self.threshold = state.get("threshold", 0.5)
        self.score_mean = state.get("score_mean", 0.0)
        self.score_std = state.get("score_std", 1.0)
        self.is_trained = state.get("is_trained", False)
        self.training_history = state.get("training_history", [])

        self.model = self.model.to(self.device)
        logger.info(f"Trainer state loaded from {load_path}")
        return True

    def get_training_summary(self) -> dict:
        """Get summary of training status."""
        return {
            "is_trained": self.is_trained,
            "baseline_snapshots": len(self.baseline_snapshots),
            "epochs_completed": len(self.training_history),
            "threshold": self.threshold,
            "score_mean": self.score_mean,
            "score_std": self.score_std,
            "device": str(self.device),
            "last_loss": (
                self.training_history[-1]["total_loss"]
                if self.training_history else None
            ),
        }
