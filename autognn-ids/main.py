#!/usr/bin/env python3
"""
AutoGNN-IDS Main Engine
The main process that runs continuously, responding to state changes
from autognn_ctl.py.

Modes:
  baseline  → Collect snapshots and store as training data
  training  → Train GNN model on collected baselines
  detection → Run anomaly detection every 30 seconds
  stopped   → Idle, waiting for commands
"""
import json
import sys
import time
import signal
import logging
import pickle
from pathlib import Path
from datetime import datetime

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.resolve()
sys.path.insert(0, str(PROJECT_ROOT))

from config import (
    STATE_FILE, TRAINING_CONFIG, DISCOVERY_CONFIG,
    MODEL_DIR, SQLITE_DB_PATH,
)
from network_discovery.topology_builder import TopologyBuilder
from gnn_engine.feature_extractor import FeatureExtractor
from gnn_engine.model import AutoGNNIDS
from gnn_engine.trainer import Trainer
from gnn_engine.explainer import AttackExplainer

# ─── Logging Setup ───────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(PROJECT_ROOT / "autognn_ids.log"),
    ],
)
logger = logging.getLogger("autognn.main")

# ─── Globals ─────────────────────────────────────────────────
running = True
BASELINE_DIR = MODEL_DIR / "baselines"


def signal_handler(sig, frame):
    """Handle graceful shutdown."""
    global running
    logger.info("Shutdown signal received")
    running = False


signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)


def load_state() -> dict:
    """Load system state from file."""
    if STATE_FILE.exists():
        with open(STATE_FILE) as f:
            return json.load(f)
    return {"mode": "stopped"}


def save_state(state: dict):
    """Save system state to file."""
    state["updated_at"] = datetime.utcnow().isoformat() + "Z"
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)


def save_baseline(snapshot_data, index: int):
    """Save a baseline snapshot to disk."""
    BASELINE_DIR.mkdir(parents=True, exist_ok=True)
    path = BASELINE_DIR / f"baseline_{index:06d}.pkl"
    with open(path, "wb") as f:
        pickle.dump(snapshot_data, f)


def load_baselines() -> list:
    """Load all saved baseline snapshots from disk."""
    if not BASELINE_DIR.exists():
        return []

    baselines = []
    for path in sorted(BASELINE_DIR.glob("baseline_*.pkl")):
        with open(path, "rb") as f:
            baselines.append(pickle.load(f))

    return baselines


def run_baseline_mode(topology: TopologyBuilder, state: dict) -> dict:
    """Collect one baseline snapshot."""
    logger.info("Baseline mode: collecting snapshot...")

    # Run network discovery
    topology.run_discovery()
    snapshot = topology.get_snapshot()

    # Save the snapshot
    count = state.get("baseline_count", 0) + 1
    save_baseline(snapshot, count)

    state["baseline_count"] = count
    state["last_snapshot_time"] = datetime.utcnow().isoformat() + "Z"
    state["last_snapshot_nodes"] = snapshot.get("node_count", 0)
    state["last_snapshot_edges"] = snapshot.get("edge_count", 0)

    # Check auto-train threshold
    auto_threshold = TRAINING_CONFIG["auto_train_threshold"]
    if auto_threshold > 0 and count >= auto_threshold:
        logger.info(
            f"Auto-train threshold reached ({count} >= {auto_threshold}). "
            f"Switching to training mode."
        )
        state["mode"] = "training"

    # Log rule-based alerts (these work immediately)
    alerts = topology.get_alerts()
    if alerts:
        for alert in alerts[-5:]:  # Log last 5
            logger.warning(
                f"Rule-based alert: [{alert.get('severity', '?')}] "
                f"{alert.get('alert_type', '?')} — "
                f"{alert.get('description', '')[:100]}"
            )

    logger.info(
        f"Baseline snapshot #{count} collected: "
        f"{snapshot.get('node_count', 0)} nodes, "
        f"{snapshot.get('edge_count', 0)} edges, "
        f"{len(alerts)} alerts"
    )

    return state


def run_training_mode(state: dict) -> dict:
    """Train the GNN model on collected baselines."""
    logger.info("Training mode: starting model training...")

    # Load baselines
    baselines = load_baselines()
    if not baselines:
        logger.error("No baseline data found!")
        state["mode"] = "stopped"
        return state

    min_needed = TRAINING_CONFIG["min_baseline_snapshots"]
    if len(baselines) < min_needed:
        logger.error(
            f"Not enough baselines: {len(baselines)}/{min_needed}"
        )
        state["mode"] = "stopped"
        return state

    # Create model and trainer
    model = AutoGNNIDS()
    feature_extractor = FeatureExtractor()
    trainer = Trainer(model, feature_extractor)

    # Add all baselines
    for i, snapshot in enumerate(baselines):
        success = trainer.add_baseline_snapshot(snapshot)
        if success:
            logger.info(f"  Loaded baseline {i + 1}/{len(baselines)}")

    if not trainer.has_enough_baseline(min_needed):
        logger.error("Failed to load enough valid baselines")
        state["mode"] = "stopped"
        return state

    # Train
    result = trainer.train(verbose=True)

    if "error" in result:
        logger.error(f"Training failed: {result['error']}")
        state["mode"] = "stopped"
        return state

    # Save trainer state
    trainer.save_state()

    # Update system state
    state["mode"] = "detection"
    state["last_trained"] = datetime.utcnow().isoformat() + "Z"
    state["training_loss"] = round(result.get("final_loss", 0), 4)
    state["threshold"] = round(result.get("threshold", 0.5), 4)
    state["model_path"] = result.get("model_path", "")
    state["training_epochs"] = result.get("epochs_trained", 0)
    state["training_duration"] = result.get("duration_seconds", 0)
    state["detection_cycles"] = 0
    state["total_alerts"] = 0

    logger.info(
        f"Training complete! "
        f"Loss: {state['training_loss']}, "
        f"Threshold: {state['threshold']}, "
        f"Duration: {state['training_duration']}s. "
        f"Switching to detection mode."
    )

    return state


def run_detection_mode(topology: TopologyBuilder, trainer: Trainer,
                        explainer: AttackExplainer,
                        state: dict) -> dict:
    """Run one detection cycle."""
    # Run network discovery
    topology.run_discovery()
    snapshot = topology.get_snapshot()
    graph = topology.get_graph()

    # Run GNN detection
    detection = trainer.detect(snapshot)

    cycle = state.get("detection_cycles", 0) + 1
    state["detection_cycles"] = cycle
    state["last_detection"] = datetime.utcnow().isoformat() + "Z"

    anomalous = detection.get("anomalous_nodes", 0)
    total = detection.get("total_nodes", 0)

    if anomalous > 0:
        state["total_alerts"] = state.get("total_alerts", 0) + anomalous

        # Explain anomalies
        data = trainer.feature_extractor.extract_from_snapshot(snapshot)
        if data is not None:
            explanations = explainer.explain_all_anomalies(
                data, detection, graph
            )

            for exp in explanations:
                attack = exp.get("attack_type", {}).get("primary", {})
                logger.warning(
                    f"🚨 ANOMALY: {exp.get('node_id', '?')} "
                    f"(score={exp.get('anomaly_score', 0):.2f}) — "
                    f"{attack.get('type', 'unknown')} "
                    f"({attack.get('confidence', 0):.0%} confidence)"
                )
                if exp.get("summary"):
                    for line in exp["summary"].split("\n")[:6]:
                        logger.warning(f"  {line}")

    # Online learning (periodic)
    online_interval = TRAINING_CONFIG["online_update_interval"]
    if online_interval > 0 and cycle % online_interval == 0 and anomalous == 0:
        logger.info(f"Online update at cycle {cycle}...")
        trainer.online_update(snapshot)

    logger.info(
        f"Detection cycle #{cycle}: "
        f"{total} nodes, {anomalous} anomalous, "
        f"{len(topology.get_alerts())} rule-based alerts"
    )

    return state


def main():
    """Main engine loop."""
    global running

    logger.info("═" * 50)
    logger.info("  AutoGNN-IDS Engine Starting")
    logger.info("═" * 50)

    # Initialize components
    topology = TopologyBuilder()
    model = None
    trainer = None
    explainer = None

    # Try to load existing model
    trainer_state_path = MODEL_DIR / "trainer_state.pt"
    if trainer_state_path.exists():
        logger.info("Loading saved model...")
        model = AutoGNNIDS()
        feature_extractor = FeatureExtractor()
        trainer = Trainer(model, feature_extractor)
        if trainer.load_state():
            explainer = AttackExplainer(model, feature_extractor)
            logger.info("Saved model loaded successfully")
        else:
            trainer = None
            explainer = None

    interval = DISCOVERY_CONFIG["snapshot_interval"]

    logger.info(f"Snapshot interval: {interval}s")
    logger.info(f"State file: {STATE_FILE}")
    logger.info(f"Min baselines: {TRAINING_CONFIG['min_baseline_snapshots']}")
    logger.info(f"Auto-train threshold: {TRAINING_CONFIG['auto_train_threshold']}")
    logger.info("")

    while running:
        try:
            state = load_state()
            mode = state.get("mode", "stopped")

            if mode == "baseline":
                state = run_baseline_mode(topology, state)
                save_state(state)

            elif mode == "training":
                state = run_training_mode(state)
                save_state(state)

                # Initialize detection components after training
                if state["mode"] == "detection":
                    model = AutoGNNIDS()
                    feature_extractor = FeatureExtractor()
                    trainer = Trainer(model, feature_extractor)
                    trainer.load_state()
                    explainer = AttackExplainer(model, feature_extractor)

            elif mode == "detection":
                if trainer is None:
                    # Need to load model
                    model = AutoGNNIDS()
                    feature_extractor = FeatureExtractor()
                    trainer = Trainer(model, feature_extractor)
                    if not trainer.load_state():
                        logger.error("No trained model found!")
                        state["mode"] = "stopped"
                        save_state(state)
                        continue
                    explainer = AttackExplainer(model, feature_extractor)

                state = run_detection_mode(
                    topology, trainer, explainer, state
                )
                save_state(state)

            elif mode == "stopped":
                pass  # Idle, just check state periodically

            else:
                logger.warning(f"Unknown mode: {mode}")

            # Wait for next cycle
            time.sleep(interval)

        except KeyboardInterrupt:
            break
        except Exception as e:
            logger.error(f"Engine error: {e}", exc_info=True)
            time.sleep(interval)

    logger.info("AutoGNN-IDS Engine stopped")


if __name__ == "__main__":
    main()
