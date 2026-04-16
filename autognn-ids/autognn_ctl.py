#!/usr/bin/env python3
"""
AutoGNN-IDS Control Tool
CLI commands for the network admin to control the system.

Usage:
    python autognn_ctl.py status              Show system status
    python autognn_ctl.py baseline start      Start collecting baseline data
    python autognn_ctl.py baseline stop       Stop collecting baseline data
    python autognn_ctl.py baseline clear      Clear all collected baselines
    python autognn_ctl.py train [name]        Train the model (optionally save as name)
    python autognn_ctl.py upgrade [name]      Upgrade (fine-tune) existing model
    python autognn_ctl.py model list          List saved models
    python autognn_ctl.py model switch <name> Switch to a saved model
    python autognn_ctl.py model save <name>   Save the active model under a new name
    python autognn_ctl.py model delete <name> Delete a saved model
    python autognn_ctl.py detect              Switch to detection mode
    python autognn_ctl.py retrain             Collect new baselines + retrain
    python autognn_ctl.py stop                Stop the system
"""
import json
import sys
import os
from pathlib import Path
from datetime import datetime

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.resolve()
sys.path.insert(0, str(PROJECT_ROOT))

from config import STATE_FILE, TRAINING_CONFIG, MODEL_DIR


def load_state() -> dict:
    """Load current system state from file."""
    if STATE_FILE.exists():
        with open(STATE_FILE) as f:
            return json.load(f)

    # Default state
    return {
        "mode": "stopped",
        "baseline_count": 0,
        "baseline_start_time": None,
        "baseline_stop_time": None,
        "last_trained": None,
        "model_path": None,
        "training_loss": None,
        "threshold": None,
        "detection_cycles": 0,
        "total_alerts": 0,
        "last_detection": None,
        "created_at": datetime.utcnow().isoformat() + "Z",
    }


def save_state(state: dict):
    """Save system state to file."""
    state["updated_at"] = datetime.utcnow().isoformat() + "Z"
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)


def print_status(state: dict):
    """Display current system status."""
    mode = state.get("mode", "stopped")
    mode_icons = {
        "stopped": "⏹️",
        "baseline": "📊",
        "training": "🧠",
        "upgrading": "✨",
        "detection": "🛡️",
    }

    print()
    print("══════════════════════════════════════════════════")
    print(f"  AutoGNN-IDS Status")
    print("══════════════════════════════════════════════════")
    print()
    print(f"  Mode:              {mode_icons.get(mode, '❓')}  {mode.upper()}")
    print(f"  Baselines:         {state.get('baseline_count', 0)} snapshots")

    if state.get("baseline_start_time"):
        print(f"  Baseline started:  {state['baseline_start_time']}")
    if state.get("baseline_stop_time"):
        print(f"  Baseline stopped:  {state['baseline_stop_time']}")

    min_baselines = TRAINING_CONFIG["min_baseline_snapshots"]
    count = state.get("baseline_count", 0)
    if count < min_baselines:
        print(f"  Ready to train:    ❌ Need {min_baselines - count} more snapshots")
    else:
        print(f"  Ready to train:    ✅ Yes ({count} ≥ {min_baselines})")

    if state.get("last_trained"):
        print(f"  Last trained:      {state['last_trained']}")
        print(f"  Training loss:     {state.get('training_loss', 'N/A')}")
        print(f"  Threshold:         {state.get('threshold', 'N/A')}")
        print(f"  Model:             {state.get('model_path', 'N/A')}")

    if mode == "detection":
        print(f"  Detection cycles:  {state.get('detection_cycles', 0)}")
        print(f"  Total alerts:      {state.get('total_alerts', 0)}")
        if state.get("last_detection"):
            print(f"  Last detection:    {state['last_detection']}")

    auto_train = TRAINING_CONFIG["auto_train_threshold"]
    if auto_train > 0:
        print(f"  Auto-train at:     {auto_train} snapshots")
    else:
        print(f"  Auto-train:        Disabled (manual only)")

    print()
    print("══════════════════════════════════════════════════")
    print()


def cmd_status():
    """Show system status."""
    state = load_state()
    print_status(state)


def cmd_baseline_start():
    """Start collecting baseline data."""
    state = load_state()

    if state["mode"] == "baseline":
        print("⚠️  Already collecting baselines.")
        print(f"   Snapshots so far: {state.get('baseline_count', 0)}")
        return

    if state["mode"] == "detection":
        print("⚠️  System is in detection mode.")
        print("   Use 'retrain' to restart baseline collection.")
        return

    state["mode"] = "baseline"
    state["baseline_start_time"] = datetime.utcnow().isoformat() + "Z"
    state["baseline_stop_time"] = None
    save_state(state)

    print("✅ Baseline collection STARTED")
    print()
    print("   The system is now collecting normal traffic snapshots.")
    print("   Let it run for as long as you want (recommended: 24 hours).")
    print()
    print("   Commands:")
    print("     python autognn_ctl.py status         Check progress")
    print("     python autognn_ctl.py baseline stop   Stop collecting")
    print("     python autognn_ctl.py train           Train the model")
    print()


def cmd_baseline_stop():
    """Stop collecting baseline data."""
    state = load_state()

    if state["mode"] != "baseline":
        print(f"⚠️  Not in baseline mode (current: {state['mode']})")
        return

    state["mode"] = "stopped"
    state["baseline_stop_time"] = datetime.utcnow().isoformat() + "Z"
    save_state(state)

    count = state.get("baseline_count", 0)
    min_needed = TRAINING_CONFIG["min_baseline_snapshots"]

    print(f"✅ Baseline collection STOPPED ({count} snapshots)")
    print()

    if count >= min_needed:
        print("   Ready to train! Run:")
        print("     python autognn_ctl.py train")
    else:
        print(f"   ⚠️  Only {count} snapshots (minimum: {min_needed})")
        print("   Restart baseline collection to gather more:")
        print("     python autognn_ctl.py baseline start")
    print()


def cmd_baseline_clear():
    """Clear all collected baseline data."""
    state = load_state()

    if state["mode"] == "baseline":
        print("⚠️  Stop baseline collection first:")
        print("     python autognn_ctl.py baseline stop")
        return

    # Clear baseline pickle files if they exist
    baseline_dir = MODEL_DIR / "baselines"
    if baseline_dir.exists():
        import shutil
        shutil.rmtree(baseline_dir)
        baseline_dir.mkdir(parents=True, exist_ok=True)

    state["baseline_count"] = 0
    state["baseline_start_time"] = None
    state["baseline_stop_time"] = None
    save_state(state)

    print("✅ All baseline data cleared")
    print()


def cmd_train(model_name: str = None):
    """Train the model on collected baselines."""
    state = load_state()

    if state["mode"] == "baseline":
        print("⚠️  Stop baseline collection first:")
        print("     python autognn_ctl.py baseline stop")
        return

    count = state.get("baseline_count", 0)
    min_needed = TRAINING_CONFIG["min_baseline_snapshots"]

    if count < min_needed:
        print(f"❌ Not enough baseline data: {count}/{min_needed}")
        print("   Collect more baselines first:")
        print("     python autognn_ctl.py baseline start")
        return

    state["mode"] = "training"
    if model_name:
        state["target_model_name"] = model_name
    elif "target_model_name" in state:
        del state["target_model_name"]
        
    save_state(state)

    print(f"🧠 Training started on {count} snapshots...")
    print("   This will take ~2-5 minutes.")
    print()
    print("   The main process will pick up this command and train.")
    print("   Check progress with:")
    print("     python autognn_ctl.py status")
    print()


def cmd_upgrade(model_name: str = None):
    """Upgrade (fine-tune) the existing model with collected baselines."""
    state = load_state()

    if state["mode"] == "baseline":
        print("⚠️  Stop baseline collection first:")
        print("     python autognn_ctl.py baseline stop")
        return

    # Check if a model exists
    trainer_state_path = MODEL_DIR / "trainer_state.pt"
    if not trainer_state_path.exists():
        print("❌ No existing model found to upgrade. Use 'train' instead.")
        return

    count = state.get("baseline_count", 0)
    if count == 0:
        print("❌ No baseline data. Collect baselines first:")
        print("     python autognn_ctl.py baseline start")
        return

    state["mode"] = "upgrading"
    if model_name:
        state["target_model_name"] = model_name
    elif "target_model_name" in state:
        del state["target_model_name"]
        
    save_state(state)

    print(f"✨ Upgrading model using {count} new snapshots...")
    print("   This will take ~1-3 minutes.")
    print()
    print("   The main process will pick up this command and upgrade.")
    print("   Check progress with:")
    print("     python autognn_ctl.py status")
    print()


def cmd_detect():
    """Switch to detection mode."""
    state = load_state()

    if not state.get("last_trained"):
        print("❌ Model not trained yet.")
        print("   Train first:")
        print("     python autognn_ctl.py train")
        return

    state["mode"] = "detection"
    state["detection_cycles"] = 0
    save_state(state)

    print("🛡️  Detection mode ACTIVATED")
    print()
    print("   The GNN is now monitoring for anomalies.")
    print("   Rule-based alerts (DNS, DHCP, Syslog) are also active.")
    print()
    print("   View alerts:")
    print("     Dashboard: http://localhost:8501")
    print("     API:       http://localhost:8000/api/alerts")
    print()


def cmd_retrain():
    """Reset to baseline mode for retraining."""
    state = load_state()

    state["mode"] = "baseline"
    state["baseline_count"] = 0
    state["baseline_start_time"] = datetime.utcnow().isoformat() + "Z"
    state["baseline_stop_time"] = None
    save_state(state)

    # Clear old baselines
    baseline_dir = MODEL_DIR / "baselines"
    if baseline_dir.exists():
        import shutil
        shutil.rmtree(baseline_dir)
    baseline_dir.mkdir(parents=True, exist_ok=True)

    print("🔄 Retrain mode started")
    print()
    print("   Old baselines cleared. Collecting fresh baseline data.")
    print("   Let it run, then:")
    print("     python autognn_ctl.py baseline stop")
    print("     python autognn_ctl.py train")
    print()


def cmd_model(args):
    """Manage multiple named models."""
    state = load_state()
    trainer_state_path = MODEL_DIR / "trainer_state.pt"

    if len(args) == 0:
        print("Usage: python autognn_ctl.py model [list|switch|save|delete] <name>")
        return

    subcmd = args[0]

    if subcmd == "list":
        print("Available models:")
        count = 0
        for path in MODEL_DIR.glob("*.pt"):
            if path.name == "trainer_state.pt" or path.name == "autognn_ids_model.pt":
                continue
            print(f"  - {path.stem}")
            count += 1
        if count == 0:
            print("  (No saved models found)")
        print()

    elif subcmd == "switch":
        if len(args) < 2:
            print("Usage: python autognn_ctl.py model switch <name>")
            return
        name = args[1]
        target_path = MODEL_DIR / f"{name}.pt"
        if not target_path.exists():
            print(f"❌ Model '{name}' not found at: {target_path}")
            return
        try:
            import shutil
            shutil.copy2(target_path, trainer_state_path)
            print(f"✅ Switched to model '{name}'.")
            
            # Update state to reflect trained status
            state["mode"] = "stopped"
            state["last_trained"] = datetime.utcnow().isoformat() + "Z"
            state["model_path"] = str(trainer_state_path)
            state["baseline_count"] = 0
            save_state(state)
        except Exception as e:
            print(f"❌ Error switching model: {e}")

    elif subcmd == "save":
        if len(args) < 2:
            print("Usage: python autognn_ctl.py model save <name>")
            return
        name = args[1]
        if not trainer_state_path.exists():
            print("❌ No active model to save (trainer_state.pt not found). Train a model first.")
            return
        target_path = MODEL_DIR / f"{name}.pt"
        try:
            import shutil
            shutil.copy2(trainer_state_path, target_path)
            print(f"✅ Active model saved as '{name}'.")
        except Exception as e:
            print(f"❌ Error saving model: {e}")

    elif subcmd == "delete":
        if len(args) < 2:
            print("Usage: python autognn_ctl.py model delete <name>")
            return
        name = args[1]
        target_path = MODEL_DIR / f"{name}.pt"
        if not target_path.exists():
            print(f"❌ Model '{name}' not found.")
            return
        try:
            target_path.unlink()
            print(f"✅ Model '{name}' deleted.")
        except Exception as e:
            print(f"❌ Error deleting model '{name}': {e}")
            
    else:
        print(f"Unknown model subcommand: {subcmd}")


def cmd_stop():
    """Stop the system."""
    state = load_state()
    state["mode"] = "stopped"
    save_state(state)

    print("⏹️  System STOPPED")
    print("   Data collection and detection paused.")
    print()


def cmd_help():
    """Show help."""
    print()
    print("AutoGNN-IDS Control Tool")
    print("════════════════════════════════════════════════════")
    print()
    print("  Workflow:")
    print("    1. Start baseline:  python autognn_ctl.py baseline start")
    print("    2. Wait (hours/days) for normal traffic collection")
    print("    3. Stop baseline:   python autognn_ctl.py baseline stop")
    print("    4. Train model:     python autognn_ctl.py train")
    print("    5. Start detection: python autognn_ctl.py detect")
    print()
    print("  Commands:")
    print("    status              Show system status")
    print("    baseline start      Start collecting baseline data")
    print("    baseline stop       Stop collecting baseline data")
    print("    baseline clear      Clear all collected baselines")
    print("    train [name]        Train the model (optionally save as name)")
    print("    upgrade [name]      Upgrade (fine-tune) the existing model")
    print("    model list          List saved models")
    print("    model switch <name> Switch to a saved model (e.g., autognn)")
    print("    model save <name>   Save the active model under a new name")
    print("    model delete <name> Delete a saved model")
    print("    detect              Switch to detection mode")
    print("    retrain             Clear baselines and start fresh")
    print("    stop                Stop the system")
    print("    help                Show this help")
    print()
    print("  Environment Variables:")
    print("    AUTOGNN_MIN_BASELINES=10    Min snapshots before training")
    print("    AUTOGNN_AUTO_TRAIN=0        Auto-train at N snapshots (0=manual)")
    print("    AUTOGNN_USE_SAMPLE=true     Use sample data (for testing)")
    print()


def main():
    args = sys.argv[1:]

    if not args or args[0] == "help":
        cmd_help()
    elif args[0] == "status":
        cmd_status()
    elif args[0] == "baseline":
        if len(args) < 2:
            print("Usage: python autognn_ctl.py baseline [start|stop|clear]")
            return
        if args[1] == "start":
            cmd_baseline_start()
        elif args[1] == "stop":
            cmd_baseline_stop()
        elif args[1] == "clear":
            cmd_baseline_clear()
        else:
            print(f"Unknown: baseline {args[1]}")
    elif args[0] == "train":
        model_name = args[1] if len(args) > 1 else None
        cmd_train(model_name)
    elif args[0] == "upgrade":
        model_name = args[1] if len(args) > 1 else None
        cmd_upgrade(model_name)
    elif args[0] == "model":
        cmd_model(args[1:])
    elif args[0] == "detect":
        cmd_detect()
    elif args[0] == "retrain":
        cmd_retrain()
    elif args[0] == "stop":
        cmd_stop()
    else:
        print(f"Unknown command: {args[0]}")
        cmd_help()


if __name__ == "__main__":
    main()
