#!/usr/bin/env python3
"""
AutoGNN-IDS Control Tool
CLI commands for the network admin to control the system.

Usage:
    python autognn_ctl.py status              Show system status
    python autognn_ctl.py baseline start      Start collecting baseline data
    python autognn_ctl.py baseline stop       Stop collecting baseline data
    python autognn_ctl.py baseline clear      Clear all collected baselines
    python autognn_ctl.py train               Train the model on collected baselines
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


def cmd_train():
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
    save_state(state)

    print(f"🧠 Training started on {count} snapshots...")
    print("   This will take ~2-5 minutes.")
    print()
    print("   The main process will pick up this command and train.")
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
    print("    train               Train the model on collected baselines")
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
        cmd_train()
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
