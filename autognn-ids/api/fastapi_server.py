import json
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import aiosqlite
from pathlib import Path
import sys

# Add project root to sys.path so config can be imported securely
PROJECT_ROOT = Path(__file__).parent.parent.resolve()
sys.path.insert(0, str(PROJECT_ROOT))

from config import SQLITE_DB_PATH, STATE_FILE, API_CONFIG

app = FastAPI(
    title="AutoGNN-IDS API",
    description="Backend API for AutoGNN-IDS Dashboard",
    version="1.0.0"
)

# Allow CORS for dashboard
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/api/status")
async def get_status():
    """Retrieve the current state of the AutoGNN-IDS engine."""
    if STATE_FILE.exists():
        try:
            with open(STATE_FILE, "r") as f:
                return json.load(f)
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to read state: {e}")
    return {"mode": "stopped"}

@app.get("/api/topology")
async def get_topology(min_score: float = 0.0):
    """Retrieve the active network topology components."""
    async with aiosqlite.connect(SQLITE_DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        
        # Filter nodes based on a minimum anomaly score, defaults to 0.0 showing all
        async with db.execute("SELECT * FROM devices WHERE is_active = 1 AND anomaly_score >= ?", (min_score,)) as cursor:
            devices = await cursor.fetchall()
            nodes = [dict(row) for row in devices]
            
        device_ids = {node['device_id'] for node in nodes}
        
        # Optional: restrict to recent connections. We only grab edges for nodes that we brought down.
        async with db.execute("SELECT * FROM connections") as cursor:
            connections = await cursor.fetchall()
            links = []
            for row in connections:
                if row['src_device'] in device_ids and row['dst_device'] in device_ids:
                    links.append(dict(row))
                    
        return {"nodes": nodes, "links": links}

@app.get("/api/alerts")
async def get_alerts(limit: int = 100):
    """Retrieve recent network threats or anomalies."""
    async with aiosqlite.connect(SQLITE_DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?", (limit,)) as cursor:
            alerts = await cursor.fetchall()
            return [dict(row) for row in alerts]

@app.get("/api/devices/{device_id}")
async def get_device(device_id: str):
    """Retrieve details for a specific device."""
    async with aiosqlite.connect(SQLITE_DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM devices WHERE device_id = ?", (device_id,)) as cursor:
            device = await cursor.fetchone()
            if not device:
                raise HTTPException(status_code=404, detail="Device not found")
            return dict(device)
