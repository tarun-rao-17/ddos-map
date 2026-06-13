import os
import asyncio
import joblib
import numpy as np
import aiohttp
from datetime import datetime
from typing import List
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv

from database import (
    init_db,
    insert_event,
    get_cached_abuse_score,
    cache_abuse_score,
    get_recent_events
)

# ─── 1. CONFIG ────────────────────────────────────────────────
load_dotenv()
ABUSEIPDB_KEY  = os.getenv("ABUSEIPDB_API_KEY", "")
WORKER_SECRET  = os.getenv("WORKER_SECRET", "changeme")
MODEL_PATH     = os.path.join(os.path.dirname(__file__), "ml", "model.pkl")

ML_FEATURES = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Length of Fwd Packets",
    "Fwd Packet Length Max",
    "Fwd Packet Length Min",
    "Bwd Packet Length Max",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Fwd IAT Mean",
    "Bwd IAT Mean",
    "Fwd PSH Flags",
    "SYN Flag Count",
    "RST Flag Count",
    "ACK Flag Count",
    "Avg Fwd Segment Size",
    "Init_Win_bytes_forward",
]

# ─── 2. STARTUP ───────────────────────────────────────────────
app = FastAPI(title="DDoS Map API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

ml_model = None

@app.on_event("startup")
async def startup():
    global ml_model
    init_db()
    if os.path.exists(MODEL_PATH):
        ml_model = joblib.load(MODEL_PATH)
        print(f"ML model loaded from {MODEL_PATH}")
    else:
        print("WARNING: model.pkl not found — all confidence scores will be 0.0")

# ─── 3. WEBSOCKET MANAGER ─────────────────────────────────────
class ConnectionManager:
    def __init__(self):
        self.active: List[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active.append(ws)
        print(f"Client connected. Total: {len(self.active)}")

    def disconnect(self, ws: WebSocket):
        self.active.remove(ws)
        print(f"Client disconnected. Total: {len(self.active)}")

    async def broadcast(self, data: dict):
        dead = []
        for ws in self.active:
            try:
                await ws.send_json(data)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.active.remove(ws)

manager = ConnectionManager()

# ─── 4. REQUEST MODEL ─────────────────────────────────────────
class IngestEvent(BaseModel):
    timestamp:            str
    ip:                   str
    country:              str   = "XX"
    city:                 str   = ""
    latitude:             float = 0.0
    longitude:            float = 0.0
    asn:                  int   = 0
    asn_org:              str   = ""
    url:                  str   = ""
    method:               str   = "GET"
    user_agent:           str   = ""
    tls_version:          str   = ""
    http_protocol:        str   = ""
    requests_this_isolate: int  = 1

# ─── 5. ML SCORING ────────────────────────────────────────────
def build_feature_vector(event: IngestEvent) -> np.ndarray:
    ua        = event.user_agent
    pps       = min(event.requests_this_isolate * 100, 1_000_000)
    syn_flags = event.requests_this_isolate if event.requests_this_isolate > 10 else 0

    features = {
        "Flow Duration":                  max(1000 - event.requests_this_isolate * 10, 1),
        "Total Fwd Packets":              event.requests_this_isolate,
        "Total Length of Fwd Packets":    len(event.url) * event.requests_this_isolate,
        "Fwd Packet Length Max":          len(event.url),
        "Fwd Packet Length Min":          min(len(event.url), 20),
        "Bwd Packet Length Max":          0 if event.requests_this_isolate > 20 else 500,
        "Flow Bytes/s":                   pps * 100,
        "Flow Packets/s":                 pps,
        "Flow IAT Mean":                  max(10000 - pps, 1),
        "Flow IAT Std":                   max(5000  - pps, 1),
        "Fwd IAT Mean":                   max(10000 - pps, 1),
        "Bwd IAT Mean":                   0 if event.requests_this_isolate > 10 else 50000,
        "Fwd PSH Flags":                  1 if event.method == "POST" else 0,
        "SYN Flag Count":                 syn_flags,
        "RST Flag Count":                 syn_flags // 2,
        "ACK Flag Count":                 1,
        "Avg Fwd Segment Size":           len(event.url),
        "Init_Win_bytes_forward":         65535 if len(ua) > 30 else 0,
    }
    return np.array([features[f] for f in ML_FEATURES]).reshape(1, -1)

def get_ml_score(event: IngestEvent) -> float:
    if ml_model is None:
        return 0.0
    try:
        vec  = build_feature_vector(event)
        prob = ml_model.predict_proba(vec)[0]
        return round(float(prob[1]), 4)
    except Exception as e:
        print(f"ML scoring error: {e}")
        return 0.0

# ─── 6. ABUSEIPDB ─────────────────────────────────────────────
async def fetch_abuse_score(ip: str) -> int:
    
    cached = get_cached_abuse_score(ip)
    if cached is not None:
        return cached

    if not ABUSEIPDB_KEY:
        return 0

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 30},
                timeout=aiohttp.ClientTimeout(total=3),
            ) as resp:
                if resp.status == 200:
                    data  = await resp.json()
                    score = data["data"]["abuseConfidenceScore"]
                    cache_abuse_score(ip, score)
                    return score
    except Exception as e:
        print(f"AbuseIPDB error for {ip}: {e}")

    return 0

# ─── 7. ENDPOINTS ─────────────────────────────────────────────
@app.post("/ingest")
async def ingest(event: IngestEvent):
    # score with ML
    ddos_confidence = get_ml_score(event)

    # score with AbuseIPDB
    abuse_score = await fetch_abuse_score(event.ip)

    # combine into final verdict
    flagged = int(ddos_confidence > 0.7 or abuse_score > 50)

    record = {
        "timestamp":        event.timestamp,
        "ip":               event.ip,
        "country":          event.country,
        "city":             event.city,
        "latitude":         event.latitude,
        "longitude":        event.longitude,
        "asn":              event.asn,
        "asn_org":          event.asn_org,
        "url":              event.url,
        "method":           event.method,
        "user_agent":       event.user_agent,
        "abuse_score":      abuse_score,
        "ddos_confidence":  ddos_confidence,
        "flagged":          flagged,
    }

    insert_event(record)
    await manager.broadcast(record)
    return {"status": "ok", "flagged": bool(flagged)}


@app.get("/history")
async def history():
    events = get_recent_events(limit=200)
    return {"events": events}


@app.websocket("/live-feed")
async def websocket_endpoint(ws: WebSocket):
    await manager.connect(ws)
    try:
        while True:
            await asyncio.sleep(30)
    except WebSocketDisconnect:
        manager.disconnect(ws)


@app.get("/health")
async def health():
    return {
        "status":    "ok",
        "model":     ml_model is not None,
        "timestamp": datetime.utcnow().isoformat(),
    }