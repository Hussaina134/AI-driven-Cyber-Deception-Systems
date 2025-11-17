from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Dict, Any
from pymongo import MongoClient
from datetime import datetime
import numpy as np
import uuid
import os
import json

from controller.bandit import LinUCB

# Config
MONGO_URI = os.environ.get("MONGO_URI", "mongodb://localhost:27017")
MODEL_PATH = os.environ.get("MODEL_PATH", "controller/linucb.pkl")
SCHEMA_PATH = os.environ.get("SCHEMA_PATH", "controller/feature_schema.json")

# Actions your controller can choose (start small)
ACTIONS = [
    "banner:generic",
    "banner:os_hint",
    "service:ftp_on",
    "service:ftp_off",
    "fingerprint:linux",
    "fingerprint:windows"
]

# Connect Mongo
client = MongoClient(MONGO_URI)
db = client["controller_db"]
decisions_col = db["decisions"]
reports_col = db["reports"]

# Load feature schema
with open(SCHEMA_PATH, "r") as f:
    schema = json.load(f)
FEATURE_ORDER = schema.get("features_order", [])

DIM = max(len(FEATURE_ORDER), 1)

# Load or init bandit
if os.path.exists(MODEL_PATH):
    policy = LinUCB.load(MODEL_PATH)
else:
    policy = LinUCB(ACTIONS, DIM, alpha=0.8)
    policy.save(MODEL_PATH)

app = FastAPI(title="Honeypot Controller")

class DecideReq(BaseModel):
    session_id: str
    context: Dict[str, float]

class DecideResp(BaseModel):
    action: str
    action_id: str

class ReportReq(BaseModel):
    action_id: str
    session_id: str
    reward: float
    metadata: Dict[str, Any] = {}

def _to_vec(context: Dict[str, float]):
    # Build vector following feature order from schema
    vec = np.array([float(context.get(k, 0.0)) for k in FEATURE_ORDER], dtype=float)
    # simple L2 normalization for stability
    norm = np.linalg.norm(vec)
    if norm > 0:
        vec = vec / (norm + 1e-9)
    return vec

@app.post("/decide", response_model=DecideResp)
def decide(req: DecideReq):
    vec = _to_vec(req.context)
    action, scores = policy.decide(vec)
    action_id = str(uuid.uuid4())
    # save decision
    decisions_col.insert_one({
        "action_id": action_id,
        "session_id": req.session_id,
        "action": action,
        "context": req.context,
        "scores": scores,
        "ts": datetime.utcnow()
    })
    policy.save(MODEL_PATH)
    # Also write a small file to controller/actions so other processes (forwarder) can read it
    os.makedirs("controller/actions", exist_ok=True)
    with open(f"controller/actions/{action_id}.json", "w") as fh:
        json.dump({"action_id": action_id, "session_id": req.session_id, "action": action, "ts": datetime.utcnow().isoformat()}, fh)
    return {"action": action, "action_id": action_id}

@app.post("/report")
def report(r: ReportReq):
    reports_col.insert_one({
        "action_id": r.action_id,
        "session_id": r.session_id,
        "reward": float(r.reward),
        "metadata": r.metadata,
        "ts": datetime.utcnow()
    })
    # find the decision to get the context
    dec = decisions_col.find_one({"action_id": r.action_id})
    if not dec:
        raise HTTPException(status_code=404, detail="action_id not found")
    action = dec["action"]
    context = dec.get("context", {})
    vec = _to_vec(context)
    policy.update(action, vec, float(r.reward))
    policy.save(MODEL_PATH)
    return {"updated": True}

@app.get("/health")
def health():
    return {"status": "ok", "policy_saved": os.path.exists(MODEL_PATH)}

