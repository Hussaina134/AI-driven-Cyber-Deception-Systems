# scripts/demo_inject_sessions.py
import pandas as pd
import time
from pymongo import MongoClient
import os
import random
from datetime import datetime

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
client = MongoClient(MONGO_URI)
db = client["honeypot"]
agg = db.sessions_agg

CSV = "notebooks/features_agg.csv"

def synthetic(n=20):
    rows = []
    for i in range(n):
        s = {
            "session_id": f"demo-{int(time.time())}-{i}",
            "src_ip": f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}",
            "start": datetime.utcnow().isoformat(),
            "duration": random.randint(1,600),
            "cmd_count": random.randint(0,20),
            "unique_cmds": random.randint(0,10),
            "downloads": random.randint(0,4),
            "reward": round(random.random(),4),
            "applied_action": random.choice(["banner:generic","banner:hard","default","honeypot:fakefs"])
        }
        rows.append(s)
    return rows

def inject_from_csv(path, delay=0.2):
    if not os.path.exists(path):
        print("CSV not found, injecting synthetic instead")
        for doc in synthetic(50):
            doc["ts"] = time.time()
            agg.insert_one(doc)
            print("Inserted synthetic", doc["session_id"])
            time.sleep(delay)
        return
    df = pd.read_csv(path)
    # choose a sample subset so demo is quick
    sample = df.sample(min(100, len(df)))
    for _, r in sample.iterrows():
        doc = {
            "session_id": r.get("session_id") or str(r.get("session_id","demo")),
            "src_ip": r.get("src_ip") or f"10.0.0.{random.randint(1,254)}",
            "start": str(r.get("start") or datetime.utcnow().isoformat()),
            "reward": float(r.get("reward") or 0.0),
            "applied_action": r.get("applied_action") or "default",
            "ts": time.time()
        }
        agg.insert_one(doc)
        print("Inserted", doc["session_id"])
        time.sleep(delay)

if __name__ == "__main__":
    import sys
    delay = float(sys.argv[1]) if len(sys.argv) > 1 else 0.1
    inject_from_csv(CSV, delay=delay)
