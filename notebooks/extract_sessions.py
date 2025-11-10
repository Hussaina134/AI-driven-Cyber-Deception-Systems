# notebooks/extract_sessions.py
# Run: python3 extract_sessions.py
from pymongo import MongoClient
import pandas as pd
from dateutil import parser
from datetime import timedelta
import json
import os

MONGO_URI = "mongodb://localhost:27017"
OUT = "sessions.json"   # output - list of session dicts

def to_dt(x):
    try:
        return parser.parse(x)
    except:
        return None

def main():
    client = MongoClient(MONGO_URI)
    # Try common db names (we used 'honeypot')
    db_name = None
    for candidate in ("honeypot","cowrie","default"):
        if candidate in client.list_database_names():
            db_name = candidate
            break
    if not db_name:
        db_name = client.list_database_names()[0]  # fallback
    db = client[db_name]

    # choose collection
    coll_name = None
    for name in db.list_collection_names():
        if name in ("sessions","session","cowrie.log","log","events"):
            coll_name = name
            break
    if not coll_name:
        coll_name = db.list_collection_names()[0]
    coll = db[coll_name]

    # read events into dataframe (may be many - adjust limit if needed)
    docs = list(coll.find().sort([("timestamp", 1)]))
    if not docs:
        print("No events found in", db_name, coll_name)
        return

    # normalize timestamps and important fields
    rows = []
    for d in docs:
        ts = d.get("timestamp") or d.get("time") or d.get("ts")
        if ts:
            ts = to_dt(ts) if not isinstance(ts, (int,float)) else pd.to_datetime(ts, unit="s")
        rows.append({
            "raw": d,
            "timestamp": ts,
            "src_ip": d.get("src_ip") or d.get("srcip") or d.get("peer"),
            "event": d.get("event") or d.get("eventid") or d.get("message"),
            "input": d.get("input") or d.get("message") or d.get("cmd"),
            "session": d.get("session") or d.get("sessionid") or None
        })
    df = pd.DataFrame(rows).sort_values("timestamp").reset_index(drop=True)

    # Sessionization strategy:
    # If session id present, group by session id.
    # Else group by (src_ip) with inactivity gap (e.g., 5 minutes) -> new session.
    sessions = []
    if "session" in df.columns and df["session"].notnull().any():
        for sid, g in df.groupby("session"):
            if sid is None:
                continue
            g = g.sort_values("timestamp")
            sess = {
                "session_id": str(sid),
                "src_ip": g["src_ip"].iloc[0],
                "start": g["timestamp"].min().isoformat() if g["timestamp"].notnull().any() else None,
                "end": g["timestamp"].max().isoformat() if g["timestamp"].notnull().any() else None,
                "events": [r for r in g["raw"].tolist()]
            }
            sessions.append(sess)
    else:
        # group by src_ip + inactivity window
        gap = timedelta(minutes=5)
        for src, group in df.groupby("src_ip"):
            group = group.sort_values("timestamp")
            cur_events = []
            cur_start = None
            cur_end = None
            for _, row in group.iterrows():
                ts = row["timestamp"]
                if cur_start is None:
                    cur_start = ts
                    cur_end = ts
                    cur_events = [row["raw"]]
                else:
                    if ts is None or (ts - cur_end) <= gap:
                        cur_events.append(row["raw"])
                        if ts is not None:
                            cur_end = ts
                    else:
                        sessions.append({
                            "session_id": f"{src}-{cur_start.isoformat() if cur_start else 'na'}",
                            "src_ip": src,
                            "start": cur_start.isoformat() if cur_start else None,
                            "end": cur_end.isoformat() if cur_end else None,
                            "events": cur_events
                        })
                        cur_start = ts
                        cur_end = ts
                        cur_events = [row["raw"]]
            if cur_events:
                sessions.append({
                    "session_id": f"{src}-{cur_start.isoformat() if cur_start else 'na'}",
                    "src_ip": src,
                    "start": cur_start.isoformat() if cur_start else None,
                    "end": cur_end.isoformat() if cur_end else None,
                    "events": cur_events
                })
    # write sessions.json
    with open(OUT, "w") as f:
        json.dump(sessions, f, indent=2, default=str)
    print("Wrote", len(sessions), "sessions to", OUT)

if __name__ == "__main__":
    main()
