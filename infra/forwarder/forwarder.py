#!/usr/bin/env python3
import os
import time
import json
import traceback
from collections import defaultdict
from pymongo import MongoClient
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from dateutil import parser as dateparser
import requests
from bson import json_util

# ----- Config -----
CONTROLLER_URL = os.getenv("CONTROLLER_URL", "http://host.docker.internal:9000")
# MONGO selection helper will try env, then localhost, then docker hostname 'mongo'
_MONGO_ENV = os.getenv("MONGO_URI", None)

def _pick_mongo_uri():
    candidates = []
    if _MONGO_ENV:
        candidates.append(_MONGO_ENV)
    candidates += ["mongodb://localhost:27017", "mongodb://mongo:27017"]
    for uri in candidates:
        try:
            c = MongoClient(uri, serverSelectionTimeoutMS=2000)
            c.server_info()
            print("Using Mongo URI:", uri)
            return uri
        except Exception:
            continue
    return candidates[0] if candidates else "mongodb://localhost:27017"

MONGO_URI = _pick_mongo_uri()
LOG_DIR = os.getenv("LOG_DIR", "/cowrie/log")   # where Cowrie writes json logs
# ------------------

# Mongo client + collections
client = MongoClient(MONGO_URI)
db = client['honeypot']
raw_collection = db['sessions']
agg_collection = db['sessions_agg']

# in-memory session aggregator
sessions = defaultdict(lambda: {
    "first_ts": None,
    "last_ts": None,
    "cmds": [],
    "downloads": 0,
    "unique_cmds": set(),
    "src_ip": None,
    "action": None,
    "action_id": None
})

# ----- Controller helpers -----
def send_to_controller(session_id, context):
    try:
        resp = requests.post(
            f"{CONTROLLER_URL}/decide",
            json={"session_id": session_id, "context": context},
            timeout=5
        )
        return resp.json()
    except Exception as e:
        print("Controller error (decide):", e)
        return {"action": "default", "action_id": session_id}

def send_reward_to_controller(action_id, session_id, reward):
    try:
        requests.post(
            f"{CONTROLLER_URL}/report",
            json={"action_id": action_id, "session_id": session_id, "reward": float(reward)},
            timeout=5
        )
        print(f"[controller] reported reward={reward} for session={session_id}")
    except Exception as e:
        print("Controller error (report):", e)

# ----- Features & Reward -----
def compute_features(session):
    first = session["first_ts"]
    last = session["last_ts"]
    duration = 0.0
    if first and last:
        duration = (last - first).total_seconds()
    cmd_count = len(session["cmds"])
    unique_cmds = len(session["unique_cmds"])
    downloads = session["downloads"]
    return {
        "duration": duration,
        "cmd_count": cmd_count,
        "unique_cmds": unique_cmds,
        "downloads": downloads,
        "reward": 0.0,
        "dummy1": 0.0,
        "dummy2": 0.0,
        "dummy3": 0.0
    }

def compute_reward(session):
    first = session["first_ts"]
    last = session["last_ts"]
    duration = 0.0
    if first and last:
        duration = max(0.0, (last - first).total_seconds())
    unique_cmds = len(session["unique_cmds"])
    dur_norm = min(duration / 300.0, 1.0)
    cmd_norm = min(unique_cmds / 5.0, 1.0)
    reward = 0.6 * dur_norm + 0.4 * cmd_norm
    return max(0.0, min(reward, 1.0))

# ----- Event processing -----
def safe_parse_timestamp(ts):
    try:
        return dateparser.parse(ts)
    except Exception:
        return None

def process_event_obj(obj):
    # store raw event safely (avoid storing unserializable types as-is)
    try:
        if "timestamp" in obj:
            try:
                obj["_ts_parsed"] = dateparser.parse(obj["timestamp"]).isoformat()
            except Exception:
                obj["_ts_parsed"] = obj["timestamp"]
        raw_collection.insert_one(obj)
    except Exception as e:
        print("Mongo insert raw failed:", e)

    # determine session id
    session_id = None
    if "session" in obj:
        session_id = obj.get("session")
    elif "sessionid" in obj:
        session_id = obj.get("sessionid")
    else:
        src = obj.get("src_ip") or obj.get("src_ip_str") or obj.get("src_ip_addr") or "unknown"
        ts = obj.get("timestamp", str(time.time()))
        session_id = f"{src}-{ts}"

    sess = sessions[session_id]

    # timestamps
    parsed = None
    if "timestamp" in obj:
        try:
            parsed = dateparser.parse(obj["timestamp"])
        except Exception:
            parsed = None
    if parsed:
        if sess["first_ts"] is None or parsed < sess["first_ts"]:
            sess["first_ts"] = parsed
        if sess["last_ts"] is None or parsed > sess["last_ts"]:
            sess["last_ts"] = parsed

    # src ip
    if not sess["src_ip"]:
        sess["src_ip"] = obj.get("src_ip") or obj.get("src_ip_str") or obj.get("src_ip_addr")

    # commands
    if "command" in obj or "input" in obj:
        cmd = obj.get("command") or obj.get("input") or obj.get("message")
        if cmd:
            sess["cmds"].append(cmd)
            sess["unique_cmds"].add(cmd.split()[0] if isinstance(cmd, str) else cmd)

    # downloads detection (safe dump)
    try:
        s = json_util.dumps(obj).lower()
    except Exception:
        obj_clean = dict(obj)
        obj_clean.pop("_id", None)
        s = json.dumps(obj_clean, default=str).lower()
    if "wget" in s or "curl" in s or "download" in str(obj.get("eventid","")).lower():
        sess["downloads"] += 1

    # session closed?
    eventid = obj.get("eventid") or obj.get("event") or ""
    if "session.closed" in str(eventid) or "cowrie.session.closed" in str(eventid):
        finish_session(session_id, sess)
    else:
        # call controller once at first meaningful event if no action yet
        if sess["action_id"] is None:
            ctx = compute_features(sess)
            decision = send_to_controller(session_id, ctx)
            sess["action"] = decision.get("action")
            sess["action_id"] = decision.get("action_id")
            print(f"[controller decide] session={session_id} action={sess['action']} id={sess['action_id']}")

def finish_session(session_id, session_data):
    try:
        features = compute_features(session_data)
        reward = compute_reward(session_data)
        features["reward"] = reward

        agg_doc = {
            "session_id": session_id,
            "src_ip": session_data.get("src_ip"),
            "start": session_data.get("first_ts").isoformat() if session_data.get("first_ts") else None,
            "end": session_data.get("last_ts").isoformat() if session_data.get("last_ts") else None,
            "duration": features["duration"],
            "cmd_count": features["cmd_count"],
            "unique_cmds": features["unique_cmds"],
            "downloads": features["downloads"],
            "reward": reward,
            "applied_action": session_data.get("action"),
            "applied_action_id": session_data.get("action_id"),
            "ts": time.time()
        }

        try:
            agg_collection.insert_one(agg_doc)
        except Exception as e:
            print("Failed to insert aggregated doc:", e)

        action_id = session_data.get("action_id") or session_id
        send_reward_to_controller(action_id, session_id, reward)
        print(f"[session finished] {session_id} reward={reward} saved.")
    except Exception:
        print("Error in finish_session:", traceback.format_exc())
    finally:
        if session_id in sessions:
            del sessions[session_id]

# ----- File reading / watchdog -----
def process_file(path):
    try:
        with open(path, 'r', errors='ignore') as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                obj = None
                try:
                    obj = json.loads(line)
                except Exception:
                    try:
                        start = line.index('{')
                        obj = json.loads(line[start:])
                    except Exception:
                        continue
                if obj:
                    process_event_obj(obj)
    except Exception:
        print("Error processing file:", path, traceback.format_exc())

class NewFileHandler(FileSystemEventHandler):
    def on_created(self, event):
        if event.is_directory:
            return
        path = event.src_path
        if path.endswith(".log") or path.endswith(".json"):
            try:
                process_file(path)
            except Exception as e:
                print("error processing created file", path, e)

def initial_scan():
    try:
        for fname in os.listdir(LOG_DIR):
            full = os.path.join(LOG_DIR, fname)
            if os.path.isfile(full):
                process_file(full)
    except Exception as e:
        print("initial_scan error", e)

# ----- Main -----
if __name__ == "__main__":
    print("Starting forwarder. LOG_DIR =", LOG_DIR, "MONGO_URI =", MONGO_URI, "CONTROLLER_URL =", CONTROLLER_URL)
    time.sleep(3)
    initial_scan()
    event_handler = NewFileHandler()
    observer = Observer()
    observer.schedule(event_handler, LOG_DIR, recursive=False)
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
