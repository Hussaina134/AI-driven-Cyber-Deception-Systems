import pandas as pd
import requests
import os
import time

API_DECIDE = os.environ.get("API_DECIDE", "http://localhost:9000/decide")
API_REPORT = os.environ.get("API_REPORT", "http://localhost:9000/report")

# path to your features CSV (ensure it exists)
DATA = os.path.join(os.getcwd(), "..", "notebooks", "features_agg.csv")
if not os.path.exists(DATA):
    raise SystemExit("features_agg.csv not found at " + DATA)

df = pd.read_csv(DATA)

# choose the context keys to send - must match feature_schema.json order
keys = ["duration","cmd_count","unique_cmds","downloads","reward","dummy1","dummy2","dummy3"]

for idx, row in df.iterrows():
    session_id = str(row.get("session_id", f"s{idx}"))
    context = {k: float(row.get(k, 0.0)) if k in row else 0.0 for k in keys}
    # call decide
    r = requests.post(API_DECIDE, json={"session_id": session_id, "context": context})
    if r.status_code != 200:
        print("decide failed:", r.status_code, r.text)
        continue
    resp = r.json()
    action_id = resp["action_id"]
    # compute reward from data (if present)
    reward = float(row.get("reward", 0.0))
    # report the reward
    rr = requests.post(API_REPORT, json={"action_id": action_id, "session_id": session_id, "reward": reward, "metadata": {"idx": idx}})
    if rr.status_code != 200:
        print("report failed:", rr.status_code, rr.text)
    # throttle a little
    time.sleep(0.01)

print("Replay complete")

