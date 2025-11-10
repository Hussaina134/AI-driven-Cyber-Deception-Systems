# notebooks/feature_extractor.py
import json
import pandas as pd
from dateutil import parser
from sklearn.feature_extraction.text import HashingVectorizer
import numpy as np
import os

IN = "sessions.json"
OUT = "features.csv"

def parse_iso(dt):
    try:
        return parser.parse(dt) if dt else None
    except:
        return None

def summarize_events(events):
    # events are raw JSON docs from Cowrie; we try to extract command inputs
    cmds = []
    downloads = 0
    for e in events:
        # common fields where command may appear
        input_field = e.get("input") or e.get("message") or e.get("command") or e.get("cmd")
        if input_field:
            # if it's a dict or list convert to str
            cmds.append(str(input_field))
        # check for download attempts (basic heuristic)
        msg = json.dumps(e).lower()
        if "download" in msg or "wget" in msg or "curl" in msg or ".sh" in msg or "upload" in msg:
            downloads += 1
    return cmds, downloads

def main():
    with open(IN, "r") as f:
        sessions = json.load(f)
    rows = []
    for s in sessions:
        start = parse_iso(s.get("start"))
        end = parse_iso(s.get("end"))
        duration = (end - start).total_seconds() if start and end else None
        cmds, downloads = summarize_events(s.get("events", []))
        unique_cmds = len(set(cmds))
        cmd_count = len(cmds)
        seq_text = " ; ".join(cmds)[:10000]  # limit length
        start_hour = start.hour if start else None
        rows.append({
            "session_id": s.get("session_id"),
            "src_ip": s.get("src_ip"),
            "start": s.get("start"),
            "end": s.get("end"),
            "duration": duration,
            "cmd_count": cmd_count,
            "unique_cmds": unique_cmds,
            "downloads": downloads,
            "start_hour": start_hour,
            "sequence_text": seq_text
        })
    df = pd.DataFrame(rows)
    # simple normalization placeholders
    df["duration_norm"] = df["duration"].fillna(0) / (300.0)
    df["cmd_count_norm"] = df["cmd_count"].fillna(0) / 20.0

    # tokenization -> simple hashing vectorizer to get numeric features (sparse)
    vec = HashingVectorizer(n_features=64, alternate_sign=False, norm=None)
    X_seq = vec.transform(df["sequence_text"].fillna(""))
    X_seq = X_seq.toarray()  # small n_features so okay

    seq_cols = [f"seq_{i}" for i in range(X_seq.shape[1])]
    df_seq = pd.DataFrame(X_seq, columns=seq_cols)
    out = pd.concat([df.reset_index(drop=True), df_seq.reset_index(drop=True)], axis=1)
    out.to_csv(OUT, index=False)
    print("Wrote", OUT, "with", len(out), "rows and", out.shape[1], "columns")

if __name__ == "__main__":
    import json
    main()
