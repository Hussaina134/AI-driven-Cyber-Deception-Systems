# week2_sample_events.py
# Simple script to fetch sample Cowrie events from MongoDB and show them via pandas

from pymongo import MongoClient
import pandas as pd
import sys

# 1. Connection string to local MongoDB (Docker maps 27017:27017)
MONGO_URI = "mongodb://localhost:27017"

def main():
    try:
        client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
        # test connection
        client.admin.command("ping")
    except Exception as e:
        print("ERROR: Cannot connect to MongoDB at", MONGO_URI)
        print("Exception:", e)
        sys.exit(1)

    # 2. Print databases and choose the cowrie DB if present
    db_names = client.list_database_names()
    print("Databases found:", db_names)

    # Try common cowrie DB names (cowrie or honeypot), fallback to first DB (excluding system DBs)
    chosen_db = None
    for candidate in ("cowrie", "honeypot", "honeypot_db"):
        if candidate in db_names:
            chosen_db = candidate
            break
    if not chosen_db:
        # pick first non-system DB (not admin/local)
        for name in db_names:
            if name not in ("admin", "local", "config"):
                chosen_db = name
                break

    if not chosen_db:
        print("No suitable user DB found in MongoDB.")
        sys.exit(0)

    print("Using database:", chosen_db)
    db = client[chosen_db]

    # 3. List collections
    coll_names = db.list_collection_names()
    print("Collections in DB:", coll_names)
    if not coll_names:
        print("No collections found. Interact with the honeypot to generate logs.")
        sys.exit(0)

    # 4. Pick a collection (prefer 'sessions' or 'session' or 'cowrie_log') else the first
    preferred = None
    for name in ("sessions", "session", "cowrie_log", "log", "events"):
        if name in coll_names:
            preferred = name
            break
    collection_name = preferred if preferred else coll_names[0]
    print("Querying collection:", collection_name)
    coll = db[collection_name]

    # 5. Fetch sample documents and show them using pandas
    docs = list(coll.find().sort([("_id", -1)]).limit(10))
    if not docs:
        print("No documents in the selected collection yet.")
        sys.exit(0)

    df = pd.json_normalize(docs)
    pd.set_option('display.max_columns', None)
    print("\n=== Sample documents (most recent 10) ===\n")
    print(df.head(10).to_string(index=False))

if __name__ == "__main__":
    main()
