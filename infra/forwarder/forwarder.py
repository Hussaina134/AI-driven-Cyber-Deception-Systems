
import os
import time
import json
from pymongo import MongoClient
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from dateutil import parser as dateparser

MONGO_URI = os.getenv("MONGO_URI", "mongodb://mongo:27017")
LOG_DIR = "/cowrie/log"

client = MongoClient(MONGO_URI)
db = client['honeypot']
collection = db['sessions']

class NewFileHandler(FileSystemEventHandler):
    def on_created(self, event):
        path = event.src_path
        if path.endswith(".log") or path.endswith(".json"):
            process_file(path)

def process_file(path):
    try:
        with open(path, 'r', errors='ignore') as f:
            for line in f:
                line=line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except:
                    try:
                        start = line.index('{')
                        obj = json.loads(line[start:])
                    except Exception:
                        continue
                if 'timestamp' in obj:
                    try:
                        obj['timestamp'] = dateparser.parse(obj['timestamp'])
                    except:
                        pass
                collection.insert_one(obj)
    except Exception as e:
        print("Error processing", path, e)

def initial_scan():
    for fname in os.listdir(LOG_DIR):
        full = os.path.join(LOG_DIR, fname)
        if os.path.isfile(full):
            process_file(full)

if __name__ == "__main__":
    time.sleep(5)
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

