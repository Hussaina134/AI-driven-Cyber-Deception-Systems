# scripts/simulate_attacker.py
# This script uses pexpect to connect to Cowrie's SSH port and send simple commands.
import pexpect
import time
import random
import sys

HOST = "localhost"
PORT = 2222
USERNAMES = ["root","admin","user","test"]
PASSWORDS = ["password","123456","admin","toor","letmein"]
COMMANDS = ["ls -la", "whoami", "uname -a", "pwd", "cat /etc/hosts", "id"]

def single_session():
    try:
        cmd = f"ssh -o StrictHostKeyChecking=no -p {PORT} {random.choice(USERNAMES)}@{HOST}"
        child = pexpect.spawn(cmd, timeout=15)
        # expect a password prompt or connection closed
        i = child.expect([r"[Pp]assword:", pexpect.EOF, pexpect.TIMEOUT], timeout=10)
        if i == 0:
            child.sendline(random.choice(PASSWORDS))
            time.sleep(1)
            # send a few commands
            for _ in range(random.randint(1,5)):
                c = random.choice(COMMANDS)
                child.sendline(c)
                time.sleep(random.uniform(0.2, 1.2))
            child.sendline("exit")
            child.close()
        else:
            child.close()
    except Exception as e:
        # ignore errors; honeypot may drop connection
        # print(e)
        pass

if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 100
    for i in range(n):
        single_session()
        time.sleep(random.uniform(0.1,1.0))
    print("Done simulating", n, "sessions")

