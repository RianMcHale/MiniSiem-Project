import random
from datetime import datetime, timedelta

users = ["alice", "bob", "carol", "dave", "erin", "intruder"]
ips = ["192.168.1.10", "192.168.1.11", "203.0.113.5", "198.51.100.20", "203.32.159.311", "203.0.113.42"]
events = ["login_success", "login_failure"]

# Number of log lines
N = 50

now = datetime.utcnow()
with open("sample_logs.txt", "w") as f:
    for i in range(N):
        # Increment timestamp randomly within a few minutes
        ts = (now + timedelta(seconds=random.randint(0, 600))).isoformat() + "Z"
        user = random.choice(users)
        ip = random.choice(ips)
        event = random.choices(events, weights=[0.8, 0.2])[0]  # 80% success, 20% fail
        f.write(f"{ts}|{user}|{ip}|{event}\n")

print(f"Generated {N} random log lines.")
