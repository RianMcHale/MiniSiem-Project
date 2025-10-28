import random
from datetime import datetime, timedelta

users = ["alice", "bob", "carol", "dave", "erin", "intruder"]
ips = ["192.168.1.10", "192.168.1.11", "203.0.113.5", "198.51.100.20", "203.32.159.311", "203.0.113.42"]
events = ["login_success", "login_failure", "file_access", "privilege_escalation"]

# Number of log lines
N = 100

now = datetime.utcnow()

with open("sample_logs.txt", "w") as f:
    for i in range(N):
        # Increment timestamp randomly within a few minutes
        ts = (now + timedelta(seconds=random.randint(0, 600))).isoformat() + "Z"
        user = random.choice(users)

        if user == "intruder":
            ip = random.choice(["203.0.113.42", "198.51.100,20"])
            event = random.choices(
                ["login_failure", "login_failure", "login_success"],
                 weights= [0.75, 0.2, 0.05],
            )[0]
        else:
            ip = random.choice(ips)
            event = random.choices(
                ["login_success", "login_failure", "file_access"],
                weights = [0.75, 0.2, 0.05],
            )[0]

        if random.random() < 0.03:
            event = "privilege_escalation"
            user = random.choice(["intruder", "dave", "bob"])
            ip = random.choice(["203.0.113.42", "192,168.1.11"])

        f.write(f"{ts}|{user}|{ip}|{event}\n")

print(f"Generated {N} simualted SOAR log lines.")
