"""Security monitoring rule for ShieldDesk.
Rule: >= THRESHOLD failed logins for the same user OR the same IP within WINDOW seconds -> ALERT.
Usage: python3 tools/monitor.py logs/security.log
"""
import re
import sys
from collections import defaultdict, deque
from datetime import datetime, timedelta

THRESHOLD = 5
WINDOW = timedelta(seconds=120)
LINE = re.compile(r"^(\S+) (LOGIN_FAILED|LOGIN_BLOCKED_LOCKED) user=(\S+) ip=(\S+)")

path = sys.argv[1] if len(sys.argv) > 1 else "logs/security.log"
recent = defaultdict(deque)          # key -> timestamps inside the window
alerted = set()
alerts = 0

with open(path) as fh:
    for line in fh:
        m = LINE.match(line)
        if not m:
            continue
        ts = datetime.fromisoformat(m.group(1))
        for key in (f"user={m.group(3)}", f"ip={m.group(4)}"):
            q = recent[key]
            q.append(ts)
            while q and ts - q[0] > WINDOW:
                q.popleft()
            if len(q) >= THRESHOLD and key not in alerted:
                alerted.add(key)
                alerts += 1
                print(f"[ALERT] {ts.isoformat()} Possible brute force: {key}, "
                      f"{len(q)} failed logins in {int((ts - q[0]).total_seconds())}s")

print(f"Monitoring complete: {alerts} alert(s) raised")
sys.exit(2 if alerts else 0)
