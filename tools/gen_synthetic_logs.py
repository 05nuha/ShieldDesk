"""Write SYNTHETIC security log entries: normal traffic + one brute-force burst.
Usage: python3 tools/gen_synthetic_logs.py logs/synthetic_security.log
"""
import random
import sys
from datetime import datetime, timedelta

out = sys.argv[1] if len(sys.argv) > 1 else "logs/synthetic_security.log"
random.seed(5)
t = datetime(2026, 11, 15, 9, 0, 0)
lines = []
for i in range(30):                                   # normal behaviour
    t += timedelta(seconds=random.randint(20, 90))
    user = f"stu{random.randint(0, 39):03d}"
    ip = f"10.0.0.{random.randint(10, 60)}"
    if random.random() < 0.15:                         # the occasional typo
        lines.append(f"{t:%Y-%m-%dT%H:%M:%S} LOGIN_FAILED user={user} ip={ip}")
        t += timedelta(seconds=8)
    lines.append(f"{t:%Y-%m-%dT%H:%M:%S} LOGIN_SUCCESS user={user} ip={ip}")
for i in range(8):                                    # attack: 8 guesses in ~40 s
    t += timedelta(seconds=5)
    lines.append(f"{t:%Y-%m-%dT%H:%M:%S} LOGIN_FAILED user=alice ip=10.0.0.99")
with open(out, "w") as fh:
    fh.write("\n".join(lines) + "\n")
print(f"Wrote {len(lines)} synthetic log lines to {out}")
