"""Task 4.5 - pseudonymisation + generalisation of the SYNTHETIC dataset.
Usage: PSEUDO_KEY=<random secret> python3 tools/privacy_transform.py app/shielddesk.db
Writes data_before.csv and data_after.csv in reports/.
"""
import csv
import hashlib
import hmac
import os
import sqlite3
import sys

db_path = sys.argv[1] if len(sys.argv) > 1 else "app/shielddesk.db"
KEY = os.environ.get("PSEUDO_KEY")
if not KEY:
    sys.exit("Set PSEUDO_KEY (keep it separate from the dataset, e.g. in a vault)")

db = sqlite3.connect(db_path)
rows = db.execute("""SELECT u.full_name, u.student_id, u.email, r.category, r.details, r.created_at
                     FROM requests r JOIN users u ON u.username = r.username
                     ORDER BY r.id""").fetchall()


def pseudonym(value):
    # Keyed hash (HMAC-SHA256): same input -> same token, but not reversible without KEY.
    # A plain SHA-256 of an 8-digit ID could be brute-forced in seconds (only 10^8 values).
    return "P-" + hmac.new(KEY.encode(), value.encode(), hashlib.sha256).hexdigest()[:12]


def to_month(ts):
    return ts[:7]                       # 2026-08-14 10:22:01 -> 2026-08


os.makedirs("reports", exist_ok=True)
with open("reports/data_before.csv", "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["full_name", "student_id", "email", "category", "details", "created_at"])
    w.writerows(rows)

with open("reports/data_after.csv", "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["student_pseudonym", "category", "month"])      # name, email, details dropped
    for name, sid, email, cat, details, created in rows:
        w.writerow([pseudonym(sid), cat, to_month(created)])

# k-anonymity check on the quasi-identifiers that remain (category + month)
groups = {}
for _, _, _, cat, _, created in rows:
    groups[(cat, to_month(created))] = groups.get((cat, to_month(created)), 0) + 1
print(f"{len(rows)} rows transformed. Smallest (category, month) group k = {min(groups.values())}")
print("Before:", rows[0][:4])
with open("reports/data_after.csv") as f:
    print("After: ", f.readlines()[1].strip())
