"""Compute ASVS verification coverage from a CSV checklist.
CSV columns: req_id,chapter,description,status,evidence   (status = Pass | Fail | N/A)
Usage: python3 tools/asvs_coverage.py docs/asvs_v0.csv
"""
import csv
import sys
from collections import defaultdict

per = defaultdict(lambda: [0, 0])            # chapter -> [passed, applicable]
with open(sys.argv[1]) as f:
    for row in csv.DictReader(f):
        st = row["status"].strip().lower()
        if st == "n/a":
            continue
        per[row["chapter"]][1] += 1
        if st == "pass":
            per[row["chapter"]][0] += 1

tp = ta = 0
print(f"{'Chapter':<10}{'Passed':>8}{'Applicable':>12}{'Coverage':>10}")
for ch in sorted(per):
    p, a = per[ch]
    tp, ta = tp + p, ta + a
    print(f"{ch:<10}{p:>8}{a:>12}{100 * p / a:>9.1f}%")
print(f"{'TOTAL':<10}{tp:>8}{ta:>12}{100 * tp / ta:>9.1f}%")
