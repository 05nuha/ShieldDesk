"""Repeatable attack tests for ShieldDesk (run ONLY against your local lab app).
Usage: python3 attack_tests.py http://127.0.0.1:5000
The same script is run before (v0) and after (v1) the fixes = attack/defend/verify.
"""
import sys
import requests

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:5000"
assert BASE.startswith(("http://127.0.0.1", "http://localhost")), "Local targets only!"
results = []


def record(name, vulnerable, detail):
    results.append((name, vulnerable))
    print(f"[{'VULNERABLE' if vulnerable else 'SECURE    '}] {name}: {detail}")


# 1. SQL injection login bypass
s = requests.Session()
r = s.post(f"{BASE}/login", data={"username": "admin' --", "password": "anything"}, allow_redirects=True)
record("SQL injection login bypass", "Service requests" in r.text,
       f"final URL {r.url}")

# 2. Reflected XSS in search
payload = "<script>alert(1)</script>"
r = requests.get(f"{BASE}/search", params={"q": payload})
record("Reflected XSS in /search", payload in r.text,
       "payload returned raw" if payload in r.text else f"payload encoded/rejected (HTTP {r.status_code})")

# 3. User enumeration via error messages
a = requests.post(f"{BASE}/login", data={"username": "nosuchuser1", "password": "x"}).text
b = requests.post(f"{BASE}/login", data={"username": "alice", "password": "wrong"}).text
record("User enumeration", ("does not exist" in a) or (a != b), "messages differ" if a != b else "identical messages")

# 4. Brute force / no lockout (correct password tried after 6 wrong ones)
for i in range(6):
    requests.post(f"{BASE}/login", data={"username": "bob", "password": f"guess{i}"})
r = requests.post(f"{BASE}/login", data={"username": "bob", "password": "Summer2026!"}, allow_redirects=True)
record("No account lockout", "Service requests" in r.text,
       "login still possible after 6 failures" if "Service requests" in r.text else "account locked")

# 5. Information leak in errors (debug traceback)
r = requests.get(f"{BASE}/search", params={"q": "'"})
leak = ("Traceback" in r.text) or ("OperationalError" in r.text) or ("Werkzeug Debugger" in r.text)
record("Error information leak", leak, f"HTTP {r.status_code}")

vuln = sum(v for _, v in results)
print(f"\nSummary: {len(results) - vuln}/{len(results)} tests passed (secure), {vuln} vulnerable")
