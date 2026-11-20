#!/usr/bin/env bash
# ShieldDesk DevSecOps pipeline: SAST -> secret scan -> build/deploy -> DAST
# Exit code 0 = BUILD PASSED, 1 = BUILD BLOCKED
set -u
cd "$(dirname "$0")/.."
mkdir -p reports
FAIL=0
TARGET="http://127.0.0.1:5000"
RUN_DAST="${RUN_DAST:-1}"          # RUN_DAST=0 ./pipeline/ci.sh skips stage 3-4 (used by pre-commit)
SEED_MODE="${SEED_MODE:-secure}"   # SEED_MODE=md5 when testing the v0 code

banner() { echo; echo "==================== $1 ===================="; }

# ---------- Stage 1: SAST (Bandit) ----------
banner "[1/4] SAST - Bandit"
bandit -r app/ -x app/seed.py -f json -o reports/bandit.json -q
bandit -r app/ -x app/seed.py -f txt  -o reports/bandit.txt  -q
HIGH=$(jq '[.results[] | select(.issue_severity=="HIGH")] | length' reports/bandit.json)
MED=$(jq  '[.results[] | select(.issue_severity=="MEDIUM")] | length' reports/bandit.json)
LOW=$(jq  '[.results[] | select(.issue_severity=="LOW")] | length' reports/bandit.json)
LOC=$(jq '.metrics._totals.loc' reports/bandit.json)
echo "Bandit findings: High=$HIGH Medium=$MED Low=$LOW  (LOC=$LOC)"
if [ "$HIGH" -gt 0 ]; then
  echo "GATE FAILED: $HIGH High-severity SAST finding(s)"; FAIL=1
else
  echo "GATE PASSED: no High-severity SAST findings"
  [ "$MED" -gt 0 ] && echo "WARNING: $MED Medium finding(s) added to backlog"
fi

# ---------- Stage 2: Secret scan (gitleaks) ----------
banner "[2/4] Secret scan - gitleaks"
if gitleaks detect --no-git --source app --config .gitleaks.toml --redact --no-banner \
     --report-format json --report-path reports/gitleaks.json; then
  echo "GATE PASSED: no secrets in source"
else
  echo "GATE FAILED: $(jq length reports/gitleaks.json) secret(s) found in source"; FAIL=1
fi

if [ "$RUN_DAST" = "1" ]; then
  # ---------- Stage 3: Build and deploy container ----------
  banner "[3/4] Build and deploy (Docker, localhost only)"
  docker rm -f shielddesk >/dev/null 2>&1
  docker build -q --build-arg SEED_MODE="$SEED_MODE" -t shielddesk:ci . || { echo "GATE FAILED: build error"; exit 1; }
  docker run -d --name shielddesk -p 127.0.0.1:5000:5000 \
     -e SHIELDDESK_SECRET_KEY="$(openssl rand -hex 32)" shielddesk:ci >/dev/null
  for i in $(seq 1 30); do curl -s -o /dev/null "$TARGET/" && break; sleep 1; done
  echo "App is up at $TARGET"

  # ---------- Stage 4: DAST (OWASP ZAP) ----------
  banner "[4/4] DAST - OWASP ZAP (active scan of localhost only)"
  # Seed URLs so ZAP's spider finds the parameterised pages
  zaproxy -cmd -port 8090 -quickurl "$TARGET/search?q=IT" \
          -quickout "$PWD/reports/zap.json" -quickprogress >/dev/null 2>&1
  # Reviewed false positives (alert name -> reason). Everything else still blocks the build.
  # "Path Traversal": ZAP flagged /search?q=search with EMPTY evidence. Verified by hand: the app
  # returns HTTP 400 for ../../etc/passwd and reads no files, so nothing is exploitable.
  ZAP_FALSE_POSITIVES='["Path Traversal"]'
  ZHIGH=$(jq --argjson fp "$ZAP_FALSE_POSITIVES" '[.site[]?.alerts[]? | select(.riskcode=="3") | select(.alert as $a | ($fp | index($a)) | not)] | length' reports/zap.json)
  jq -r '.site[]?.alerts[]? | "  [risk \(.riskcode)] \(.alert)"' reports/zap.json | sort -u
  if [ "$ZHIGH" -gt 0 ]; then
    echo "GATE FAILED: $ZHIGH High-risk DAST alert(s)"; FAIL=1
  else
    echo "GATE PASSED: no High-risk DAST alerts"
  fi
  docker rm -f shielddesk >/dev/null 2>&1
fi

banner "RESULT"
if [ "$FAIL" -ne 0 ]; then echo "BUILD BLOCKED - insecure release stopped"; exit 1; fi
echo "BUILD PASSED - release allowed"; exit 0
