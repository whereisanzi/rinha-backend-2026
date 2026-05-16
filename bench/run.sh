#!/usr/bin/env bash
# bench/run.sh — replicates the rinha-de-backend-2026 bot evaluation.
#
# Usage:
#   ./bench/run.sh            # uses ./docker-compose.yml from repo root
#   COMPOSE=path ./bench/run.sh
#
# Behavior:
#   1) docker compose down -v (clean slate)
#   2) docker logout ghcr.io (simulate bot — no creds)
#   3) docker compose --compatibility up -d
#   4) wait for GET http://localhost:9999/ready
#   5) k6 run bench/test/test.js (the official test from zanfranceschi/rinha-de-backend-2026)
#   6) print bench/test/results.json (final_score, p99, failure_rate)
#   7) docker compose down -v
#
# Exit codes:
#   0 = test ran (regardless of score — caller checks final_score)
#   1 = stack failed to come up / /ready timeout
#   2 = k6 missing
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BENCH_DIR="$REPO_ROOT/bench"
COMPOSE="${COMPOSE:-$REPO_ROOT/docker-compose.yml}"

if ! command -v k6 >/dev/null 2>&1; then
  echo "ERROR: k6 not installed (apt install k6 OR https://k6.io/docs/get-started/installation/)" >&2
  exit 2
fi

if [ ! -f "$COMPOSE" ]; then
  echo "ERROR: compose file not found: $COMPOSE" >&2
  exit 1
fi

cd "$BENCH_DIR"

if [ ! -f test/test-data.json ]; then
  echo "=== fetch test-data.json (26 MB) from upstream ==="
  curl -sSLf -o test/test-data.json \
    "https://raw.githubusercontent.com/zanfranceschi/rinha-de-backend-2026/main/test/test-data.json"
  echo "  size: $(wc -c < test/test-data.json) bytes"
fi

echo "=== teardown previous (if any) ==="
docker compose -f "$COMPOSE" down -v 2>&1 | tail -3 || true

echo "=== simulate bot: docker logout ghcr.io (anonymous pull) ==="
docker logout ghcr.io 2>&1 | tail -1 || true

echo "=== up --compatibility (apply deploy.resources.limits) ==="
docker compose -f "$COMPOSE" --compatibility up -d 2>&1 | tail -10

echo "=== wait /ready (up to 60s) ==="
ok=0
for i in $(seq 1 30); do
  if curl -sf -o /dev/null http://localhost:9999/ready; then
    echo "/ready ok at attempt $i"
    ok=1
    break
  fi
  sleep 2
done
if [ "$ok" != "1" ]; then
  echo "ERROR: /ready never came up in 60s"
  docker compose -f "$COMPOSE" logs 2>&1 | tail -50
  docker compose -f "$COMPOSE" down -v >/dev/null 2>&1 || true
  exit 1
fi

echo "=== k6 run test/test.js (900 req/s sustained 120s) ==="
date "+inicio: %Y-%m-%d %H:%M:%S"
rm -f test/results.json
k6 run test/test.js 2>&1 | tail -40 || true
date "+fim:    %Y-%m-%d %H:%M:%S"

echo
echo "=== RESULT ==="
if [ -f test/results.json ]; then
  python3 - <<'PY'
import json
d = json.load(open("test/results.json"))
s = d.get("scoring", {})
print(f"  p99:           {d.get('p99')}")
print(f"  failure_rate:  {s.get('failure_rate')}")
print(f"  http_errors:   {s.get('breakdown', {}).get('http_errors')}")
print(f"  TP / TN:       {s.get('breakdown', {}).get('true_positive_detections')} / {s.get('breakdown', {}).get('true_negative_detections')}")
print(f"  FP / FN:       {s.get('breakdown', {}).get('false_positive_detections')} / {s.get('breakdown', {}).get('false_negative_detections')}")
print(f"  p99_score:     {s.get('p99_score')}")
print(f"  detection:     {s.get('detection_score')}")
print(f"  final_score:   {s.get('final_score')}")
PY
else
  echo "  (test/results.json not produced)"
fi

echo
echo "=== mem snapshot before teardown ==="
docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}" $(docker compose -f "$COMPOSE" ps --format "{{.Name}}" 2>/dev/null) 2>/dev/null || true

echo
echo "=== teardown ==="
docker compose -f "$COMPOSE" down -v 2>&1 | tail -3
