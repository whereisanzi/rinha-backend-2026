#!/usr/bin/env bash
# bench/run-2core.sh — mimic the rinha bot's hardware (Mac Mini Late 2014:
# 2.6 GHz, ~2 cores) by pinning the whole stack AND k6 onto CORES physical
# cpus, so they contend the way they do on the evaluator. maracatu (12 idle
# cores) otherwise massively understates p99.
#
# Env:
#   CORES       cpus to confine everything to (default "0,1")
#   SEARCH SCHED FAST_NPROBE RINHA_CPU1 RINHA_CPU2  passed through to the stack
#   NOBUILD=1   skip docker build
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE="$REPO_ROOT/docker-compose.yml"
CORES="${CORES:-0,1}"
cd "$REPO_ROOT"

[ -f bench/test/test-data.json ] || cp "$HOME/rinha-official/test/test-data.json" bench/test/test-data.json 2>/dev/null || true

docker compose -f "$COMPOSE" down -v >/dev/null 2>&1 || true
if [ "${NOBUILD:-0}" != "1" ]; then
  echo "=== build ==="
  docker compose -f "$COMPOSE" build 2>&1 | tail -3
fi

echo "=== up (CORES=$CORES SEARCH=${SEARCH:-0} FAST_NPROBE=${FAST_NPROBE:-4} SCHED=${SCHED:-fifo} RINHA_CPU1=${RINHA_CPU1:-0} RINHA_CPU2=${RINHA_CPU2:-2}) ==="
docker compose -f "$COMPOSE" --compatibility up -d 2>&1 | tail -3

# Confine every service container to CORES so the stack + k6 share the same cpus.
ids=$(docker compose -f "$COMPOSE" ps -q)
for id in $ids; do docker update --cpuset-cpus "$CORES" "$id" >/dev/null; done
echo "confined containers to cpus $CORES"

ok=0
for i in $(seq 1 30); do curl -sf -o /dev/null http://localhost:9999/ready && { ok=1; break; }; sleep 1; done
if [ "$ok" != 1 ]; then echo "ERROR: /ready never came up"; docker compose -f "$COMPOSE" logs 2>&1 | tail -30; docker compose -f "$COMPOSE" down -v >/dev/null 2>&1; exit 1; fi

echo "=== k6 (pinned to cpus $CORES) ==="
rm -f bench/test/results.json
( cd bench && taskset -c "$CORES" k6 run test/test.js 2>&1 | tail -3 )

echo "=== RESULT (2-core mimic) ==="
python3 - <<'PY'
import json
try:
    d=json.load(open("bench/test/results.json")); s=d.get("scoring",{})
    print(f"  p99={d.get('p99')}  failure={s.get('failure_rate')}  http_errors={s.get('breakdown',{}).get('http_errors')}")
    print(f"  FP/FN={s.get('breakdown',{}).get('false_positive_detections')}/{s.get('breakdown',{}).get('false_negative_detections')}")
    print(f"  p99_score={s.get('p99_score',{}).get('value')}  detection={s.get('detection_score',{}).get('value')}  final={s.get('final_score')}")
except Exception as e:
    print("  no results:", e)
PY
docker compose -f "$COMPOSE" down -v >/dev/null 2>&1
