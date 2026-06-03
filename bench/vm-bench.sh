#!/usr/bin/env bash
# Runs INSIDE the rinha2c VM (2 vCPU, faithful 2-core mimic of the evaluator).
# Files expected in CWD: docker-compose.vm.yml, test.js, test-data.json
# Env knobs forwarded to compose: SPIN_US, CPUSET_API1/API2/LB, API_CPUS, LB_CPUS
set -uo pipefail
C=docker-compose.vm.yml
sudo docker compose -f $C down -v >/dev/null 2>&1 || true
sudo -E docker compose -f $C --compatibility up -d 2>&1 | tail -1
ok=0
for i in $(seq 1 40); do curl -sf -o /dev/null http://localhost:9999/ready && { ok=1; break; }; sleep 1; done
if [ "$ok" != 1 ]; then echo "READYFAIL"; sudo docker compose -f $C logs 2>&1 | tail -20; sudo docker compose -f $C down -v >/dev/null 2>&1; exit 1; fi
mkdir -p test
rm -f test/results.json
k6 run test.js >/dev/null 2>&1
python3 -c "import json;d=json.load(open('test/results.json'));s=d['scoring'];print(f\"SPIN_US=${SPIN_US:-0} CPUSET[api1=${CPUSET_API1:-0},api2=${CPUSET_API2:-1},lb=${CPUSET_LB:-0,1}] -> p99={d['p99']} fail={s['failure_rate']} FP/FN={s['breakdown']['false_positive_detections']}/{s['breakdown']['false_negative_detections']} final={s['final_score']}\")"
sudo docker compose -f $C down -v >/dev/null 2>&1
