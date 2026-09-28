#!/bin/bash
# Session 18 Phase 1J — 200-event profiler smoke.
set -u
cd ~/kavach360
source .venv/bin/activate

export KAVACH_STORAGE_BACKEND=postgres
export KAVACH_STORAGE_DSN="postgresql://kavach:kavach_dev@127.0.0.1:5432/kavach"
export KAVACH_JWT_SECRET=$(openssl rand -hex 32)
export KAVACH_DETECTION_YAML=1
export KAVACH_WORKER_MODE=process
export KAVACH_BENCH_MODE=1
export KAVACH_HEARTBEAT_SECONDS=2
export KAVACH_PROFILE=1

LOG_DIR="$HOME/kavach360/session18_results"
SERVER_LOG="$LOG_DIR/phase1j_server.log"
SUP_LOG="$LOG_DIR/phase1j_supervisor.log"
BENCH_LOG="$LOG_DIR/phase1j_bench.json"
ACCT_LOG="$LOG_DIR/phase1j_bench_account.log"

echo "=== [1/6] cleanup old processes ==="
pkill -INT -f 'KAVACH360.py --host 127.0.0.1 --port 8543' 2>/dev/null || true
pkill -INT -f 'KAVACH360.py --supervise' 2>/dev/null || true
pkill -INT -f 'KAVACH360.py --worker' 2>/dev/null || true
sleep 2

echo "=== [2/6] create bench account ==="
python3 KAVACH360.py --create-bench-account \
  --bench-account-tenant default \
  --bench-account-name bench \
  --db "$(pwd)/kavach360.db" > "$ACCT_LOG" 2>&1
BENCH_PW=$(grep -oP '(?<=password:  )\S+' "$ACCT_LOG" | head -1)
echo "bench password length: ${#BENCH_PW}"
if [ -z "$BENCH_PW" ]; then
  echo "FATAL: could not extract bench password"
  echo "--- account log ---"
  cat "$ACCT_LOG"
  exit 1
fi

echo "=== [3/6] start server (background) ==="
python3 KAVACH360.py --host 127.0.0.1 --port 8543 --ingest-workers 0 \
  > "$SERVER_LOG" 2>&1 &
SERVER_PID=$!
echo "server pid: $SERVER_PID"
sleep 3
echo "healthz: $(curl -s http://127.0.0.1:8543/healthz)"

echo "=== [4/6] start supervisor (background) ==="
python3 KAVACH360.py --supervise > "$SUP_LOG" 2>&1 &
SUP_PID=$!
echo "supervisor pid: $SUP_PID"
sleep 5
CHILDREN=$(pgrep -P "$SUP_PID" | wc -l)
echo "supervisor children: $CHILDREN"

echo "=== [5/6] run 200-event benchmark @ 1000 EPS ==="
KAVACH_BENCH_PASSWORD="$BENCH_PW" \
  python3 KAVACH360.py --bench-process \
    --host 127.0.0.1 --port 8543 \
    --bench-events 200 --bench-rate 1000 \
    --bench-user bench --bench-tenant default \
    > "$BENCH_LOG" 2>&1
BENCH_RC=$?
echo "benchmark exit code: $BENCH_RC"
if [ -s "$BENCH_LOG" ]; then
  python3 -c "
import json, sys
try:
    d = json.load(open('$BENCH_LOG'))
    print('published:', d.get('published'))
    print('errors:', d.get('errors'))
    print('http_429_count:', d.get('http_429_count'))
    print('publisher_throughput_eps:', d.get('publisher_throughput_eps'))
    print('end_to_end_eps:', d.get('end_to_end_eps'))
    print('ok:', d.get('ok'))
except Exception as e:
    print('parse error:', e)
"
fi

echo "=== [6/6] shutdown ==="
kill -INT "$SUP_PID" 2>/dev/null || true
wait "$SUP_PID" 2>/dev/null
echo "supervisor exit: $?"
kill -INT "$SERVER_PID" 2>/dev/null || true
wait "$SERVER_PID" 2>/dev/null
echo "server exit: $?"
sleep 1
REMAINING=$(pgrep -f 'KAVACH360.py' | wc -l)
echo "remaining KAVACH processes: $REMAINING"

echo "=== profiler output (server) ==="
grep 'profile_' "$SERVER_LOG" | tail -40
echo "=== profiler output (supervisor) ==="
grep 'profile_' "$SUP_LOG" | tail -40

echo "=== DONE ==="
