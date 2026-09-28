#!/bin/bash
# Session 18 Phase 1L — full 5000-event profiler benchmark.
# Same topology as Session 17: process mode, supervisor + server.
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
SERVER_LOG="$LOG_DIR/phase1L_server.log"
SUP_LOG="$LOG_DIR/phase1L_supervisor.log"
BENCH_LOG="$LOG_DIR/phase1L_bench.json"
ACCT_LOG="$LOG_DIR/phase1L_bench_account.log"
RUN_LOG="$LOG_DIR/phase1L_run.log"

exec > >(tee "$RUN_LOG") 2>&1

echo "=== Session 18 Phase 1L — 5000-event profiler benchmark ==="
echo "start: $(date -u +%Y-%m-%dT%H:%M:%SZ)"

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

echo "=== [5/6] run 5000-event benchmark @ 1000 EPS ==="
BENCH_T0=$(date +%s.%N)
KAVACH_BENCH_PASSWORD="$BENCH_PW" \
  python3 KAVACH360.py --bench-process \
    --host 127.0.0.1 --port 8543 \
    --bench-events 5000 --bench-rate 1000 \
    --bench-user bench --bench-tenant default \
    > "$BENCH_LOG" 2>&1
BENCH_RC=$?
BENCH_T1=$(date +%s.%N)
BENCH_WALL=$(echo "$BENCH_T1 - $BENCH_T0" | bc)
echo "benchmark exit code: $BENCH_RC"
echo "benchmark wall time (s): $BENCH_WALL"

if [ -s "$BENCH_LOG" ]; then
  python3 -c "
import json
try:
    d = json.load(open('$BENCH_LOG'))
    print('--- benchmark result ---')
    for k in ('ok','published','errors','http_429_count',
              'publisher_throughput_eps','end_to_end_eps',
              'publish_elapsed_seconds','drain_elapsed_seconds',
              'publish_http_latency_ms_p50','publish_http_latency_ms_p95',
              'publish_http_latency_ms_p99'):
        print(f'{k}: {d.get(k)}')
    print('drain_detail:', d.get('drain_detail'))
except Exception as e:
    print('parse error:', e)
"
fi

# give a moment for the profiles to flush
sleep 2

echo "=== [6/6] shutdown ==="
kill -INT "$SUP_PID" 2>/dev/null || true
wait "$SUP_PID" 2>/dev/null
echo "supervisor exit: $?"
kill -INT "$SERVER_PID" 2>/dev/null || true
wait "$SERVER_PID" 2>/dev/null
echo "server exit: $?"
sleep 2
REMAINING=$(pgrep -f 'KAVACH360.py' | wc -l)
echo "remaining KAVACH processes: $REMAINING"

echo "=== server profiler output ==="
grep 'profile_' "$SERVER_LOG" | tail -50
echo "=== supervisor profiler output ==="
grep 'profile_' "$SUP_LOG" | tail -50

echo "=== worker logs (individual pids) ==="
ls -1 "$LOG_DIR"/phase1L_*.log 2>/dev/null
for f in "$LOG_DIR"/phase1L_worker_*.log; do
  [ -e "$f" ] || continue
  echo "--- $f ---"
  grep 'profile_' "$f" | tail -30
done

echo "=== DONE ==="
echo "end: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
