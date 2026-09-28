# KAVACH360 — Session 25 Report

**Date:** 2026-09-23
**Scope:** HTTP ingest and process-mode throughput measurement.
**File hash:** 50a5b39c28efdd70f3628067c79785084f44df151de469347a348d3227ae0393
**Test count:** 153 / 153

## Configuration

- Process-mode topology: server (0 ingest workers) + supervisor (3 worker processes)
- Single-writer SQLite with autocommit=True
- KAVACH_BENCH_MODE=1 (server-side rate limiter raised)
- Fresh DB per run
- Events: 5000 at 100/500/1000/2000 EPS, 20000 at 5000/10000 EPS
- Warm-up: none; single run per rate

## Results

| Target | Events | Published | Errors | 429s | Publisher EPS | E2E EPS | Publish (s) | Drain (s) |
|---|---|---|---|---|---|---|---|---|
| 100 | 5000 | 5000 | 0 | 0 | 100.0 | 96.1 | 50.00 | 2.00 |
| 500 | 5000 | 5000 | 0 | 0 | 500.0 | 384.4 | 10.00 | 3.01 |
| 1000 | 5000 | 5000 | 0 | 0 | 1000.0 | 624.6 | 5.00 | 3.00 |
| 2000 | 5000 | 5000 | 0 | 0 | 1464.8 | 779.2 | 3.41 | 3.00 |
| 5000 | 20000 | 20000 | 0 | 0 | 1531.1 | 1244.6 | 13.06 | 3.01 |
| 10000 | 20000 | 20000 | 0 | 0 | 1565.8 | 1267.3 | 12.77 | 3.01 |

## Observations

1. All events published. Zero drops. Zero errors. Zero HTTP 429.
2. All queues drain to 0 within ~3 seconds of publish completion.
3. HTTP ingest ceases to reach target rate above ~1,500 EPS.
4. The publisher ceiling is between 1,464.8 and 1,565.8 EPS.

## Comparison

| Configuration | Publisher | E2E | Notes |
|---|---|---|---|
| Session 17 baseline | 785.3 | 347.6 | pre-fix |
| Session 22 PostgreSQL | 1,293 | — | process mode |
| Session 23d broken | 442 | 272.7 | HTTP broken |
| Session 24d broken | 362.9 | 193.2 | HTTP broken |
| **Session 25** | **1,565.8** | **1,267.3** | HTTP healthy |

HTTP ingest improved from 785 → 1,566 EPS (+99%).
End-to-end improved from 347.6 → 1,267 EPS (+264%).

## Bottleneck

The server's HTTP handler is the current ceiling at ~1,565 EPS.
This is not SQLite per se. It is the sequential bus.publish insert
per HTTP request, plus the shared _write_lock.

## Claims not made

- Not 10,000 EPS. Achieved ~1,565 publisher / ~1,267 end-to-end.
- Not enterprise-scale.
- Not production-ready.
- No comparative benchmark against Splunk, Sentinel, Wazuh.

## What would need to be measured next

- Sustained-load (multi-hour) behavior.
- Multi-tenant behavior.
- Batching of bus.publish inserts (N events per transaction).
- PostgreSQL backend with the same HTTP path.
