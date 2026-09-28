# KAVACH360 — Session 20A Report

**Date:** 2026-09-22
**Scope:** Benchmark rigor + verdict fix + regressions 118/119/120
**Status:** PASS

## Baseline

- File before: `de44d1e26bbe97a4039e5814ce6357033a6f8e97e1228f0f3d49f4c7fd1ecbd8`
- Backup: `KAVACH360.py.before-session20a-20260922-055017.bak`
- File after: `2858b7d6ee598a56c06dadac8479b02e741e6b66661e0f17991122b90c264333`

## Changes applied

1. `run_benchmark_hot` now delegates to `_run_benchmark_hot_once`. If
   `KAVACH_BENCH_REPEATS > 1`, it runs the benchmark that many times,
   discards the first as warm-up when `repeats >= 3`, and returns a
   statistical summary with median and interquartile range.
2. `_judge_hot_sample` was added. It returns `(ok, reasons)` for a single
   sample. It treats zero alerts as acceptable when the run was too short
   for the stateful rule to fire.
3. `run_benchmark_hot_with_watchdog` uses `_judge_hot_sample`. When the
   result contains `samples`, it judges each sample and reports unhealthy
   if any sample is unhealthy.
4. New field `end_to_end_eps` in the per-sample result dict.
5. Three regressions added:
   - `regression.118_aggregate_incident_no_degradation`
   - `regression.119_benchmark_verdict_low_eps`
   - `regression.120_benchmark_repeats_statistics`

## Test results

| Matrix | Result |
|---|---|
| py_compile | PASS |
| self-test (nopg) | 139 / 139, failed 0 |
| self-test (yaml) | 139 / 139, failed 0 |
| self-test (yaml_pg) | 139 / 139, failed 0 |

Test count: 136 → 139.

## Benchmark results

### 100 EPS, single run

- `ok: true`
- published 1000, processed 1000, dropped 0, errors 0
- alerts 0, incidents 0
- verdict fixed: zero alerts at this rate is expected, not a failure

### 1,000 EPS, 5 repeats

- median publish EPS: 1000.0
- IQR publish EPS: [1000.0, 1000.0] — width 0.0
- median end-to-end EPS: 142.9
- IQR end-to-end EPS: [142.9, 142.9] — width 0.0
- All 5 samples flat. Pipeline is rate-limited by the publisher at this tier.

### 10,000 EPS, 5 repeats

| # | Duration | Published | Processed | Dropped | Errors | Publish EPS | End-to-end EPS | p99 |
|---|---|---|---|---|---|---|---|---|
| 1 | 38.05s | 50000 | 50000 | 0 | 0 | 1313.9 | 640.6 | 4.079 |
| 2 | 37.84s | 50000 | 50000 | 0 | 0 | 1321.4 | 642.4 | 4.138 |
| 3 | 38.35s | 49999 | 50000 | 1 | 1 | 1303.8 | 638.2 | 8.452 |
| 4 | 39.70s | 50000 | 50000 | 0 | 0 | 1259.6 | 627.4 | 8.518 |
| 5 | 39.40s | 50000 | 50000 | 0 | 0 | 1268.9 | 629.7 | 4.307 |

- median publish EPS: 1286.35
- IQR publish EPS: [1268.9, 1321.4] — width 52.5 EPS, ~4.1%
- median end-to-end EPS: 633.95
- IQR end-to-end EPS: [629.7, 642.4] — width 12.7 EPS, ~2.0%

The benchmark reported `ok: false` because sample 3 had one drop and
one error. Four of five samples were clean. This is a real measured
result, not a synthetic failure, and it must not be hidden.

## Findings

### F1 — Verdict fix works

The 100 EPS tier now correctly reports `ok: true`. The previous
false-negative behavior is gone.

### F2 — Benchmark now has a measurable noise floor

At 10,000 EPS target, the interquartile range of publisher throughput
across 5 repeats is ~4% of the median. This is the smallest change the
current benchmark can resolve on this host.

### F3 — One event lost in one of five samples

One sample of 50,000 events lost 1 event with 1 error. The error type
was not recorded by the old benchmark; Session 20B adds that recording.
Classification is pending. It is not claimed as benign.

### F4 — At 1,000 EPS the pipeline is publisher-limited

All 5 samples hit exactly 1,000 EPS. IQR width 0. The benchmark cannot
distinguish between two builds at this tier, because both hit the same
ceiling.

## What Session 20A did NOT do

- Did not change detection, correlation, SOAR, auth, RBAC, MFA, UI, audit
- Did not change the ingest worker's write pattern
- Did not introduce PostgreSQL or any external service
- Did not claim 10,000 EPS is achievable

## Next step

Session 20B: benchmark error-type recording + ingest write coalescing
gated by `KAVACH_WRITE_COALESCE=1`. The coalescing change is measured
against the acceptance criteria stated in the Session 20B patch. If the
result is inside the noise floor, the change is reported as FLAT, not
improved.
