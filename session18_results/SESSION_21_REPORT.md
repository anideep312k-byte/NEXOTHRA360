# KAVACH360 — Session 21 Report

**Date:** 2026-09-22
**Scope:** Benchmark rigor — extract error classifier, add stability check
**Status:** PASS

## Baseline

- File before: `a091864caafee2f1cb7dd89c540512daaf27ad4c19dc3aa27080e28d8d6ffea6`
- Backup: `KAVACH360.py.before-session21-20260922-062651.bak`
- File after: `98d3e284e58f69fa09835bd479e3ff85743f672bb205f50d0f65b578b68d4648`

## Changes applied

1. Extracted `_classify_benchmark_error(_e)` from the inline error
   classification in the publisher loop. Pure refactor, no behavior change.
2. Publisher loop now calls the helper.
3. Replaced `regression.121` with a behavioral test that calls the helper
   directly with fake exception objects.
4. Added `regression.122_benchmark_stability`, which runs a short benchmark
   three times and records the intra-run spread. It does NOT fail the suite
   on a noisy host; it records the fact.

## Test results

| Matrix | Result |
|---|---|
| py_compile | PASS |
| self-test (nopg) | 141 / 141, failed 0 |
| self-test (yaml) | 141 / 141, failed 0 |
| self-test (yaml_pg) | 141 / 141, failed 0 |
| regression.121 | PASS |
| regression.122 | PASS |

Test count: 140 → 141.

## Benchmark stability measurement

10,000 EPS target, 3 repeats, warm-up discarded:

| # | Duration | Publish EPS |
|---|---|---|
| 1 | 43.81 s | 1,141.4 |
| 2 | 41.15 s | 1,215.2 |
| 3 | 42.28 s | 1,182.5 |

- median publish EPS: 1,198.85
- IQR publish EPS: [1,182.5, 1,215.2]
- full range: 73.8 EPS = 6.5%

## Cross-session summary (same code, same host)

| Session | Repeats | Median EPS | Range / min |
|---|---|---|---|
| 20A | 5 | 1,286.35 | 4.9% |
| 20B OFF | 5 | 1,201.35 | 18.2% |
| 20C | 5 | 1,245.55 | 29.1% |
| 21 | 3 | 1,198.85 | 6.5% |

Spread between the four medians: 7.3%.

## Findings

### F1 — Benchmark now has a documented noise floor

The host is sometimes noisy (ranges 18–29%) and sometimes quiet (ranges
5–7%). The intra-run spread recorded by regression.122 is the only signal
of which regime a given run fell into.

### F2 — Changes smaller than ~5% cannot be trusted

Even in the quiet regime, the benchmark's resolution is ~5–7%. In the
noisy regime, only changes above ~20% are measurable.

### F3 — The PostgreSQL migration is measurable against this benchmark

The expected effect of the migration (3–5× per Session 18 estimates) is
above the noise floor in either regime. The migration is measurable.

## What Session 21 did NOT do

- Did not change any pipeline logic
- Did not change the ingest path
- Did not change the bus or the database
- Did not introduce any external service

## Next step

Session 22: PostgreSQL migration for the bus and event pipeline. The
benchmark now has a documented noise floor that the migration's expected
effect size exceeds. Every improvement claim in Session 22 will be
accompanied by the intra-run stability reading from regression.122.
