# KAVACH360 — Session 21 Baseline (locked)

**Date:** 2026-09-22
**File hash at time of run:** 644b90c3904be432a0a394c575189393102cf8088a3c1f91bfe8b1395ebfbec7
**Test count:** 144 / 144 under nopg, yaml, yaml_pg

## Configuration

- Mode: hot-path benchmark, single-process
- Workers: 4 ingest, 2 detection, 2 correlation
- Actors: 500
- Target rate: 10,000 EPS
- Repeats: 3, warm-up discarded
- Host: same Kali host, clean (no stray KAVACH360 processes)

## Sample results

| Sample | Duration (s) | Published | Dropped | Errors | Publish EPS | E2E EPS |
|---|---|---|---|---|---|---|
| 1 | 37.61 | 50,000 | 0 | 0 | 1,329.6 | 644.3 |
| 2 | 40.94 | 50,000 | 0 | 0 | 1,221.3 | 617.8 |
| 3 | 40.58 | 50,000 | 0 | 0 | 1,232.2 | 620.5 |

## Summary statistics

- median_publish_eps: 1,226.75
- iqr_publish_eps: [1,221.3, 1,232.2]
- W (IQR width): 10.9 EPS
- R = W / M: 0.9%
- median_end_to_end_eps: 619.15

## Measurement quality

The benchmark can resolve differences above 0.9% on this host, on
this code, when the host is clean. This is the noise floor for any
comparison made after 2026-09-22.

## Known limitations

- Single-tenant workload
- Single-host
- Short-duration runs (~40 s per sample)
- No sustained-load measurement
- No multi-worker scaling test at this rate
- No PostgreSQL backend comparison yet (Session 22)

## Claims NOT made

- Not 10,000 EPS achieved. Achieved is 1,227 EPS median.
- Not enterprise-ready.
- Not production-ready.

## Session 22 acceptance criterion

The PostgreSQL migration is judged IMPROVED, FLAT, or REGRESSED by
comparing its median_publish_eps against 1,226.75 EPS with the same
protocol. If the difference does not exceed the new run's own IQR,
it is FLAT.
