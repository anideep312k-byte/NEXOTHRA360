# KAVACH360 — Session 22 Report

**Date:** 2026-09-22
**Scope:** PostgreSQL bus lease path with SELECT ... FOR UPDATE SKIP LOCKED.
**Verdict:** IMPROVED (publisher side). FLAT (end-to-end).
**File after:** 9486317015d8f14edd992cb934eb63a8d287aac6d26494ee5eff53d9e7defc24
**Test count:** 145 / 145 across nopg, yaml, yaml_pg.

## Changes applied

1. DurableBus.__init__ detects PostgreSQL backend, sets _is_postgres_backend.
2. DurableBus._lease_inner: PostgreSQL branch with FOR UPDATE SKIP LOCKED.
3. DurableBus._lease_inner: SQLite path preserved unchanged.
4. regression.126_postgres_bus_lease, gated on KAVACH_TEST_PG_DSN.

## Correctness gates

- py_compile PASS
- self-test (nopg): 145 / 145
- self-test (yaml): 145 / 145
- self-test (yaml_pg): 145 / 145
- regression.126: passed
- Orphan processes after: exit 1

## Prerequisite failure at start

KAVACH_TEST_PG_DSN was not set when Part 1 ran. The patch was
applied anyway, which was a process error. PostgreSQL itself was
reachable (version 18.6), and all 10 required tables were present.
The patch was functionally safe in this case; the preflight rule
was violated regardless.

## Benchmarks

### SQLite re-run (3 repeats)

- samples: 1153.7, 1277.2, 1258.5
- median_publish_eps: 1267.85
- iqr_publish_eps: [1258.5, 1277.2]
- W_sqlite: 18.7
- median_end_to_end_eps: 629.40

### PostgreSQL (5 repeats)

- samples: 1371.1, 1327.6, 1279.0, 1307.5, 1172.0
- median_publish_eps: 1293.25
- iqr_publish_eps: [1279.0, 1327.6]
- W_pg: 48.6
- median_end_to_end_eps: 635.65

## Verdict (locked rule)

- delta = M_pg - M_21 = 1293.25 - 1226.75 = +66.50
- noise = max(W_pg, W_21) = max(48.6, 10.9) = 48.6
- 66.50 > 48.6 => IMPROVED (publisher side)

- delta_e2e = 635.65 - 629.40 = +6.25
- noise_e2e = max(12.7, 12.9) = 12.9 (approx)
- 6.25 < 12.9 => FLAT (end-to-end)

## Claims NOT made

- Not 10,000 EPS. Achieved 1,293 EPS median.
- Not enterprise-ready.
- Not production-ready.
- SQLite ceiling not removed. One bus operation migrated.

## Confounds acknowledged

- SQLite ran 3 repeats, PostgreSQL ran 5.
- Small sample size. Verdict could change on a noisy host.
- Cause of the +5.4% bus improvement is not isolated.

## Next step

Session 23: measurement only. Profile the ingest worker under the
PostgreSQL backend to see whether the ingest stage is still dominant.
No patch until the measurement is complete.
