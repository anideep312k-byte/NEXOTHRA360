# KAVACH360 — Dependency License Report

Core KAVACH360.py has zero third-party dependencies (stdlib only).
kavach_storage has zero dependencies unless the postgres backend is used.

## Optional
| Package  | Version    | License      | Commercial | Notes |
|----------|------------|--------------|------------|-------|
| psycopg  | >=3.1,<4   | LGPL-3.0     | Yes, unmodified | Only needed for postgres backend. Include LGPL text in distribution. |
| postgres | 14+        | PostgreSQL License | Yes | Server only; not linked in. |

## Not present
AGPL, SSPL, BUSL, GPL — none.

## Not legal advice
Review LGPL obligations with a lawyer before commercial distribution.
