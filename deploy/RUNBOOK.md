# Kavach360 Operational Runbook

## Daily
- Verify backup file < 24h old
- Check `/api/ready` returns `ready: true`
- Check `kavach360_broker_lag` < 10000 per stream

## Weekly
- Run audit chain verification (admin only): `GET /api/v1/soc/audit/verify`
- Review 5xx spikes in `kavach360_http_requests_total`
- Rotate API keys for external integrations

## Incident: Redis unavailable
1. Auth fails closed (503). This is expected.
2. Check: `redis-cli -u $REDIS_URL ping`
3. Restart: `docker compose restart redis`
4. Verify AOF: `redis-cli -u $REDIS_URL info persistence | grep aof_enabled`
5. Force all users to re-login (revocation state may be lost)

## Incident: PostgreSQL unavailable
1. Writes return 503.
2. Check: `pg_isready -h <host>`
3. Promote standby via HA tooling if primary down.
4. Verify `SELECT 1` before restarting API.

## Incident: Audit chain broken
1. `/api/v1/soc/audit/verify` returns `ok: false` with `broken_event_id`.
2. DO NOT delete audit table. Preserve for forensics.
3. Export chain to immutable storage.
4. Investigate: tampering, migration error, or clock skew.
5. Document and notify compliance.

## Restore
1. Stop API and workers.
2. `gunzip -c backup.sql.gz | psql $PG_URL`
3. Restart. Verify chain via `/audit/verify`.
