#!/usr/bin/env bash
# Kavach360 backup script. Run daily via cron.
set -Eeuo pipefail

TARGET="${1:?Usage: backup.sh <target_dir>}"
TS="$(date +%Y%m%d_%H%M%S)"
mkdir -p "$TARGET"

DB_URL="${DATABASE_URL:?DATABASE_URL not set}"
PG_URL="${DB_URL/postgresql+pg8000:\/\//postgresql://}"

echo "[+] Dumping PostgreSQL to $TARGET/kavach360_$TS.sql.gz"
pg_dump "$PG_URL" | gzip > "$TARGET/kavach360_$TS.sql.gz"

echo "[+] Verifying dump"
gzip -t "$TARGET/kavach360_$TS.sql.gz" || { echo "[FAIL] dump corrupt"; exit 1; }

echo "[OK] Backup complete: $TARGET/kavach360_$TS.sql.gz"
