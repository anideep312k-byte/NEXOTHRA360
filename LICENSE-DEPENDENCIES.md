# Dependency License Audit

**Informational, not a legal opinion.**

| Dependency | License | Notes |
|-----------|---------|-------|
| Flask | BSD-3-Clause | OK |
| Werkzeug | BSD-3-Clause | OK |
| Flask-JWT-Extended | MIT | OK |
| Flask-Cors | MIT | OK |
| python-dotenv | BSD-3-Clause | OK |
| SQLAlchemy | MIT | OK |
| **pg8000** | **BSD-3-Clause** | Replaces psycopg2 (LGPL) |
| alembic | MIT | OK |
| bcrypt | Apache-2.0 | OK |
| pyotp | MIT | OK |
| redis-py | MIT | OK |
| requests | Apache-2.0 | OK |
| PyYAML | MIT | OK |
| dnspython | ISC | OK |
| networkx | BSD-3-Clause | OK |
| email-validator | CC0-1.0 | Public domain |
| prometheus-client | Apache-2.0 | OK |
| gunicorn | MIT | OK |

## Runtime path: 100% permissive (MIT / Apache-2.0 / BSD-3-Clause / ISC / CC0).

**No GPL, AGPL, LGPL, or SSPL in the runtime path.**

### Excluded (with reason)
- **psycopg2-binary** (LGPL) — replaced with pg8000
- **Wazuh** (GPL-2.0) — not bundled
- **VirusTotal API** (commercial terms) — not bundled
