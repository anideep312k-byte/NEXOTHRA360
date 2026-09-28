# NEXOTHRA360

**AI-Native Security Operations Platform**

A single-file, zero-dependency SOC platform built end-to-end.

## Overview

NEXOTHRA360 is an original defensive cybersecurity platform that takes a
security event from ingestion through detection, correlation, risk scoring,
investigation, and response — with multi-tenant isolation, RBAC,
hash-chained audit, and an AI L1–L5 pipeline.

Learning project — not a replacement for enterprise SIEM/SOAR.

## Capabilities

Backend (single Python file, stdlib only):
- Multi-tenant (SQLite + PostgreSQL)
- JWT + PBKDF2 (600k) + TOTP MFA
- RBAC — 11 SOC roles, 30+ permissions
- Tenant isolation on every query
- Durable message bus (DLQ, lease, backpressure)
- Ingestion (syslog, file, HTTP)
- Pipeline: normalize → validate → enrich → dedup
- Detection engine — 7 rules + YAML loader
- MITRE ATT&CK mapping
- Correlation — incident state machine
- Risk engine — multi-factor
- UEBA — online baselines
- IOC store — 4 types, tenant-scoped
- AI L1–L5 — rule-based + statistical
- SOAR — propose/approve/execute/rollback + kill switch
- Hash-chained audit log
- Cases + incidents + alerts

Frontend:
- Single-page UI — vanilla HTML/CSS/JS
- Dark + light themes
- 20+ pages (Dashboard, Alerts, Incidents, Cases, Events, IOC, Detections,
  MITRE, Assets, Risk, Hunting, Investigation, SOAR, AI, Audit, Users,
  Profile, Reports, Settings, Health)
- Real API data only — no fabricated metrics
- Honest empty states
- Responsive (laptop → 4K)
- Accessible (keyboard, focus, reduced-motion)
- XSS-safe rendering

## Quick Start

    python3 KAVACH360.py --self-test

    KAVACH_JWT_SECRET=$(openssl rand -hex 32) \
      KAVACH_DETECTION_YAML=1 \
      KAVACH_WORKER_MODE=process \
      python3 KAVACH360.py --host 127.0.0.1 --port 8443 \
        --ingest-workers 0 --db kavach360.db

Open http://127.0.0.1:8443 and login with the bootstrap password
printed to the log once.

## API

All under /v1/. Bearer JWT.

- Auth: /v1/auth/login, /v1/auth/logout, /v1/auth/change_password
- Data: /v1/dashboard, /v1/alerts, /v1/incidents, /v1/cases,
  /v1/events, /v1/entities, /v1/iocs, /v1/detections,
  /v1/audit, /v1/response_actions
- AI: /v1/ai/l1 … /v1/ai/l5
- SOAR: /v1/soar/propose|approve|execute|rollback|killswitch
- Health: /healthz, /readyz, /metrics, /v1/health, /v1/version

## Security

- PBKDF2 password hashing (600,000 iterations)
- TOTP MFA
- JWT HS256 + issuer/audience validation
- Per-user + per-IP rate limiting
- Account lockout
- Hash-chained audit log
- XSS-safe frontend
- CSP headers
- Prompt-injection defense
- Tenant isolation

## Testing

    python3 KAVACH360.py --self-test

159 tests covering auth, RBAC, tenant isolation, detection,
correlation, risk, IOC, UEBA, SOAR, audit, and regressions.

## Performance

~700 req/s sustained on a single Kali VM.
p50 44 ms, p99 49 ms. See --bench for details.

## Design Principles

1. Single file
2. Zero external dependencies
3. Defensive by default
4. Original code
5. Honest reporting
6. Backend preserved

## Limitations

Learning project — not production-ready enterprise SIEM/SOAR.

- Single-node (no horizontal scaling)
- SQLite single-writer bottleneck
- 7 built-in rules (no 1000+ library)
- Local threat intel only
- Rule-based + statistical AI
- No SSO
- No SOC2 / ISO 27001
- No 24/7 support

## Roadmap

| Phase | Scope | Timeline |
|---|---|---|
| 1 | Foundation | Done |
| 2 | Scale (PostgreSQL, Kafka) | 2 months |
| 3 | Security (SSO, ABAC, pen test) | 2 months |
| 4 | Detection (1000+ rules, Sigma) | 3 months |
| 5 | SOAR (playbooks, integrations) | 3 months |
| 6 | Compliance (SOC2, ISO 27001) | 6 months |
| 7 | Support + sales | 6 months |

## License

Original work. No competitor code, assets, or branding used.

## Author

Anideep — github.com/anideep312k-byte

Not a clone of Wazuh, Splunk, Microsoft Sentinel, IBM QRadar,
Elastic Security, Palo Alto Cortex XSOAR, or any other product.

## Copyright & Usage

© 2026 Anish (Anideep) — NEXOTHRA360

This project is licensed under the **MIT License**.

You are free to:
- Use, copy, modify
- Distribute

Under the condition:
- Attribution required — keep the copyright notice
- License notice preserved

Commercial use: allowed under MIT terms.

Original author: Anish (Anideep)
GitHub: [github.com/anideep312k-byte/NEXOTHRA360](https://github.com/anideep312k-byte/NEXOTHRA360)

Not a clone of Wazuh, Splunk, Microsoft Sentinel, IBM QRadar,
Elastic Security, Palo Alto Cortex XSOAR, or any other product.
