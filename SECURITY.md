# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in NEXOTHRA360, please report it responsibly:

- **Do NOT** open a public GitHub issue for security vulnerabilities
- **Response time:** Within 72 hours

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.0.x   | ✅        |

## Security Features

- PBKDF2 password hashing (600,000 iterations)
- TOTP MFA
- JWT HS256 + issuer/audience validation
- RBAC — 11 roles, 30+ permissions
- Tenant isolation
- Rate limiting + account lockout
- Hash-chained audit log
- CSP headers + XSS-safe rendering
- Prompt-injection defense

## Scope

NEXOTHRA360 is a learning project. Responsible disclosure appreciated.
