---
name: Dashboard Authentication Feature Context
description: Key security findings and design decisions from the feature/security-authentication branch review (session auth, bcrypt, itsdangerous)
type: project
---

The `feature/security-authentication` branch added session-based login to the OVS SIEM dashboard. Key facts for future reviews:

- Session secret: env var `SESSION_SECRET_KEY` with fallback `"change-me-in-production"` in `api/app/main.py:80` — startup must validate this is overridden.
- Credentials: `DASHBOARD_USERNAME` and `DASHBOARD_PASSWORD_HASH` (base64-encoded bcrypt hash) from env vars; bcrypt checkpw used correctly.
- `https_only=False` in SessionMiddleware — intentional for local dev but must be `True` for any production/non-localhost deployment.
- `same_site="lax"` on session cookie — partially mitigates CSRF on login POST; does not fully cover logout CSRF.
- No login rate limiting in place as of this review.
- No audit logging for login success/failure/logout — Required Fix for a SIEM platform.
- Session fixation risk on login: session not cleared before setting `authenticated=True` — Required Fix.
- Agent-facing routes (`/ingest/log`, `/api/metrics` POST, `/api/agents/*`, `/install.sh`) correctly remain unauthenticated.
- Snyk Code scan: 5 first-party issues, all Low severity, all in test files. No issues in production auth code.
- SCA scan failed (venv resolution); mitigated by package health check: bcrypt 5.0.0 = Healthy/no CVEs; itsdangerous 2.2.0 = no CVEs, maintenance flagged as Inactive.

**Why:** Single-admin prototype with no RBAC yet — noted in ARCHITECTURE_DECISIONS.md. Security gaps above are known pre-conditions for further hardening before multi-user or production deployment.

**How to apply:** In any future review of auth changes, verify the three Required Fixes (startup secret validation, session fixation, audit logging) have been addressed before treating the feature as production-ready.
