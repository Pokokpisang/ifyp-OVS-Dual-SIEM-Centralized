# OVS Platform Architecture Decisions

This file is the shared architectural context for all OVS SecOps sub-agents. Read this at the start of each session before reviewing any feature or code change.

---

## Product Identity (as of 2026-05-21)

**OVS is no longer a prototype — it is an active industry product in development.**

Target customers: VPS/hosting operators, small MSPs, freelance Linux sysadmins managing 5–500 servers.
Positioning: Lightweight server security monitoring — easy deploy, AI-assisted triage, SOAR simulation, Detection-as-Code.

Current development phase: **Foundation hardening** — closing operational gaps (migrations, notifications, TLS, retention) before expanding features.
Active sprint: See `docs/strategy/OVS_Sprint_Board_2Week.md`.
Strategic analysis: See `docs/strategy/OVS_Strategic_Product_Analysis_May2026.md`.

Sub-agents must weigh architectural decisions against this product direction. Features that increase deployment complexity for minimal operational gain are a poor fit for OVS's target market.

---

## Platform Overview

OVS is a SIEM/SOAR platform for VPS/server security monitoring. Components:

- **FastAPI backend** (`api/`) — log ingestion, rule evaluation, alerting, web dashboard
- **Go agent** (`agent/`) — lightweight endpoint collector; tails logs, sends telemetry
- **OpenSearch pipeline** — Data Prepper receives forwarded logs for search/analytics
- **Detection system** — YAML Detection-as-Code under `api/app/detection/rules/`
- **Database** — PostgreSQL via SQLAlchemy; key tables: `logs`, `metrics`, `alerts`, `detection_rules`, `rule_matches`, `agent_records`, `system_health_rules`, `alert_assessments`

---

## Hard Platform Constraints

### SOAR: Simulation-First, Always
- All SOAR actions are simulated by default. Real destructive actions (firewall block, account disable, process kill, file delete, host isolation) must never be automated without explicit RBAC gating, approval flow, audit logging, rollback support, allowlists, rate limits, feature flags, and clear UI warnings.
- AI triage must never directly trigger any SOAR action — automated or simulated.
- Recommended live action progression: Recommendation only → Simulation → Manual live action outside platform → Approval-gated live action → Limited automatic live action for low-risk reversible cases only.

### AI Triage: Advisory Only, Never Source of Truth
- AI triage verdicts must be one of: `LIKELY_TRUE_POSITIVE`, `LIKELY_FALSE_POSITIVE`, or `UNCERTAIN`.
- AI summarizes, explains, and classifies. It must never be the deterministic source of alert validity.
- AI output must never trigger automated response, auto-close alerts, or replace analyst judgment.
- Any feature that makes AI output influence automated action is a hard NO-GO.

### Detection Engine: Deterministic and Auditable
- Detection pipeline: `POST /ingest/log` → `collector.py` → background task → `RuleEngine.evaluate_raw()` → `ActiveDetectionRunner` → `YAMLDetectionEngine` + `CorrelationEngine` → `models.Alert`
- Active modes: `YAML` (default), `SHADOW` (dual-run, YAML results not persisted), `LEGACY` (fallback) — controlled by `DETECTION_ENGINE_MODE` env var.
- All rules must be explainable, testable, and mapped to MITRE ATT&CK.

---

## Known Platform Limitations

### Correlation Engine — In-Process Only
- `CorrelationEngine` uses an in-memory `ProcessEventBuffer` (per-agent rolling deque).
- **Known limitation**: buffer is lost on API restart and not shared across multiple API workers.
- Any detection rule relying on correlation state across multiple workers will silently fail in multi-worker deployments.
- Do not design correlation rules that assume cross-worker state until this is addressed (Redis-backed or DB-backed buffer).
- New T1110/T1053/T1078 sprint rules must use DB-backed count queries, not the in-process CorrelationEngine.

### Dashboard Authentication — Session-Based, Single Admin
- Dashboard uses session-based login (merged in v2.8.0).
- **No multi-user RBAC yet** — all authenticated users have the same access level.
- Multi-tenancy is a planned 3-month milestone, not a current feature. Do not design features that assume per-tenant data isolation until the tenant model is built.

### Agent TLS — Not Yet Enforced
- `ARCHITECTURE_DECISIONS.md` states TLS must be validated, but the Go agent sender does not currently enforce `InsecureSkipVerify=false`.
- **Sprint task W1-P1**: TLS enforcement is being added. Until merged, do not assume the agent-to-server channel is encrypted in dev/test deployments.

### Log and Metrics Retention — Unbounded
- PostgreSQL tables `logs` and `metrics` grow without bound.
- **Sprint task W1-P2**: a configurable TTL cleanup job is being added.
- Until merged, warn operators deploying to production that disk growth is uncontrolled.

### Agent Registration — Token Single-Use
- Registration tokens are SHA-256 hashed in DB; the token is nulled after first use.
- Permanent `agent_key` is issued after successful registration.
- `X-Agent-Key` header is used for all subsequent requests.
- No key rotation UI exists yet — rotation is a future sprint item.

### Notification System — Not Yet Built
- No email, webhook, or Slack notification system exists.
- **Sprint task W1-P0**: being built now. Until merged, alerts are only visible in the dashboard.

### OpenSearch — Wired but Underused
- Data Prepper and OpenSearch are in `docker-compose.yml` but the dashboard does not use OpenSearch for any operational feature.
- Do not expand OpenSearch integration until a real customer's log volume justifies the operational complexity.
- PostgreSQL full-text search is sufficient at current scale.

---

## Module Placement Rules

| Change type | Correct layer |
|---|---|
| New detection condition logic | `api/app/detection/engine/rule_evaluator.py` |
| New YAML detection rule | `api/app/detection/rules/<platform>/<tactic>/<technique>/` |
| New detection rule test | `api/app/detection/tests/` — always add true-positive + false-positive fixture |
| New suppression | `api/app/detection/tuning/*.yaml` |
| New alert field | `api/app/models.py` + Alembic migration (required, no exceptions) |
| New notification channel type | `api/app/services/notification/` (being created in sprint) |
| New SOAR playbook | `api/app/soar/playbooks/` — YAML only, not detection engine, not AI triage |
| AI triage changes | `api/app/ai_triage/` — advisory layer only, no writes to alert truth fields |
| Agent behavior changes | `agent/internal/` — prefer low resource usage and safe defaults |
| New API route | Appropriate router in `api/app/routers/` |
| New model | `api/app/models.py` + Alembic migration, never `create_all()` workaround |
| Background / scheduled tasks | Registered at startup in `api/app/main.py` lifespan; keep tasks non-blocking |
| New environment variable | Add to `api/.env.example` and document in `CLAUDE.md` environment section |

---

## Database Migration Convention

- **Alembic is being added as sprint P0 (2026-05-21).** Once merged, all schema changes must go through an Alembic migration file. Do not bypass this with `create_all()` or raw SQL on a production database.
- Until Alembic is merged: migrations are handled at startup via SQLAlchemy `create_all()` or manual SQL — treat any schema change as high-risk.
- All schema changes must be backward-compatible or include an explicit migration plan.
- Index all foreign keys and any column used in alert queries (`alert_id`, `agent_id`, `created_at`).
- New `NOT NULL` columns require a safe default or a two-step migration (add nullable → backfill → add constraint).
- New model additions (e.g., `NotificationChannel`, sprint target) must include an Alembic migration file before merging.

---

## Security Boundaries

- `X-Agent-Token` (registration, one-time) and `X-Agent-Key` (permanent) must never be logged.
- Dashboard session secrets must come from environment variables, never hardcoded.
- SOAR recommendations must never embed raw alert content that could leak PII or credentials.
- Jinja2 templates must use `{{ var }}` (auto-escaped) not `{{ var | safe }}` unless explicitly reviewed.
- Go agent: TLS must be validated; insecure skip-verify is not acceptable in production. (**Sprint W1-P1 is enforcing this — do not merge agent code that enables InsecureSkipVerify.**)
- Notification webhooks must be signed with HMAC-SHA256 — never send alert data to an unsigned endpoint.
- When multi-tenancy is added: every DB query touching `logs`, `metrics`, `alerts`, or `agent_records` must be scoped to `tenant_id`. No cross-tenant query is ever acceptable.
- AI triage prompts must not include raw log lines that may contain credentials, tokens, or PII without sanitization.

---

## Agent Sub-Agent Handoff Chain

Before implementing any significant feature:
1. `secops-architecture-reviewer` — does this fit the architecture?
2. `detection-rule-engineer` — if detection rules are involved
3. `soar-simulation-engineering` — if SOAR playbooks or response actions are involved
4. `code-security-reviewer` — before merge, run Snyk scan on new code
5. `test-and-release-auditor` — GO/NO-GO before merging to main

A missing Snyk scan result = automatic NO-GO from `test-and-release-auditor`.
