# OVS Platform Architecture Decisions

This file is the shared architectural context for all OVS SecOps sub-agents. Read this at the start of each session before reviewing any feature or code change.

---

## Platform Overview

OVS is a prototype SIEM/SOAR platform for VPS/server security monitoring. Components:

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

### Dashboard Authentication — Session-Based
- Dashboard uses session-based login (recent addition, `feature/security-authentication` branch).
- No multi-user RBAC yet — all authenticated users have the same access level.

### Agent Registration — Token Single-Use
- Registration tokens are SHA-256 hashed in DB; the token is nulled after first use.
- Permanent `agent_key` is issued after successful registration.
- `X-Agent-Key` header is used for all subsequent requests.

---

## Module Placement Rules

| Change type | Correct layer |
|---|---|
| New detection condition logic | `api/app/detection/engine/rule_evaluator.py` |
| New YAML detection rule | `api/app/detection/rules/<platform>/<tactic>/<technique>/` |
| New suppression | `api/app/detection/tuning/*.yaml` |
| New alert field | `api/app/models.py` (requires DB migration) |
| New SOAR playbook | SOAR service layer (not detection engine, not AI triage) |
| AI triage changes | Advisory layer only — no writes to alert truth fields |
| Agent behavior changes | `agent/internal/` — prefer low resource usage and safe defaults |
| New API route | Appropriate router in `api/app/routers/` |

---

## Database Migration Convention

- No Alembic in use — migrations are handled at startup via SQLAlchemy `create_all()` or manual SQL.
- All schema changes must be backward-compatible or include an explicit migration plan.
- Index all foreign keys and any column used in alert queries (`alert_id`, `agent_id`, `created_at`).
- New `NOT NULL` columns require a safe default or a two-step migration (add nullable → backfill → add constraint).

---

## Security Boundaries

- `X-Agent-Token` (registration, one-time) and `X-Agent-Key` (permanent) must never be logged.
- Dashboard session secrets must come from environment variables, never hardcoded.
- SOAR recommendations must never embed raw alert content that could leak PII or credentials.
- Jinja2 templates must use `{{ var }}` (auto-escaped) not `{{ var | safe }}` unless explicitly reviewed.
- Go agent: TLS must be validated; insecure skip-verify is not acceptable in production.

---

## Agent Sub-Agent Handoff Chain

Before implementing any significant feature:
1. `secops-architecture-reviewer` — does this fit the architecture?
2. `detection-rule-engineer` — if detection rules are involved
3. `soar-simulation-engineering` — if SOAR playbooks or response actions are involved
4. `code-security-reviewer` — before merge, run Snyk scan on new code
5. `test-and-release-auditor` — GO/NO-GO before merging to main

A missing Snyk scan result = automatic NO-GO from `test-and-release-auditor`.
