# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

**OVS — Server Security Platform for Hosting Operators and MSPs.**

This project has transitioned from an FYP SIEM prototype into a real industry product direction targeting VPS/server operators, small MSPs, and hosting providers. All development decisions should be made with this audience and goal in mind.

The system consists of four main components:

1. **FastAPI backend** (`api/`) — log ingestion, detection engine, alerting + notifications, admin/analyst SOC dashboard, SOAR simulation, AI triage, tenant management, audit trail
2. **Go agent** (`agent/`) — lightweight single-binary endpoint collector; tails logs, sends telemetry, offline-buffered
3. **Client portal** (`portal/`) — standalone read-only FastAPI+Jinja app for one tenant; runs in a SEPARATE environment, no database, consumes only the SOC's `/api/portal/*` endpoints via a per-client API key. Clients can never register agents or mutate SOC state.
4. **OpenSearch pipeline** — Data Prepper receives forwarded logs for search/analytics (low priority until log volume justifies it)

**Current product stage (v2.13.0):** the 2026-07 UI redesign Phases 1–4 are complete — role-aware shell, audit trail UI, notification channels, DB-backed users/RBAC, settings hub, detection-rule management + MITRE coverage, tenant layer + client portal, design reskin, enforced data retention. Remaining work is Phase-5 polish (exports, saved filters, search, network-page data decision). The plan of record is `docs/roadmap/UI_Implementation_Gap_Audit_2026-07.md` (+ progress report alongside it).

**Git conventions:** the repo is **rebase-merge only**; `Master` and `Development` have diverged with duplicate-SHA commits — always branch from up-to-date `origin/Development` and target PRs at `Development`. `.gitignore` ignores `docs/*` **except** `docs/roadmap/` (product docs); `docs/strategy/` files referenced historically are local-only.

## Commands

### Start/Stop the Full System

```bash
make up        # builds Go agent, starts Docker services (API :8000, portal :8100, DB, OpenSearch, Data Prepper), runs agent as background sudo process
make down      # stops Docker services and kills agent
make restart   # down then up — REQUIRED to pick up code changes (images bake code at build time)
make logs      # tail docker-compose service logs
```

The `docker-compose-v2` binary (committed to repo root) is used instead of the system `docker compose` command.

**Client portal first run:** `make up` seeds `portal/.env` from `portal/env.example`. Issue a key in the SOC dashboard (Assets → Clients → Issue portal key), paste it as `CLIENT_API_KEY`, then **recreate** (not restart) the container: `./docker-compose-v2 up -d portal` — plain `restart` does not reload `env_file`.

### Build the Go Agent Only

```bash
cd agent && go build -o agent ./cmd/agent/main.go
# or via Makefile (also copies binary to api/downloads/):
make build-agent
```

### Run the API in Development (without Docker)

```bash
cd api
source .venv/bin/activate
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### Run Tests

```bash
cd api && source .venv/bin/activate

# Everything (≈380 tests):
python -m pytest app/tests/ app/detection/tests/ -v

# app/tests/       — auth, RBAC, CSRF, services (audit, notifications, users,
#                    clients, portal API, retention, SOAR, agent monitor…)
# app/detection/tests/ — YAML engine, rules, correlation, fixtures

# Client portal tests:
cd ../portal && PYTHONPATH=. ../api/.venv/bin/python -m pytest tests/ -v
```

When adding new detection rules: always add a fixture test (true-positive + false-positive) under `api/app/detection/tests/`.

## Architecture

### Detection Pipeline

The active detection path: `POST /ingest/log` → `collector.py` → background task → `RuleEngine.evaluate_raw()` → `ActiveDetectionRunner` → `YAMLDetectionEngine` + `CorrelationEngine` → `alert_service.create_alert` → notification dispatch.

**Detection engine mode:** the engine is YAML-only. `RuleEngine` delegates unconditionally to `ActiveDetectionRunner` (YAML rules + correlation + SSH brute-force). The legacy `DETECTION_ENGINE_MODE` env var is retained for backward compatibility but is **intentionally ignored**.

**Key detection engine files:**
- `api/app/detection/engine/detection_engine.py` — `RuleEngine` thin wrapper; always delegates to `ActiveDetectionRunner`
- `api/app/detection/engine/active_runner.py` — `ActiveDetectionRunner`: calls `YAMLDetectionEngine` (passing runtime-disabled rule ids), then optionally `CorrelationEngine`
- `api/app/detection/engine/yaml_detection_engine.py` — load rules → filter overrides → evaluate → score risk → check suppressions → return `DetectionCandidate`
- `api/app/detection/engine/correlation_engine.py` — in-memory rolling buffer detecting "curl/wget → bash" two-event patterns (T1059.004)
- `api/app/detection/engine/audit_parser.py` — normalises raw auditd log lines into ECS-compatible dicts
- `api/app/detection/engine/rule_loader.py` — loads YAML rule files recursively from `detection/rules/` (mtime-cached; runs per event)
- `api/app/detection/engine/rule_evaluator.py` — field-based condition matching
- `api/app/detection/engine/risk_scoring.py` — base score + `risk_adjustment` adjustments
- `api/app/detection/engine/suppressions.py` — loads `detection/tuning/*.yaml` false-positive suppressions

**Runtime rule toggle:** `detection_rule_overrides` table + `services/rule_override_service.py` (30s TTL cache on the hot path). Overrides can only DISABLE file-enabled rules — the YAML `enabled` flag (detection-as-code) stays authoritative; file-disabled rules cannot be enabled from the UI.

### Detection-as-Code Rules

YAML rules live under `api/app/detection/rules/` (organised by `platform/tactic/technique/`). Rule schema: `api/app/detection/schemas/rule_schema.py` (`DetectionRule` Pydantic model). Suppression tuning files: `api/app/detection/tuning/`. The dashboard exposes rules read-only at `/detection/rules` (30-day alert stats, admin pause toggle) and real ATT&CK coverage at `/detection/mitre`.

### Correlation Engine

Handles fragmented auditd events where `curl http://... | bash` appears as two separate EXECVE records. Order-insensitive singleton in-memory `ProcessEventBuffer` + `DedupCache`. Env: `ENABLE_CORRELATION_ENGINE`, `CORRELATION_WINDOW_SECONDS` (10), `CORRELATION_BUFFER_TTL_SECONDS` (60), `CORRELATION_DEDUP_SECONDS` (60). **Known limitation:** buffer is in-process only.

### Background tasks (main.py startup; all failure-isolated, single-process)

- **Agent dead-silence sweep** — every `AGENT_SILENCE_SWEEP_SECONDS` (60): agents silent past `AGENT_SILENCE_THRESHOLD_MINUTES` (5) get ONE HIGH alert per outage episode (dedup key embeds `last_seen`). Kill-switch `AGENT_SILENCE_ALERTING_ENABLED`.
- **Retention sweep** — every `RETENTION_SWEEP_SECONDS` (3600): deletes logs/metrics past `LOG_RETENTION_DAYS`/`METRICS_RETENTION_DAYS` (unset = unlimited). Alerts, audit events, SOAR history are exempt (security record). Real deletions are audited (`DATA_RETENTION_APPLIED`).
- **Notification dispatch** runs on daemon threads per alert (never blocks ingestion; failures become `failed` delivery rows).

Note for scaling: these are per-process; revisit before running multiple uvicorn workers.

### Tenancy & Client Portal (Phase 4)

- `clients` table + nullable `agent_records.client_id`. Alerts/logs/metrics scope THROUGH agent assignment via `services/client_service.py` (`client_hostnames` / `client_alerts_query` — the single fail-closed choke point: a client with no agents matches nothing; unassigned agents are SOC-internal).
- Per-client portal API keys: `ovsc_` prefix, SHA-256 stored, raw shown once, rotate/revoke on `/clients/{id}`; suspended clients fail closed. Lifecycle audited; raw keys never stored/logged/audited.
- `/api/portal/*` (routers/portal.py): **GET-only** (structural test enforces), exact portal-safe serializers (no rule internals, SOAR data, keys, or internal UUIDs), `X-Client-Key` auth, rate-limited.
- `portal/` app: see component list above. Deps are **pinned** (`portal/requirements.txt`) after a Starlette 1.x breakage — bump deliberately and re-run `portal/tests/`.

### Auth, Users, RBAC

- Session auth: signed cookie + server-side `server_sessions` rows (hash-stored tokens); `ServerSessionMiddleware` sets `request.state.user = {username, role}`.
- **DB users** (`users` table, managed at `/settings/users`): roles `admin | analyst | client`. DB rows are authoritative for their username; env accounts (`DASHBOARD_*`, `CLIENT_*`) remain break-glass bootstrap. Role change/deactivation/deletion revoke live sessions immediately.
- Role gates (auth/dependencies.py): `require_html_auth`, `require_api_auth`, `require_admin_auth/html`, `require_analyst_auth/html`, `require_agent_key`, `require_client_key` (portal).
- CSRF: Origin/Referer-based (`verify_json_csrf` / `verify_form_csrf`).

### Audit Trail

`services/audit_service.py` is the single write path (`record_audit_event`): ~25 action types across auth, alerts, SOAR, agents, AI triage, config, notifications, users, clients, detection toggles, retention. Every event carries `source_ip`. Secret scrubbing on write AND read: detail keys containing `key/token/secret/password/…` word-segments become `__SENSITIVE__`. UI at `/audit` (admin) with filters, detail drawer, CSV export. Records are append-only — never add write endpoints to the audit surface.

### Agent Registration Flow

1. Create an `AgentRecord` with a one-time registration token via `/agents/deploy` (admin)
2. Install with `curl http://<server>/install.sh | bash -- --token <token>`
3. Agent POSTs `X-Agent-Token` to `/api/agents/register` → server validates SHA-256 hash, returns permanent `agent_key`
4. Subsequent requests use `X-Agent-Key`; token nulled after first use. Agents heartbeat every 60s, send metrics every 5s, and poll `/api/agent/rules` every 5 min (currently returns `[]`).

### Database (PostgreSQL)

SQLAlchemy models in `api/app/models.py`. Tables: `logs`, `metrics`, `alerts`, `alert_assessments`, `agent_records`, `activity_audit`, `soar_action_executions`, `ai_alert_triages`, `system_health_rules`, `server_sessions`, `users`, `clients`, `notification_channels`, `notification_deliveries`, `detection_rule_overrides`, plus legacy `detection_rules`/`rule_matches`. Startup migrations in `main.py` are raw idempotent SQL (Postgres only) — add new columns/tables there AND to the models.

### HTML Routes (all under the role-aware shell in `templates/base.html`)

| Route | Access | Purpose |
|---|---|---|
| `/dashboard` `/alerts` `/alerts/{id}/investigation` `/agents` `/agents/{id}` `/logs` | all roles | core SOC pages |
| `/agents/deploy` | admin | agent registration wizard (`/agents/new` redirects) |
| `/network` `/soar/history` `/soar/actions` `/ai-triage` `/clients` `/clients/{id}` `/detection/mitre` | admin+analyst | (`/detection/rules` analyst read, admin toggle) |
| `/audit` `/notifications` `/settings` `/settings/users` | admin | (`/rules`, `/soar/settings`, `/system-health-rules` redirect into the new pages) |

JSON APIs live under `/api/…` in routers: `api_metrics`, `soar`, `ai_triage`, `settings`, `system_health_rules`, `audit`, `notifications`, `users`, `clients`, `portal`, `rules` (detection), `agents`, `collector`.

### UI conventions

Design system from `Design/OVS SECOPS_Design/design_handoff_audit_trail/` (`styles.css` = token source of truth; the Audit Trail page is the reference implementation). Tailwind CDN config in `base.html` carries the exact tokens (IBM Plex Sans/Mono, primary `#F05484`, `line`/`elev`/`hover-dark` etc.) — reuse token names, never hardcode hex in templates. Product rules: no fake data unless labelled DEMO, no disabled/dead controls (use the `nav_soon` "Soon" pattern for roadmap items), SOAR is simulation-only and must say so, AI triage is advisory-only.

### Infrastructure Services

Started by `docker-compose-v2`: `siem_api` (:8000), `ovs_portal` (:8100), `siem_db` (Postgres 13, :5432), `opensearch` (:9200), `data-prepper` (:2021), `opensearch-dashboards` (:5601).

## Environment Configuration

`api/.env` is the live config (see `.env.example` at repo root); `portal/.env` configures the portal (see `portal/env.example`). Key variables:

```
DATABASE_URL=postgresql://...
SESSION_SECRET_KEY=...                  # required; validated at startup
DASHBOARD_USERNAME / DASHBOARD_PASSWORD_HASH   # bootstrap admin (bcrypt, base64)
CLIENT_USERNAME / CLIENT_PASSWORD_HASH         # optional bootstrap read-only user
SIEM_SERVER_ADDRESS=<host-IP>           # used to generate agent installer scripts

ENABLE_CORRELATION_ENGINE=true
CORRELATION_WINDOW_SECONDS=10

# Notifications (implemented)
SMTP_HOST= SMTP_PORT=587 SMTP_USER= SMTP_PASSWORD= SMTP_FROM=

# Agent dead-silence monitoring (implemented)
AGENT_SILENCE_THRESHOLD_MINUTES=5
AGENT_SILENCE_SWEEP_SECONDS=60
AGENT_SILENCE_ALERTING_ENABLED=true

# Data retention (implemented; unset = unlimited)
LOG_RETENTION_DAYS=90
METRICS_RETENTION_DAYS=30
RETENTION_SWEEP_SECONDS=3600
RETENTION_ENABLED=true

# AI triage (advisory only)
AI_TRIAGE_ENABLED=true
GEMINI_API_KEY=...
GEMINI_MODEL=gemini-2.5-flash

# Portal (portal/.env)
SOC_API_URL= CLIENT_API_KEY= PORTAL_PASSWORD= PORTAL_SECRET_KEY=
```
