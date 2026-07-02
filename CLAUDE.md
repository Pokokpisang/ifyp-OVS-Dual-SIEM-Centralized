# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

**OVS — Server Security Platform for Hosting Operators and MSPs.**

This project has transitioned from an FYP SIEM prototype into a real industry product direction targeting VPS/server operators, small MSPs, and hosting providers. All development decisions should be made with this audience and goal in mind.

The system consists of three main components:

1. **FastAPI backend** (`api/`) — log ingestion, rule evaluation, alerting, web dashboard, SOAR simulation, AI triage
2. **Go agent** (`agent/`) — lightweight single-binary endpoint collector; tails logs, sends telemetry, offline-buffered
3. **OpenSearch pipeline** — Data Prepper receives forwarded logs for search/analytics (low priority until log volume justifies it)

**Current product stage:** Foundation hardening phase. Priority is operational correctness (migrations, notifications, TLS, retention) before feature expansion. See `docs/strategy/OVS_Strategic_Product_Analysis_May2026.md` and `docs/strategy/OVS_Sprint_Board_2Week.md` for the active roadmap.

## Commands

### Start/Stop the Full System

```bash
make up        # builds Go agent, starts Docker services (API, DB, OpenSearch, Data Prepper), runs agent as background sudo process
make down      # stops Docker services and kills agent
make restart   # down then up
make logs      # tail docker-compose service logs
```

The `docker-compose-v2` binary (committed to repo root) is used instead of the system `docker compose` command.

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

### Run Python Tests

Tests live in `api/app/detection/tests/`. Run from the `api/` directory with the virtualenv active:

```bash
cd api
source .venv/bin/activate
python -m pytest app/detection/tests/ -v

# Run a single test file:
python -m pytest app/detection/tests/test_yaml_detection_engine.py -v

# Run a single test:
python -m pytest app/detection/tests/test_yaml_detection_engine.py::test_t1059_match_returns_candidate -v
```

## Architecture

### Detection Pipeline (v2.8.0)

The active detection path: `POST /ingest/log` → `collector.py` → background task → `RuleEngine.evaluate_raw()` → `ActiveDetectionRunner` → `YAMLDetectionEngine` + `CorrelationEngine` → `models.Alert`.

**Detection engine mode:** the engine is YAML-only. `RuleEngine` delegates
unconditionally to `ActiveDetectionRunner` (YAML rules + correlation + SSH
brute-force). The legacy `DETECTION_ENGINE_MODE` env var (`YAML`/`SHADOW`/`LEGACY`)
is retained for backward compatibility but is **intentionally ignored** — there
is no separate legacy or shadow path anymore.

**Key detection engine files:**
- `api/app/detection/engine/detection_engine.py` — `RuleEngine` thin wrapper; always delegates to `ActiveDetectionRunner`
- `api/app/detection/engine/active_runner.py` — `ActiveDetectionRunner`: calls `YAMLDetectionEngine`, then optionally `CorrelationEngine`
- `api/app/detection/engine/yaml_detection_engine.py` — `YAMLDetectionEngine`: load rules → evaluate → score risk → check suppressions → return `DetectionCandidate`
- `api/app/detection/engine/correlation_engine.py` — `CorrelationEngine`: in-memory rolling buffer detecting "curl/wget → bash" two-event patterns (T1059.004)
- `api/app/detection/engine/audit_parser.py` — `AuditdParser`: normalises raw auditd log lines into ECS-compatible dicts before rule evaluation
- `api/app/detection/engine/rule_loader.py` — loads YAML rule files recursively from `detection/rules/`
- `api/app/detection/engine/rule_evaluator.py` — field-based condition matching (`in`, `contains_any`, `not_contains_any`, `exists`, etc.)
- `api/app/detection/engine/risk_scoring.py` — base score + adjustments from rule's `risk_adjustment` block
- `api/app/detection/engine/suppressions.py` — loads `detection/tuning/*.yaml` and suppresses false positives

### Detection-as-Code Rules

YAML rules live under `api/app/detection/rules/` (organised by `platform/tactic/technique/`). Active rules:

- `linux/execution/t1059/linux_t1059_shell_network_tool.yaml` — T1059.004: shell + network tool + pipe-to-shell pattern
- `linux/credential-access/t1110/` — T1110: SSH brute force (sprint target — in progress)
- `linux/persistence/t1053/` — T1053: cron/systemd persistence by unexpected process (sprint target — in progress)
- `linux/defense-evasion/t1078/` — T1078: sudo by unexpected user (sprint target — in progress)

Rule schema: `api/app/detection/schemas/rule_schema.py` (`DetectionRule` Pydantic model). Key fields: `condition`, `risk_adjustment`, `mitre`, `required_fields`.

Suppression tuning files: `api/app/detection/tuning/` — `global_suppressions.yaml`, `linux_suppressions.yaml`, `rule_exceptions.yaml`.

When adding new rules: always add a fixture test (true-positive + false-positive) under `api/app/detection/tests/`.

### Correlation Engine

Handles fragmented auditd events where `curl http://... | bash` appears as two separate EXECVE records. Uses a singleton in-memory `ProcessEventBuffer` (per-agent rolling deque) and `DedupCache`. The engine is order-insensitive: Event A (download tool) or Event B (shell) can arrive first. Controlled by env vars: `ENABLE_CORRELATION_ENGINE`, `CORRELATION_WINDOW_SECONDS` (default 10), `CORRELATION_BUFFER_TTL_SECONDS` (default 60), `CORRELATION_DEDUP_SECONDS` (default 60). **Known limitation:** buffer is in-process only — data is lost on restart and not shared across multiple API workers.

### Go Agent Internals

Entry point: `agent/cmd/agent/main.go`. Config priority: YAML file (`-config` flag) → env vars (`AGENT_SERVER_URL`, `AGENT_NAME`, `AGENT_KEY`, `AGENT_LOG_PATH`).

- `internal/tailer` — wraps `hpcloud/tail` to follow log files in real time
- `internal/collector` — gathers CPU/RAM/network metrics via `gopsutil`
- `internal/sender` — HTTP client; sends `X-Agent-Key` header; falls back to `internal/queue` (JSONL file) when offline
- `internal/rules` — polls `/api/agent/rules` every 5 min for client-side rule matching
- `internal/queue` — file-backed `agent_queue.jsonl` for offline buffering

Agent sends heartbeats every 60s and metrics every 5s. Logs filtered to avoid circular ingestion (agent's own syslog lines are dropped).

### Agent Registration Flow

1. Create an `AgentRecord` with a one-time registration token via the dashboard
2. Install the agent with `curl http://<server>/install.sh | bash -- --token <token>`
3. Agent POSTs `X-Agent-Token` to `/api/agents/register` → server validates SHA-256 hash, returns permanent `agent_key`
4. Subsequent requests use `X-Agent-Key`; token is nulled in DB after first use

### Database (PostgreSQL)

SQLAlchemy models in `api/app/models.py`. Key tables: `logs`, `metrics`, `alerts`, `detection_rules` (legacy JSON-logic rules), `rule_matches`, `agent_records`, `system_health_rules`, `alert_assessments`.

`Alert` rows include `detection_engine` (`YAML`, `CorrelationEngine`, `LEGACY`, `MetricEngine`), `risk_score`, `mitre_tactic`, `mitre_technique`, and `detection_metadata` (JSON blob with match reasons).

### API Routers

| Router | Prefix | Purpose |
|---|---|---|
| `collector.py` | `/ingest/log` | Receives agent telemetry, runs detection in background |
| `dashboard.py` | `/dashboard`, `/logs`, `/alerts` | HTML dashboard views |
| `api_metrics.py` | `/api/metrics` | Metrics ingestion and health alerts |
| `rules.py` | `/rules` | CRUD for legacy DB-backed `DetectionRule` rows |
| `agents.py` | `/api/agents`, `/install.sh` | Agent registration, heartbeat, installer generation |
| `system_health_rules.py` | `/api/system-health-rules` | CRUD for metric threshold rules |
| `auth.py` | `/login`, `/logout` | Session-based dashboard authentication |
| `soar.py` | `/api/soar` | SOAR playbook matching, simulation, history, approval |
| `ai_triage.py` | `/api/triage` | AI triage trigger and result retrieval (advisory only) |
| `settings.py` | `/api/settings` | Platform settings (notification channels — sprint target) |

### Infrastructure Services

Started by `docker-compose-v2`:
- `siem_api` — FastAPI on port 8000
- `siem_db` — PostgreSQL 13 on port 5432 (`user/password/siemdb`)
- `opensearch` — OpenSearch 2.11 on port 9200
- `data-prepper` — OpenSearch Data Prepper on port 2021 (receives forwarded logs)
- `opensearch-dashboards` — port 5601

## Environment Configuration

`api/.env` is the live config file (not committed by default — see `.env.example` at repo root). Key variables:

```
DATABASE_URL=postgresql://...
DETECTION_ENGINE_MODE=YAML              # legacy/no-op — engine is YAML-only
ENABLE_CORRELATION_ENGINE=true
CORRELATION_WINDOW_SECONDS=10
SIEM_SERVER_ADDRESS=<host-IP>           # Used to generate agent installer scripts

# Notification system (sprint target)
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USER=alerts@example.com
SMTP_PASSWORD=...
SMTP_FROM=alerts@example.com

# Retention / cleanup (sprint target)
LOG_RETENTION_DAYS=90
METRICS_RETENTION_DAYS=30

# Agent monitoring (sprint target)
AGENT_SILENCE_THRESHOLD_MINUTES=10
```
