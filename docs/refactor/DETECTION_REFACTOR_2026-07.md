# Detection Subsystem Refactor, Hardening & Product-Quality Pass — Change Log (July 2026)

**Branch:** `Development` (not yet merged to `main`)
**Baseline commit:** `b5de893` (v2.8.0-rc1) → **HEAD:** `c0d07b0`
**Scope:** 24 commits, 87 files, +4,639 / −819 lines
**Tests:** 174 → **310 passing** (detection + app suites), 0 failures
**Proposed release tag:** `v2.9.0 — Detection Subsystem Refactor & Hardening`

This document records everything **added, improved, removed, and fixed** across the
whole pass, plus a **manual pre-release checklist** (Section 9) to run before merging
`Development` → `main` and tagging. Unless explicitly noted, nothing changed public
route paths, DB models/schema, env var names, or the frontend contract.

The work came in two phases:
- **Phase A — Refactor & hardening** (service layer, bug fixes, T1543/T1110/T1059
  robustness, safety nets).
- **Phase B — Follow-up roadmap items #2–#7** (investigation read-only + SOAR dedup,
  YAML-driven engine metadata, centralized audit trail, two new detections, dashboard
  service extraction).

---

## 1. TL;DR

- A real **service layer** now owns business logic: `alert_service`, `metric_service`,
  `investigation_service`, `audit_service`, `dashboard_service` — routers and engines
  no longer duplicate alert-creation, agent-auth, health-rule, investigation, audit, or
  dashboard-assembly logic.
- **Four latent detection bugs fixed** (dead parent-name, broken T1110 adjustment, stale
  rule-exception, SOAR dedup guard) plus a `RuleLoader.errors` accumulation bug.
- **Detection library grew** from 3 techniques to 5: T1059, T1110, T1543 hardened; **T1053.003
  (cron)** and **T1078.003 (service-account login)** added — all detection-as-code YAML.
- **Correlation & SSH-brute-force engine metadata** moved to YAML (`engine_meta/`).
- **Centralized audit trail** records analyst/operator actions (SOAR, auth, alert status,
  agent registration/key rotation, AI-triage) with secret-safe details.
- **Safety nets:** rule-schema validation at load, mtime rule caching, fixture-based
  regression tests.

---

## 2. Bugs fixed

| # | Bug | Impact before | Fix |
|---|-----|---------------|-----|
| 1 | `AuditdParser` never populated `process.parent.name` (only `ppid`) | All 3 tuning suppressions and the T1059 parent-based ±20 risk adjustments were **dead no-ops** | Best-effort parent-name resolution via `process_cache.py`; suppressions also match normalized build commands |
| 2 | T1110 `risk_adjustment` used unsupported `conditions:`/`increase_by:` | Adjustment **silently ignored** | Replaced with a valid `+5 privileged account` block; schema validator now rejects the bad shape at load |
| 3 | `rule_exceptions.yaml` targeted the **disabled** sample rule id | Exception could never apply to the live rule | Retargeted to `linux_t1059_shell_network_tool` |
| 4 | SOAR auto-run dedup guard filtered `status="success"` but rows are written `status="executed"` | Guard never matched → **duplicate SOARActionExecution rows** on repeated auto-runs (automatic mode) | Guard now matches `("executed","success")` — auto-run is idempotent |

Also fixed: **`RuleLoader.errors` accumulation** (never reset between loads → duplicated
errors) — now rebuilt per call.

---

## 3. Added

### Service layer (`api/app/services/`)
- **`alert_service.py`** — single `create_alert(db, AlertSpec, *, trigger_soar, commit)`; the **only** place alerts are persisted. Owns dedup, metadata JSON-encoding, SOAR trigger. Plus `get_actor_username(request)`.
- **`metric_service.py`** — `evaluate_health_rules(...)` + `compute_metrics_summary(...)` (out of the metrics router).
- **`investigation_service.py`** — `get_investigation_data(db, alert_id)` + read-only helpers (out of `api_metrics.py`, ~190 lines). **Now strictly read-only** (see §4).
- **`audit_service.py`** — `record_audit_event(...)` + `list_audit_events(...)`; appends to the existing `ActivityAudit` table; secret-safe details; `commit` flag for atomic writes.
- **`dashboard_service.py`** — `build_agents_view`, `build_soar_history_view`, `build_network_view`, `build_agents_history_view` (out of `dashboard.py`).

### Detection-engine modules (`api/app/detection/engine/`)
- **`normalization.py`** — `process.normalized_command` (whitespace-collapsed, null-stripped) for match robustness; raw `command_line` preserved as evidence.
- **`process_cache.py`** — thread-safe TTL `(agent_id, pid) → name` for best-effort parent-name resolution.
- **`engine_metadata.py`** + **`engine_meta/*.yaml`** — correlation & SSH-BF alert metadata (id, name, MITRE, base risk, severity) sourced from YAML instead of Python dataclass defaults.

### Evaluator operators (`rule_evaluator.py`)
`contains_all`, `gte`, `lte` (fail-closed), `list_intersects`, `not_exists`.

### Auth dependency (`auth/dependencies.py`)
`require_agent_key` — shared `X-Agent-Key` auth for agent-facing routes. (`require_analyst_auth` added earlier for `/soar/run`.)

### New detection rules (detection-as-code YAML)
- **T1053.003 — Cron persistence** (`linux_t1053_003_cron_persistence.yaml`): writes to cron dirs + write-style action + (suspicious cron-write/tee command OR shell process). Reuses the package-manager suppression.
- **T1078.003 — Service-account login** (`linux_t1078_003_service_account_login.yaml`): successful SSH login by a service/daemon account; +15 external source; ships a rule-scoped **trusted-source allowlist** suppression (`allow_high_risk: true`, placeholder doc IP for operators to populate).

### Enhanced detection capabilities
- **T1110:** DB-backed failure counting over `models.Log` (restart-surviving; buffer fallback) + **password-spray escalation** (`SSH_BF_SPRAY_USER_THRESHOLD`, +10).
- **T1059:** base64 decode-and-run (+10), `chmod +x` drop-and-run via `contains_all` (+15), `/var/tmp` execution (+10); web-server-parent +20 now **live**.
- **T1543:** `benign_package_manager_service_write` suppression (dpkg/apt/rpm/yum/dnf/pacman/snapd), fail-safe.

### Centralized audit trail (`audit_service` + wiring)
Actions recorded (all secret-safe): `SOAR_RUN`, `SOAR_APPROVE`, `SOAR_REJECT`,
`ALERT_STATUS_CHANGED`, `LOGIN_SUCCESS`, `LOGIN_FAILURE`, `LOGOUT`, `AGENT_REGISTERED`,
`AGENT_KEY_ROTATED`, `AI_TRIAGE_REQUESTED`. No passwords/tokens/keys/prompts stored.

### Safety nets
- **Rule schema validation** (`rule_schema.py`) — `model_validator` walkers reject bad operators/conditions/adjustments at load; invalid rules soft-fail.
- **Rule caching** (`rule_loader.py`) — parsed rules cached by file mtime.
- **Fixture-based regression** (`test_fixture_regression.py` + `fixtures/`) — pins `(rule_id, matched, suppressed, score band)` per scenario across T1059/T1110/T1543/T1053/T1078.

### Tests
16 new test files; suite grew 174 → **310**. Coverage for every new service, engine
module, operator, rule, and the audit wiring (incl. no-secret assertions).

---

## 4. Improved / changed

| Area | Before | After |
|------|--------|-------|
| Alert creation | 4 near-identical `models.Alert(...)` blocks | All flow through `alert_service.create_alert` |
| Agent auth | Hand-rolled in `collector.py` + `api_metrics.py` | Shared `require_agent_key` dependency |
| `ingest_metric` | Embedded health-rule engine inline | Delegates to `metric_service` |
| `get_investigation_data` | ~190 lines inline + **SOAR write side effect on GET** | Thin delegator to `investigation_service`; **read-only** (SOAR trigger removed — already fires at alert creation) |
| Dashboard views (4 heavy) | DB queries + assembly inline in handlers | Delegate to `dashboard_service` |
| Correlation / SSH-BF metadata | Hardcoded Python dataclass defaults | YAML-driven (`engine_meta/`) |
| T1059 / T1543 rules | Matched raw `command_line` (whitespace-evadable) | Match `process.normalized_command` |
| Rule loading | Disk read + parse every event | mtime-cached |
| SOAR investigation playbooks | auto-run enabled | Approval-gated (`requires_approval: true`) |
| Correlation engine | Scheme URLs only | Also bare-IP URLs (`1.2.3.4:8080/x.sh`) |

### Behavior changes to verify after deploy
- **`POST /api/metrics` missing `X-Agent-Key` now returns `401`** (was `422`).
- **Parent-name enrichment activates previously-dormant suppressions & adjustments** — some events score differently by design (build-parent −20, web-server-parent +20). High/critical suppression guard still holds.
- **Investigation page load no longer triggers SOAR** — SOAR fires once at alert creation; opening an alert is now a pure read (no duplicate SOAR rows on refresh).

---

## 5. Removed
- `services/audit_parser.py` (dead re-export stub).
- Hand-rolled agent-key auth blocks in `collector.py` / `api_metrics.py`.
- The `make test-t1059` Makefile target (non-assertive manual demo depending on a hardcoded key; pytest covers the logic).
- Stale shadow-mode / `DETECTION_ENGINE_MODE` docs; various unused imports.

---

## 6. Detection library at a glance (post-pass)

| Technique | Rule / engine | Signal |
|-----------|---------------|--------|
| T1059.004 | `linux_t1059_shell_network_tool.yaml` + correlation engine | shell + network tool + pipe-to-shell; download→shell correlation |
| T1110 | `linux_t1110_ssh_bruteforce.yaml` + `SSHBruteForceEngine` | failed SSH auth; DB-backed threshold + spray |
| T1543.002 | `linux_t1543_002_systemd_service_persistence.yaml` | suspicious systemd unit write |
| T1053.003 | `linux_t1053_003_cron_persistence.yaml` | suspicious cron file write |
| T1078.003 | `linux_t1078_003_service_account_login.yaml` | service-account SSH login (+ trusted-IP allowlist) |

---

## 7. Resolved since the first draft of this doc
- ✅ Investigation GET side effect (now read-only) + SOAR dedup bug (#4 above).
- ✅ Correlation/SSH-BF metadata YAML-driven.
- ✅ `audit_service` built and wired.
- ✅ `dashboard.py` heavy views extracted.
- ✅ T1053 and T1078 detections added.

## 8. Open follow-ups (post-release backlog)
1. **Sudo detection needs an `audit_parser.py` sudo branch** (parse invoking user + `COMMAND=`, stop hard-coding `service=ssh`). Prerequisite for **T1078 v2 / a T1548 rule**. The same change fixes a known FN: the parser's `\w+` user regex truncates hyphenated accounts (`www-data`→`www`) from raw syslog.
2. **Audit-trail read route / UI** — `list_audit_events` exists; no page/endpoint surfaces it yet.
3. **In-process state** — `process_cache`, correlation buffer, SSH-BF dedup are per-worker/lost on restart (T1110 counting is DB-backed). Redis-backed shared state only if multi-worker deployment is adopted.
4. **Hardcoded localhost agent key** still in the Makefile `up` target — move to env/`.env`.
5. Agent heartbeat / key-use audit events (deliberately skipped — high volume).

---

## 9. Manual pre-release checklist & guidance (for #1: merge → validate → tag)

> All code items are done and unit-tested; this is the operational gate before merging
> `Development` → `main` and tagging `v2.9.0`. Work top to bottom. **The merge and tag are
> operator actions — do not automate them without review.**

### 9.1 Automated gate (must pass)
- [ ] `cd api && source .venv/bin/activate`
- [ ] `python -m pytest app/detection/tests/ app/tests/ -q` → **310 passed**, 0 failures.
- [ ] Rule/tuning lint is green (covered by `test_rule_schema_validation.py::test_all_shipped_rules_load_without_errors`).
- [ ] `git status` clean on `Development`; review `git log --oneline b5de893..HEAD` (24 commits).
- [ ] (Optional but recommended) run `/code-review ultra` on the branch before merge.

### 9.2 Bring the stack up
- [ ] `make up` (from repo root; needs Docker + sudo for the agent). Confirm `siem_api`, `siem_db`, `opensearch`, `data-prepper` are healthy.
- [ ] API responds: `curl -s -o /dev/null -w "%{http_code}" http://localhost:8000/login` → `200`.

### 9.3 Manual functional smoke test (walk the UI)
Log in, then verify each page renders and the refactors behave:
- [ ] **Login/logout** — wrong password shows error + 401; correct login redirects to `/dashboard`. (Both now also write `LOGIN_SUCCESS`/`LOGIN_FAILURE`/`LOGOUT` audit rows.)
- [ ] **/dashboard** — host dropdown + widgets load.
- [ ] **/agents** — registered + metric-only hosts merged; status chips (active / HIGH LOAD / offline); summary counts and pagination correct. *(dashboard_service extraction)*
- [ ] **/agents/history** — lifecycle list + cpu/ram, pagination.
- [ ] **/network** — agent rows + net stats + alert chips.
- [ ] **/alerts** and **/logs** — filters + pagination.
- [ ] **Alert investigation** (`/alerts/{id}/investigation`) — timeline, correlated events, endpoint health, source intel render. **Refresh the page a few times and confirm the SOAR timeline does NOT gain duplicate rows** (investigation GET is now read-only).
- [ ] **/soar/history** — summary counts (executed = executed+success), filters, distinct options.
- [ ] Change an alert's assessment status → confirm it persists and an `ALERT_STATUS_CHANGED` audit row is written.

### 9.4 Detection sanity (optional, if you exercise ingestion)
Send synthetic events to `POST /ingest/log` (with a **registered** agent key) or via the agent, and confirm alerts appear:
- [ ] T1059 curl→bash correlation → correlation/T1059 alert.
- [ ] T1053 cron write (`bash -c "… > /etc/cron.d/x"`) → T1053.003 alert.
- [ ] T1078 successful SSH login as a service account (e.g. `postgres`) → T1078.003 alert (external source scores 80).
- [ ] A package-manager cron/service write is **suppressed** (no alert).
- [ ] `POST /api/metrics` **without** `X-Agent-Key` returns **401** (behavior change).

### 9.5 Security spot-checks
- [ ] Inspect a few `activity_audit` rows (`SELECT actor, action, details FROM activity_audit ORDER BY id DESC LIMIT 20;`) — confirm **no** passwords, tokens, keys, or AI prompts appear in `details`.
- [ ] Confirm the hardcoded agent key in the Makefile `up` target is acceptable for your environment (follow-up #4) — it is a localhost dev key.

### 9.6 Merge, tag, and record
- [ ] Merge: `git checkout main && git merge --no-ff Development` (or open a PR `Development → main` and merge after review). Prefer `--no-ff` to keep the batch as one merge commit.
- [ ] Re-run the automated gate on `main` (§9.1).
- [ ] Tag: `git tag -a v2.9.0 -m "Detection Subsystem Refactor & Hardening"` then `git push origin main --tags`.
- [ ] Update `CLAUDE.md` "Current product stage" if the roadmap advanced.

### 9.7 Rollback guidance
- Every step is an isolated commit; to revert a single change use `git revert <sha>` (e.g. the 422→401 auth change `a940d62`, or parent-name enrichment `a364267` if it over-suppresses).
- No DB schema/migrations changed in this pass, so rollback is code-only — redeploying the previous image/commit is sufficient; existing `alerts` / `activity_audit` rows remain readable.
- The `activity_audit` table is created by `Base.metadata` (already present); no migration to undo.

---

## 10. Commit reference (baseline `b5de893` → `c0d07b0`)

```
c0d07b0 refactor(dashboard): extract heavy view logic into dashboard_service
d4d1b04 feat(detection): add T1078.003 service-account login rule + allowlist + tests
001dace feat(detection): add T1053.003 cron persistence rule + tests
5b8aeea chore: remove manual make test-t1059 smoke target
b228e75 feat(audit): centralized audit_service + wire SOAR/auth/alert/agent/triage
26a0f28 refactor(detection): YAML-drive correlation + SSH-BF engine metadata
1bf1f94 fix(soar): make investigation GET read-only + idempotent auto-run dedup
1553437 refactor(investigation): extract get_investigation_data into investigation_service
84e3c4c test(detection): fixture-based end-to-end regression net
3ca55e2 feat(detection): T1543 pkg-mgr suppression, T1059 indicators, normalized matching
a66b42d feat(t1110): DB-backed failure window + password-spray escalation
8da0e74 feat(schema): validate condition tree and risk_adjustment shape at load time
538c991 fix(t1110): repair non-functional risk_adjustment in ssh_bruteforce rule
a364267 feat(detection): resolve process.parent.name and harden build suppressions
24054c2 feat(detection): add process.normalized_command for whitespace-robust matching
20cd147 feat(detection): add contains_all, gte, lte, list_intersects, not_exists operators
e716244 perf(detection): cache parsed YAML rules by mtime in RuleLoader
28c6490 refactor(metrics): extract health-rule evaluation into services/metric_service
1e56db1 refactor(alerts): centralize alert creation in services/alert_service
a940d62 refactor(auth): centralize agent-key auth in require_agent_key dependency
ca18f62 chore(cleanup): remove dead stub, unused imports; fix stale shadow-mode docs
3026029 chore(demo,ui): correlation-based test-t1059 target, All Hosts filter, dashboard refresh
3e19e7e feat(detection,rbac): analyst SOAR role, approval-gated notes, bare-IP correlation, host filters
4402b40 detection: correlation engine accepts bare-IP URLs; rework test-t1059 e2e harness
```
