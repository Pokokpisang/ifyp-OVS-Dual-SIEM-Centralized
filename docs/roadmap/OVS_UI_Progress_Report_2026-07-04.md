# OVS UI Redesign — Progress Report (2026-07-04)

Companion to `UI_Implementation_Gap_Audit_2026-07.md` (the plan of record).
Covers everything shipped since the audit was written, what state the system
was in before, what remains, and recommendations.

---

## 1. Shipped so far

| PR | Title | Status |
|----|-------|--------|
| #22 | UI Implementation Gap Audit & Roadmap (the plan itself) | Merged |
| #23 | Phase 1 — shell + routing alignment | Merged |
| #24 | Audit Trail page end-to-end (+ design bundle committed) | Merged |
| #25 | Notification channels, delivery log, alert dispatch | Merged |
| #26 | Agent dead-silence alerting + unified offline threshold | Merged |
| #27 | DB-backed users, roles, `/settings/users` | **Open — awaiting merge** |

Test suite: **325 → 354 passing** (29 new tests). Every PR also carried an
ASGI smoke test exercising the real request path for both admin and client
roles.

---

## 2. Before → After

| Area | Before (audit findings, 2026-07-03) | After (today) |
|---|---|---|
| **Shell / navigation** | 2-group sidebar, no logout button, hardcoded "JD" profile card, dead "Clients" link, fake search box, links shown to every role | 6-group role-aware sidebar (Command/Assets/Detection/Response/Admin/System), real user chip + logout, live unread-alert badge, coming-soon items visibly disabled, admin/analyst items hidden from clients |
| **Routing** | No `/`; `/agents/new`, `/rules` legacy paths; no 404 page | `/` → dashboard; `/agents/deploy`, `/detection/rules` with redirects from old paths; `/alerts/{id}` redirect; typed HTML 404 (JSON preserved for `/api`) |
| **RBAC** | Client role could open SOAR history/settings and health rules; agent creation open to any logged-in user; `analyst` role checked by SOAR-run but effectively unmintable | Server-side gates: network + SOAR history analyst+; settings/health-rules/rules/audit/notifications/users admin-only; agent deploy admin+CSRF; analyst role fully real via DB users |
| **Users** | Two env-var accounts, no user table, no CRUD, passwords unchangeable at runtime | `users` table (bcrypt, roles, active flag, last login), admin CRUD at `/settings/users`, DB-first auth with env break-glass fallback, immediate session revocation on role change/deactivation/deletion, self-lockout + last-admin guards |
| **Audit trail** | Backend recorded 9 action types but nothing read them — no page, no endpoint, no export; config changes unaudited; no source IP | Full `/audit` page per the design handoff (KPIs, filters, drawer, CSV export, skeleton/empty states); `source_ip` on every event; config/notification/user changes audited; secret scrubbing on write **and** read |
| **Notifications** | Nothing — no models, no senders, not even the env vars CLAUDE.md documented | Email + webhook channels with severity gating, threaded failure-isolated dispatch on every alert (detection + metric paths), test-send, delivery log that survives channel deletion, `/notifications` page |
| **Agent monitoring** | Offline threshold hardcoded 5 min in three places; a dead agent produced no alert; `AGENT_SILENCE_THRESHOLD_MINUTES` documented but ignored | Single env-driven threshold; background sweep emits one HIGH alert per silence episode (dedup on `last_seen`), rides the notification pipeline; dashboard "N agents silent" banner |
| **Honesty of data** | "System running stable" banner, hardcoded T1059 coverage card, network flows presented as real | Banner removed; coverage card computes real rule count; network demo sections labelled **DEMO**; dead templates (`templates_old/`, `rule_edit.html`) deleted |
| **Bugs** | Key-rotation expiry written to a phantom attribute; Go agent 404ing on `/api/agent/rules` every 5 min | Both fixed (correct column; minimal rules endpoint) |

---

## 3. What remains

### Phase 2 leftovers (skipped when we jumped to Phase 3 — still owed)
- **Reskins to design fidelity**: Alerts, Investigation, Agents (+deploy/detail), Dashboard, SOAR History, Logs still wear the old layout. They work on real data; they don't yet match the July design's look. Only the Audit Trail had a full design handoff — the other pages need their handoff bundles exported for pixel passes.
- **`/soar/actions` page**: playbook list + pending-approvals tab (backend is ready; the design's sidebar badge "2" = pending count). Includes the `decision_note` column so approvals/rejections carry a reason.
- **`/ai-triage` queue page**: cross-alert triage list endpoint + page (today only per-alert latest exists).
- Loading/error states on the older fetch-driven panels.

### Phase 3 remainder (2 of 5 workstreams left)
- **`/settings` hub**: consolidate SOAR mode + system health rules + retention display into one audited page; redirect `/soar/settings` and `/system-health-rules` into it.
- **Detection rules JSON + enable/disable** (via suppressions) and **`/detection/mitre`** real coverage matrix (aggregate YAML rule `mitre` fields — sparse and honest, not the prototype's random grid).
- *(Now unblocked by #27)* **Alert assignment** — `assigned_to` on `AlertAssessment` pointing at real users.

### Phase 4 — Client/tenant layer (not started; the largest remaining work)
`clients` table → `client_id` on `agent_records` (+ joins to alerts/metrics/logs) → tenant scoping enforced in the service layer → `/clients` admin views → read-only client portal. **Hard gate:** cross-tenant isolation tests must pass before any portal login exists.

### Phase 5 — Polish (not started)
Reports/exports, saved filters, ⌘K search, notification bell dropdown, network flow model (or formal de-scope), accessibility, responsive off-canvas sidebar.

### Audit-doc risk list status (top 10)
Fixed: #2 client over-exposure · #3 analyst ghost role · #4 unaudited config · #5 fake data (labelled) · #6 key-rotation bug · #7 agent-rules 404 · #8 no logout · #9 audit secret redaction.
Open: **#1 tenant isolation** (Phase 4) · **#10 SOAR "SIMULATED" labelling** in the UI (fold into the `/soar/actions` + SOAR History reskin).

---

## 4. Suggestions

1. **Do a visual pass before anything else** — `make up`, log in as admin *and* a client/analyst DB user, click every sidebar item. All automated checks verify structure and data, not pixels. Pay attention to `/audit` and `/notifications` (new pages) and the silent-agent banner.
2. **Wire real SMTP and test-send** — the notification pipeline is verified with mocks; one real `SMTP_HOST` + a test-send click validates the last mile. Same for one real webhook (e.g. a Discord/Slack hook).
3. **Order the remaining work as: SOAR actions page → AI-triage queue → settings hub → rules/MITRE → reskins → Phase 4.** The two skipped Phase-2 pages are small, close the SOAR-labelling risk (#10), and complete the "every design page has a working route" promise before the heavy tenancy work.
4. **Export the remaining design handoffs** (`pages-admin.jsx`, `pages-hero.jsx`, `pages-client.jsx` referenced by the prototype's `index.html`) and commit them like the audit-trail bundle — reskins without them will be approximations.
5. **Tag a release after Phase 3 completes** (suggest `v2.12.0`): migrations for 4 new tables/columns have shipped across 4 PRs; a tagged point with release notes will make rollback reasoning much easier before Phase 4's tenancy migration (the riskiest change in the plan).
6. **Update CLAUDE.md** once Phase 3 closes — the env-var section is now real (SMTP block, silence-monitor vars) and the "sprint target" annotations are stale.
7. **Note for scaling later**: notification dispatch and the silence sweeper run per-process (threads + asyncio task). Fine for the current single-worker deployment; revisit both (move to a queue or leader election) before running multiple uvicorn/gunicorn workers.
8. **Snyk**: MCP auth doesn't work headless in this environment; the repo's `security/snyk` PR check is covering scans. If you want local scans, run `snyk auth` interactively once.
