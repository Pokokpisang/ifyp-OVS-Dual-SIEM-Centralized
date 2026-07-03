# Handoff: Audit Trail (OVS SECOPS)

## Overview
A read-only **Audit Trail** page for the OVS security-monitoring platform (a SOC/MSSP product for Linux servers). It lets SOC analysts, admins, and compliance reviewers answer: *who did what, when, to which object, what changed, and was it security-sensitive?* It sits at **System → Audit Trail** in the app, alongside Settings.

## About the Design Files
The files in this bundle are **design references created in HTML/React (via in-browser Babel)** — a working prototype showing intended look and behavior. **They are not production code to ship directly.** The task is to **recreate this page inside the target codebase using its existing environment, components, and patterns** (React/Vue/etc.). If OVS already has a component library (buttons, badges, tables, drawers, KPI cards), reuse it — the prototype deliberately mirrors the rest of the OVS app, so equivalent components almost certainly already exist.

## Fidelity
**High-fidelity.** Final colors, typography, spacing, badge semantics, states, and interactions are all specified below and in the source files. Recreate the UI faithfully using the codebase's existing design system.

## Screens / Views

### 1. Audit Trail — main page
- **Purpose**: Scan and investigate platform activity; open any event for full detail.
- **Layout**: Standard app shell (232px sidebar + main column with a 56px sticky topbar). Page content is a vertical flex stack, `padding: 18px 24px 60px`, `max-width: 1680px`, `gap: var(--gap-2)` (10px compact). Stack order:
  1. **Page header** — flex row, space-between, `align-items: end`. Left: `h1` "Audit Trail" (19px/600), sub-line (13px muted). Right: a `READ-ONLY` pill (mono, 10px, bordered) + `Export` button.
  2. **Summary cards** — a single `.kpi-row` (one bordered surface card, `padding: 14px 18px`) split into **6 equal KPI cells** divided by 1px vertical rules. Each cell: mono uppercase label (11px, `letter-spacing: 0.12em`) prefixed by a 13px category-tinted icon; value (21px/600, tinted); footer trend text ("Last 24h" / "Last 7 days", dim).
     - Total Events `1,284` (primary pink) · Failed Logins `23` (crit red) · SOAR Actions `47` (info blue) · Agent Changes `9` (accent orange) · Alert Status Changes `61` (purple) · AI Triage Requests `138` (cyan).
  3. **Filter bar row 1** (`.filters` — bordered elev surface, flex wrap, `gap: 8px`, `padding: 10px 12px`): search input (280px, with search icon) + `ACTION` label + 7 chips: All / Authentication / SOAR / Alert / Agent / AI Triage / System.
  4. **Filter bar row 2** (`.filters`): labeled selects — DATE RANGE (Last 24 hours / 7 days / 30 days / Custom), ACTOR (All + distinct actors), OBJECT TYPE (all / alert / agent / soar_execution / auth / ai_triage / system), OBJECT ID (84px mono text input), spacer, `Reset` and `Apply filters` (primary) buttons.
  5. **Read-only note** — subtle full-width line, shield icon + dim 11.5px text: "Audit events are read-only and cannot be modified from this page. Records are retained per your workspace retention policy."
  6. **Table card** (`.card`, `padding: 0`, `overflow: hidden`) containing the audit table + footer pagination.
- **Table columns** (fixed widths): Time (156) · Actor (168) · Action (220) · Object (150) · Result (116) · Details (84). Sticky `thead` (mono 10.5px uppercase labels, `background: --bg-elev`). Rows: 36px (compact) / 46px (comfortable), 1px bottom border, hover → `--bg-hover`, `cursor: pointer`, a left 2px primary accent bar appears on the first cell on hover (`.row-link:hover td:first-child`).
  - **Time**: mono dim, `white-space: nowrap`, full timestamp `2026-07-03 10:21:44`.
  - **Actor**: status dot (green for humans, amber `silent` for `system:*`) + name (500; mono if a system actor) with a dim 10.5px role beneath.
  - **Action**: colored **action badge** (see Badges) + a small amber key icon if the event is security-sensitive.
  - **Object**: mono `type:id` — type dim, colon dim, id normal — or just dim type when no id.
  - **Result**: small **result badge** (see Badges).
  - **Details**: a primary-colored "View ›" affordance (whole row is also clickable). Opens the detail drawer.
- **Pagination footer** (inside card, top border, `padding: 10px 12px`, space-between): left = mono "Showing 1–12 of N records"; right = Prev / numbered page buttons (active = primary) / Next. 12 rows per page.

### 2. Audit Event Detail — right drawer
- **Purpose**: Full, defensible detail for one event, with safe handling of sensitive values and links to related context.
- **Layout**: Right-anchored drawer, `width: min(640px, 100vw)`, slides in from the right over a 50%-black backdrop; header (border-bottom) + scrollable body (`padding: 20px 22px`).
  - **Header**: dim mono "Audit Event · ev-10238"; a row of badges (action badge + result badge + a `Sensitive` badge when applicable); title "Audit Event Details" (17px/600); ✕ close button.
  - **Field list** (each row: 96px mono uppercase label + value, 1px bottom border, `padding: 9px 0`): Time (mono) · Actor (dot + name + dim role) · Action (badge) · Object Type (mono) · Object ID (mono or —) · Result (badge) · Source (mono IP or `system`).
  - **Details** section: bordered container, zebra-striped rows in a `130px 1fr` grid — mono dim key + mono value. Any value that is a secret renders as a **"Sensitive value hidden"** chip (mono, dashed border, key icon) — never the real value.
  - **Related** section: secondary buttons (`.btn`, link icon) — e.g. Open Alert Investigation, Open SOAR History, Open Agent, Open AI Triage Result, Open Settings, Open Login Context. Clicking navigates to that route (Login Context has no route → shows a toast).
  - **Footer note**: shield icon + dim text: "This record is read-only. Sensitive values (keys, tokens, secrets) are never stored or displayed."

### 3. Loading state
On mount and on **Apply filters**, the table body shows ~8 skeleton rows (`.skel` shimmer bars) for ~480ms.

### 4. Empty & no-result states
- **No-result** (filters active, 0 matches): centered `.empty` block — search icon, "No matching audit activity", "No records match the current filters.", and a **Clear filters** button.
- **Empty** (no filters, 0 records): file icon, "No audit events found", "Try adjusting the filters or selecting a wider date range."

## Interactions & Behavior
- **Filtering is live** (updates on every change); `Apply filters` re-runs with a brief loading shimmer and a toast; `Reset` clears all filters. Changing any filter resets to page 1.
- Filter logic: category (exact match on `category`), actor (exact), object type (exact), object ID (substring of `objId`), search (case-insensitive substring across actor/action/objType/objId/result/all detail key-values). *Date range is presentational in the prototype — wire it to your query layer.*
- **Row click** or **View** opens the drawer for that event. Drawer closes on ✕ or backdrop click.
- **Related links** call the app router (`onNav(routeId)`) and close the drawer; the auth "Login Context" link has no destination and fires a toast instead.
- **No mutation affordances** anywhere — no edit/delete/inline-edit. Export (CSV) is the only outbound action. This is intentional: the page must read as tamper-evident.
- **Animations**: drawer slide-in `0.22s cubic-bezier(0.2,0.8,0.2,1)`, backdrop fade `0.18s`; skeleton shimmer `1.4s linear infinite`.
- **Responsive**: sidebar collapses to an off-canvas drawer < 1024px; `.filters` and `.kpi-row` wrap; the table scrolls horizontally inside its card (`min-width: 640px`).

## State Management
Local component state (prototype uses React `useState`; map to your framework):
- `category` (default `'All'`), `actor` (`'all'`), `objType` (`'all'`), `objId` (`''`), `query` (`''`), `range` (`'24h'`) — filter inputs.
- `page` (1) — current page; reset to 1 via effect when any filter changes.
- `loading` (starts `true`) — drives skeleton; set true→false on mount and on Apply (~480ms timer).
- `openEvent` (`null` | event) — the event shown in the drawer.
- Derived: `filtered` (memoized filter of the source list), `pageCount`, `pageRows` (12-row slice), `hasFilters`.
- **Data fetching (production)**: replace the static `AUDIT_EVENTS` array with a paginated, server-filtered query. Audit records are append-only/read-only — do not expose write endpoints from this view. Never send real secret values to the client; the API should already redact them (the UI shows the "Sensitive value hidden" chip whenever a value is absent/redacted).

## Design Tokens
Dark theme (`:root[data-theme="dark"]`, from `styles.css`):
- **Backgrounds**: `--bg #18161a` · `--bg-elev #1d1b20` · `--bg-elev-2 #232128` · `--bg-hover #26232b` · `--surface #1f1d22`.
- **Borders**: `--border #2a2730` · `--border-strong #3a3640`.
- **Text**: `--text #ededed` · `--text-muted #a09da6` · `--text-dim #6f6c75`.
- **Brand/semantic**: `--primary #F05484` · `--accent #f59b00` · `--ok #3ecf8e` · `--info #5b9eff` · `--crit #ff4d6d` · `--high #f59b00` · `--med #f0c04a` · `--low #5b9eff`. Each has a matching `*-soft` (~14% alpha) fill.
- **Extended action tints** (defined in `pages-audit.jsx`, matched chroma/lightness): purple `oklch(0.72 0.12 305)` (alert changes), teal `oklch(0.74 0.10 178)` (agent registered), cyan `oklch(0.76 0.11 215)` (AI triage). Badge fills use `color-mix(in oklch, <color> 16%, transparent)`.
- **Density vars** (compact): `--row-h 36px`, `--card-pad 14px`, gaps 6/10/14/20, `--fs-body 12.5px`, `--fs-label 11px`. (Comfortable: 46px row, 18px pad, larger.)
- **Radius**: cards 6px, buttons/inputs/chips 6–7px, badges 5px, pills 999px.
- **Shadows**: `--shadow-1` (subtle inset + 2px), `--shadow-2` (drawer/menus, 8–24px). Minimal glow, no heavy gradients.
- **Type**: `IBM Plex Sans` (UI) + `IBM Plex Mono` (IDs, timestamps, labels, technical values). Both loaded from Google Fonts. `font-feature-settings: 'ss01','cv11'`; `tabular-nums` on numeric values.

### Badge semantics
Action badges (mono uppercase, colored text + soft fill, leading dot):
- `LOGIN_SUCCESS` → ok · `LOGIN_FAILURE` → crit · `LOGOUT` → dim
- `SOAR_RUN` → info · `SOAR_APPROVE` → ok · `SOAR_REJECT` → high
- `ALERT_STATUS_CHANGED` → purple
- `AGENT_REGISTERED` → teal · `AGENT_DEREGISTERED` → dim · `AGENT_KEY_ROTATED` → accent orange (sensitive)
- `AI_TRIAGE_REQUESTED` / `AI_TRIAGE_COMPLETED` → cyan
- `SYSTEM_CONFIG_CHANGED` / `SYSTEM_LOGIN_POLICY` → muted

Result badges (existing `.badge` classes): Approved/Executed/Success/Completed/Registered → `ok`; Updated/Rotated → `info`; Queued → `high`; Rejected/Failed → `crit`; Removed → `muted`.

## Assets
- **Fonts**: IBM Plex Sans + IBM Plex Mono (Google Fonts).
- **Icons**: inline SVG stroke icons from the app's `Icon` component (`components.jsx`) — names used here: `shield, download, search, filter, refresh, activity, key, soar, agent, alert, ai, link, chevron, file`. No raster/image assets. Reuse your codebase's icon set with equivalents.

## Files
In this bundle (and in the OVS project):
- `pages-audit.jsx` — **the Audit Trail page**: `AuditTrailPage`, `AuditDetailDrawer`, `ActionBadge`, `ResultBadge`, `AuditObject`, `SensitiveChip`, and the action/result color maps. Start here.
- `data.jsx` — mock data; the `AUDIT_EVENTS` array (bottom) defines the event shape: `{ id, ts, actor, actorRole, action, category, objType, objId, result, source, sensitive?, details: [[key,value]], related: [{label, page}] }`. Value `'__SENSITIVE__'` signals a redacted field.
- `components.jsx` — shared primitives the page reuses: `Icon`, `Drawer`, `Empty`, `KPI`, `Toggle`, `showToast`, badge/table CSS hooks.
- `styles.css` — all design tokens and component classes (`.kpi-row`, `.filters`, `.filter-chip`, `.table`, `.badge`, `.drawer`, `.empty`, `.skel`, `.card`, `.btn`, etc.).
- `app.jsx` — how the page is wired into nav/routing: sidebar `SYSTEM` group item `audit-trail`, `ROUTE_LABELS['audit-trail'] = ['System','Audit Trail']`, and the `renderPage` switch case.
- `index.html` — script include order (React 18 + Babel standalone, then the app scripts).

To run the prototype: open `index.html` in the OVS project and navigate to System → Audit Trail.
