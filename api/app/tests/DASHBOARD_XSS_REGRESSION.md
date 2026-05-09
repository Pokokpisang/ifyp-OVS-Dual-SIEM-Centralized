# Dashboard XSS Regression Checklist

Manual test cases for H1 — stored XSS via unsafe `innerHTML` in `dashboard.js`.
Run these after any change to `dashboard.js`, alert rendering, or `/api/alerts/*` endpoints.

## Background

Before the H1 fix, server-controlled alert fields (`title`, `host`, `description`,
`severity`, `mitre_id`) were interpolated directly into `innerHTML` template literals.
An attacker with access to `POST /ingest/log` (now gated by X-Agent-Key — see H2)
could store a malicious payload that executed JavaScript in the analyst's browser.

The fix adds `escapeHtml()` around all server-controlled fields and coerces numeric
KPI values with `parseInt(..., 10) || 0`.

---

## Prerequisites

- SIEM API running locally (`make up` or `uvicorn` in dev mode)
- A valid registered `X-Agent-Key` for a test agent (or temporarily bypass auth in
  dev with a known test key)
- Browser devtools console open on `/dashboard`

---

## Test Payloads

### TC-1 — XSS via alert `title` field

**Inject:**
```bash
curl -s -X POST http://localhost:8000/ingest/log \
  -H "Content-Type: application/json" \
  -H "X-Agent-Key: <your-test-key>" \
  -d '{"log_type":"syslog","message":"test","title":"<img src=x onerror=alert(\"XSS-title\")>"}'
```

**Expected (fixed):** The dashboard alert card renders literally:
```
<img src=x onerror=alert("XSS-title")>
```
as visible text inside the `<p>` tag. No alert dialog. No script execution.

**Failure (pre-fix):** `alert("XSS-title")` dialog fires on page load/refresh.

---

### TC-2 — XSS via alert `host` field

**Inject:**
```bash
curl -s -X POST http://localhost:8000/ingest/log \
  -H "Content-Type: application/json" \
  -H "X-Agent-Key: <your-test-key>" \
  -d '{"log_type":"syslog","message":"test","hostname":"<script>alert(\"XSS-host\")</script>"}'
```

**Expected (fixed):** The host span renders the literal string
`<script>alert("XSS-host")</script>` as text. No script execution.

**Failure (pre-fix):** Script tag executes in the browser context.

---

### TC-3 — XSS via `severity` fallback (unknown severity value)

**Inject:**
```bash
curl -s -X POST http://localhost:8000/ingest/log \
  -H "Content-Type: application/json" \
  -H "X-Agent-Key: <your-test-key>" \
  -d '{"log_type":"syslog","message":"test","severity":"<svg onload=alert(\"XSS-sev\")>"}'
```

**Expected (fixed):** The severity badge renders the literal string as text inside
the blue fallback `<span>`. No event fires.

**Failure (pre-fix):** SVG `onload` handler executes.

---

### TC-4 — XSS via `cmdExcerpt` in `title` attribute

**Inject:**
```bash
curl -s -X POST http://localhost:8000/ingest/log \
  -H "Content-Type: application/json" \
  -H "X-Agent-Key: <your-test-key>" \
  -d '{"log_type":"auditd","message":"Command Line: curl\"><img src=x onerror=alert(1)>. Agent detected"}'
```

**Expected (fixed):** The `<code>` element tooltip attribute contains the literal
string with `"` rendered as `&quot;`. Hovering the element shows escaped text.
No script execution.

**Failure (pre-fix):** The injected `"` breaks out of the `title=""` attribute and
the `onerror` handler fires.

---

### TC-5 — KPI stat coercion (non-integer injection)

This requires a crafted API response and is not injectable via normal `/ingest/log`.
It guards against a compromised backend or a future bug in `/api/alerts/stats`.

**Verify in devtools:**
Open the Network tab, intercept the `/api/alerts/stats` response, and modify it to:
```json
{"mitre_detections": "<script>alert(1)</script>", "unread_mitre": 1,
 "high_severity": 0, "unread_high": 0}
```

**Expected (fixed):** `parseInt("<script>alert(1)</script>", 10)` returns `NaN`,
`NaN || 0` renders as `0`. No script execution.

**Failure (pre-fix):** The raw string is injected into innerHTML.

---

## Pass Criteria

| TC | Injected field | Expected render | Script fires? |
|----|---------------|-----------------|---------------|
| TC-1 | `title` | Literal HTML characters as text | No |
| TC-2 | `hostname` | Literal HTML characters as text | No |
| TC-3 | `severity` (fallback) | Literal HTML characters as text | No |
| TC-4 | `description` / cmdExcerpt | Escaped in attribute and content | No |
| TC-5 | KPI stat (non-integer) | Renders as `0` | No |
