# OVS Client Portal

A standalone, **read-only** web portal for one tenant (client) of the OVS
security platform. It runs in a **separate environment** from the SOC server
— typically on the client's side or on operator infrastructure dedicated to
that client — and its only data source is the SOC server's tenant-scoped
`/api/portal/*` endpoints.

**What it can never do, by construction:**
- register or manage agents (agent lifecycle is SOC-side only)
- see any other tenant's data (the API key is tenant-scoped, fail-closed)
- mutate anything on the SOC server (the key only works on read-only GETs)
- see detection-rule internals, SOAR activity, or SOC audit logs

## Screens

| Route | Screen |
|---|---|
| `/` | Overview — servers, open events, last-24h, severity breakdown |
| `/agents` | My Agents — the client's monitored servers |
| `/events` | Security Events — paginated detections with severity filter |
| `/posture` | Monthly Posture — 7/30/90-day rollup |

## Deployment

1. On the SOC dashboard, open **Assets → Clients → (client) → Issue portal key**
   and copy the `ovsc_…` key (shown once).
2. Run the portal with that key:

```bash
docker build -t ovs-portal .
docker run -d --name ovs-portal -p 8100:8100 \
  -e SOC_API_URL="https://soc.example.com" \
  -e CLIENT_API_KEY="ovsc_..." \
  -e PORTAL_PASSWORD="something-long-for-the-client" \
  -e PORTAL_SECRET_KEY="$(openssl rand -hex 32)" \
  ovs-portal
```

Or without Docker:

```bash
pip install -r requirements.txt
SOC_API_URL=... CLIENT_API_KEY=... PORTAL_PASSWORD=... \
  uvicorn app.main:app --host 0.0.0.0 --port 8100
```

## Environment variables

| Variable | Required | Purpose |
|---|---|---|
| `SOC_API_URL` | yes | SOC server base URL |
| `CLIENT_API_KEY` | yes | This client's portal key (issued by SOC admin) |
| `PORTAL_PASSWORD` | strongly recommended | Shared password gate for portal users. Leave unset **only** if the portal sits behind other access control (private network, operator SSO). |
| `PORTAL_SECRET_KEY` | recommended | Session-cookie signing secret; auto-generated (sessions reset on restart) if unset |
| `PORTAL_COOKIE_SECURE` | production | `true` when served over HTTPS |

## Failure behavior

- SOC unreachable → friendly outage page ("your servers are still monitored").
- Key rotated/revoked or client suspended → access-problem page telling the
  client to contact their provider. The SOC admin restores access by issuing
  a new key and updating `CLIENT_API_KEY`.

## Tests

```bash
# from the repo's api/ directory (reuses its venv):
cd ../portal && PYTHONPATH=. ../api/.venv/bin/python -m pytest tests/ -v
```
