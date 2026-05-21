# ST-038 — Secrets Remediation Guide (Pre-Production)

Finding: Gemini API key and session secret stored as plaintext in `api/.env`  
Status in v2.8.0: **Accepted residual risk** — `GEMINI_API_KEY` is blank and `AI_TRIAGE_ENABLED=false`  
Must fix before: Any production deployment or before enabling Gemini AI triage

---

## Secrets in Scope

| Variable | Sensitivity | Current location |
|---|---|---|
| `GEMINI_API_KEY` | High — third-party API key; costs money if leaked | `api/.env` (blank in v2.8.0) |
| `SESSION_SECRET_KEY` | High — signs session cookies; compromise = session forgery | `api/.env` |
| `DASHBOARD_PASSWORD_HASH` | Medium — bcrypt hash; rotation breaks active sessions | `api/.env` |
| `CLIENT_PASSWORD_HASH` | Medium | `api/.env` |
| `POSTGRES_PASSWORD` | High — DB access | `api/.env` |

---

## Pre-Deployment Checklist (Immediate)

Before any production deployment regardless of secrets strategy:

- [ ] **Rotate `GEMINI_API_KEY`** — the key used during local development must be considered compromised if it was ever written to `.env` and shared or committed. Issue a new key from Google AI Studio.
- [ ] **Regenerate `SESSION_SECRET_KEY`** — generate a new 64+ character random hex string:
  ```bash
  python3 -c "import secrets; print(secrets.token_hex(32))"
  ```
- [ ] **Confirm `api/.env` is not committed** — `git status` and `git log --all -- api/.env` must return nothing.
- [ ] **Set `AI_TRIAGE_ENABLED=false`** until `GEMINI_API_KEY` is loaded from a secrets manager.

---

## Option A — Docker Secrets (Recommended for Single-Host Deployment)

Docker secrets mount secret values as files inside the container. The app reads from the file path rather than an environment variable.

### Step 1: Create secret files (never committed to git)

```bash
mkdir -p secrets/
echo -n "your-new-session-secret-hex" > secrets/session_secret_key
echo -n "your-gemini-api-key" > secrets/gemini_api_key
echo -n "your-postgres-password" > secrets/postgres_password
chmod 600 secrets/*
echo "secrets/" >> .gitignore
```

### Step 2: Update `docker-compose.yml`

```yaml
secrets:
  session_secret_key:
    file: ./secrets/session_secret_key
  gemini_api_key:
    file: ./secrets/gemini_api_key
  postgres_password:
    file: ./secrets/postgres_password

services:
  api:
    secrets:
      - session_secret_key
      - gemini_api_key
    environment:
      SESSION_SECRET_KEY_FILE: /run/secrets/session_secret_key
      GEMINI_API_KEY_FILE: /run/secrets/gemini_api_key
      # Remove SESSION_SECRET_KEY and GEMINI_API_KEY from env entirely
```

### Step 3: Update `api/app/main.py` — read from file if env var points to a file

Add a helper at the top of `main.py` (before secret-consuming code):

```python
import os

def _read_secret(env_var: str, file_env_var: str | None = None) -> str | None:
    if file_env_var:
        path = os.getenv(file_env_var)
        if path and os.path.isfile(path):
            with open(path) as f:
                return f.read().strip()
    return os.getenv(env_var)

SESSION_SECRET_KEY = _read_secret("SESSION_SECRET_KEY", "SESSION_SECRET_KEY_FILE")
GEMINI_API_KEY = _read_secret("GEMINI_API_KEY", "GEMINI_API_KEY_FILE")
```

Apply the same pattern wherever these env vars are read in routers/middleware.

---

## Option B — HashiCorp Vault (Recommended for Multi-Host / Production)

Use Vault's AppRole auth or Kubernetes auth to inject secrets at startup.

### Minimal setup

```bash
# 1. Start Vault (or use Vault Cloud / HCP Vault)
vault server -dev  # dev mode only; use Raft storage for prod

# 2. Store secrets
vault kv put secret/ovs/api \
  session_secret_key="$(python3 -c 'import secrets; print(secrets.token_hex(32))')" \
  gemini_api_key="your-api-key" \
  postgres_password="your-db-password"

# 3. Create a read-only policy
vault policy write ovs-api - <<EOF
path "secret/data/ovs/api" { capabilities = ["read"] }
EOF

# 4. Enable AppRole and create a role
vault auth enable approle
vault write auth/approle/role/ovs-api token_policies="ovs-api" token_ttl=1h

# 5. At container startup, fetch secrets via vault CLI or API and export to env
VAULT_TOKEN=$(vault write -field=token auth/approle/login \
  role_id="$VAULT_ROLE_ID" secret_id="$VAULT_SECRET_ID")
eval $(vault kv get -format=json secret/ovs/api | \
  jq -r '.data.data | to_entries[] | "export \(.key | ascii_upcase)=\(.value)"')
```

The Vault agent sidecar can also handle automatic secret injection and renewal without modifying application code.

---

## Option C — Minimal Improvement (`.env` stays, but never committed)

If full secrets management is not feasible immediately:

1. **Never commit `api/.env`** — enforce with pre-commit hook:
   ```bash
   # .git/hooks/pre-commit
   if git diff --cached --name-only | grep -q "api/.env"; then
     echo "ERROR: Refusing to commit api/.env (contains secrets)"
     exit 1
   fi
   ```
2. **Restrict file permissions** on the host:
   ```bash
   chmod 600 api/.env
   chown root:root api/.env  # or the deploy user only
   ```
3. **Rotate secrets on every deployment** using a CI/CD pipeline that injects env vars from a CI secrets store (GitHub Actions secrets, GitLab CI variables, etc.).
4. **Set `AI_TRIAGE_ENABLED=false`** unless the Gemini key is loaded from a non-`.env` source.

---

## v2.9.0 Acceptance Criteria

ST-038 should be closed in v2.9.0 when:

- [ ] `GEMINI_API_KEY` is NOT read from `.env` in any environment where `AI_TRIAGE_ENABLED=true`
- [ ] `SESSION_SECRET_KEY` is loaded from a Docker secret or Vault in production
- [ ] A startup guard in `main.py` refuses to start with `AI_TRIAGE_ENABLED=true` and `GEMINI_API_KEY` coming from a plain env var (no `_FILE` equivalent configured)
- [ ] Pre-commit hook prevents accidental `.env` commit
- [ ] Automated test verifies the `_read_secret()` helper prefers file-based secrets over env vars

---

*Document added: v2.8.0 | Tracking finding: ST-038 | Next action: v2.9.0 sprint*
