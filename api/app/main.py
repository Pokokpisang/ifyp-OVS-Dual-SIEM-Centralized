import os

from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session
from sqlalchemy import text
from starlette.middleware.sessions import SessionMiddleware
from typing import List
from . import models, db
from .routers import dashboard, api_metrics, rules, collector, agents, system_health_rules, soar, settings, ai_triage, audit, notifications
from .routers import auth as auth_router_module
from .auth.dependencies import require_html_auth, require_api_auth, require_admin_auth, require_admin_html
from .auth.exceptions import LoginRequiredException
from .auth.session_middleware import ServerSessionMiddleware
from .middleware.security_headers import SecurityHeadersMiddleware
import pathlib
from .auth.startup import validate_session_secret as _validate_session_secret
from .routers.auth import limiter as _login_limiter
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded


def run_startup_migrations():
    """Add columns/tables incrementally. PostgreSQL only."""
    db_url = str(db.engine.url)
    if not (db_url.startswith("postgresql") or db_url.startswith("postgres")):
        return
    migrations = [
        "ALTER TABLE agent_records ADD COLUMN IF NOT EXISTS is_deleted BOOLEAN NOT NULL DEFAULT FALSE",
        "ALTER TABLE agent_records ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMP",
        "ALTER TABLE agent_records ADD COLUMN IF NOT EXISTS deleted_reason VARCHAR",
        "ALTER TABLE agent_records ADD COLUMN IF NOT EXISTS lifecycle_status VARCHAR DEFAULT 'pending_registration'",
        "UPDATE agent_records SET lifecycle_status = 'active_inventory' WHERE status = 'active' AND lifecycle_status = 'pending_registration'",
        "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS dedup_key VARCHAR",
        "CREATE INDEX IF NOT EXISTS ix_alerts_dedup_key ON alerts (dedup_key)",
        "ALTER TABLE soar_action_executions ADD COLUMN IF NOT EXISTS requires_approval BOOLEAN NOT NULL DEFAULT FALSE",
        "ALTER TABLE soar_action_executions ADD COLUMN IF NOT EXISTS approved_by VARCHAR",
        "ALTER TABLE soar_action_executions ADD COLUMN IF NOT EXISTS approved_at TIMESTAMP",
        "ALTER TABLE soar_action_executions ADD COLUMN IF NOT EXISTS rejected_by VARCHAR",
        "ALTER TABLE soar_action_executions ADD COLUMN IF NOT EXISTS rejected_at TIMESTAMP",
        # v2.5.0 AI Alert Triage
        (
            "CREATE TABLE IF NOT EXISTS ai_alert_triages ("
            "  id SERIAL PRIMARY KEY,"
            "  alert_id INTEGER NOT NULL REFERENCES alerts(id),"
            "  provider VARCHAR NOT NULL,"
            "  model_name VARCHAR NOT NULL,"
            "  triage_status VARCHAR NOT NULL,"
            "  summary TEXT,"
            "  priority VARCHAR,"
            "  confidence VARCHAR,"
            "  false_positive_likelihood VARCHAR,"
            "  key_reasons_json TEXT,"
            "  recommended_next_steps_json TEXT,"
            "  soar_recommendation_json TEXT,"
            "  input_context_json TEXT,"
            "  raw_output_json TEXT,"
            "  error_message TEXT,"
            "  created_at TIMESTAMP DEFAULT NOW(),"
            "  updated_at TIMESTAMP DEFAULT NOW()"
            ")"
        ),
        "CREATE INDEX IF NOT EXISTS ix_ai_alert_triages_alert_id ON ai_alert_triages (alert_id)",
        "CREATE INDEX IF NOT EXISTS ix_ai_alert_triages_created_at ON ai_alert_triages (created_at)",
        # v2.8.0 Server-side session store (ST-010, ST-012, ST-041)
        (
            "CREATE TABLE IF NOT EXISTS server_sessions ("
            "  id SERIAL PRIMARY KEY,"
            "  token_hash VARCHAR UNIQUE NOT NULL,"
            "  username VARCHAR NOT NULL,"
            "  role VARCHAR NOT NULL DEFAULT 'admin',"
            "  created_at TIMESTAMP DEFAULT NOW(),"
            "  expires_at TIMESTAMP NOT NULL"
            ")"
        ),
        "CREATE INDEX IF NOT EXISTS ix_server_sessions_token_hash ON server_sessions (token_hash)",
        "CREATE INDEX IF NOT EXISTS ix_server_sessions_expires_at ON server_sessions (expires_at)",
        # v2.10.0 Audit Trail page
        "ALTER TABLE activity_audit ADD COLUMN IF NOT EXISTS source_ip VARCHAR",
        "CREATE INDEX IF NOT EXISTS ix_activity_audit_action ON activity_audit (action)",
        "CREATE INDEX IF NOT EXISTS ix_activity_audit_actor ON activity_audit (actor)",
        # v2.11.0 Notification channels + delivery log
        (
            "CREATE TABLE IF NOT EXISTS notification_channels ("
            "  id SERIAL PRIMARY KEY,"
            "  name VARCHAR NOT NULL,"
            "  channel_type VARCHAR NOT NULL,"
            "  target VARCHAR NOT NULL,"
            "  min_severity VARCHAR NOT NULL DEFAULT 'HIGH',"
            "  enabled BOOLEAN NOT NULL DEFAULT TRUE,"
            "  created_at TIMESTAMP DEFAULT NOW(),"
            "  updated_at TIMESTAMP DEFAULT NOW()"
            ")"
        ),
        (
            "CREATE TABLE IF NOT EXISTS notification_deliveries ("
            "  id SERIAL PRIMARY KEY,"
            "  channel_id INTEGER,"
            "  channel_name VARCHAR,"
            "  channel_type VARCHAR,"
            "  target VARCHAR,"
            "  alert_id INTEGER,"
            "  subject VARCHAR,"
            "  status VARCHAR NOT NULL,"
            "  error_message TEXT,"
            "  created_at TIMESTAMP DEFAULT NOW()"
            ")"
        ),
        "CREATE INDEX IF NOT EXISTS ix_notification_deliveries_created_at ON notification_deliveries (created_at)",
        "CREATE INDEX IF NOT EXISTS ix_notification_deliveries_alert_id ON notification_deliveries (alert_id)",
    ]
    with db.engine.connect() as conn:
        for sql in migrations:
            conn.execute(text(sql))
        conn.commit()


run_startup_migrations()

# Create tables (handles new models added after initial deployment)
models.Base.metadata.create_all(bind=db.engine)

import asyncio

# RF-1: Validate session secret at startup — fail fast if absent or insecure.
_SESSION_SECRET = os.getenv("SESSION_SECRET_KEY", "")
_validate_session_secret(_SESSION_SECRET)
_https_only = os.getenv("SESSION_COOKIE_SECURE", "true").lower() == "true"
_SESSION_MAX_AGE = int(os.getenv("SESSION_MAX_AGE_SECONDS", "28800"))  # ST-041: 8h default

# ST-022: Disable API docs in non-development environments.
_API_DOCS_ENABLED = os.getenv("API_DOCS_ENABLED", "false").lower() == "true"

app = FastAPI(
    title="SIEM Ingestion API",
    docs_url="/docs" if _API_DOCS_ENABLED else None,
    redoc_url="/redoc" if _API_DOCS_ENABLED else None,
    openapi_url="/openapi.json" if _API_DOCS_ENABLED else None,
)
app.state.limiter = _login_limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Middleware registration order (Starlette: last-added = outermost = runs first on request):
#   1. SessionMiddleware (outermost) — populates request.session from signed cookie
#   2. ServerSessionMiddleware — validates session_token against DB, sets request.state.user
#   3. SecurityHeadersMiddleware (innermost) — adds security headers to every response
app.add_middleware(SecurityHeadersMiddleware)    # innermost — runs last on request
app.add_middleware(ServerSessionMiddleware)      # middle — validates server-side session
app.add_middleware(
    SessionMiddleware,
    secret_key=_SESSION_SECRET,
    session_cookie="session",
    same_site="lax",
    https_only=_https_only,
    max_age=_SESSION_MAX_AGE,                   # ST-041: configurable lifetime (default 8h)
)


@app.exception_handler(LoginRequiredException)
async def _login_redirect(request: Request, exc: LoginRequiredException):
    return RedirectResponse(url="/login", status_code=302)


@app.exception_handler(404)
async def _not_found(request: Request, exc: HTTPException):
    """Render a typed 404 page for browser navigation; keep JSON for API paths."""
    accepts_html = "text/html" in request.headers.get("accept", "")
    is_api_path = request.url.path.startswith(("/api/", "/ingest/"))
    if accepts_html and not is_api_path:
        from fastapi.templating import Jinja2Templates
        return Jinja2Templates(directory="templates").TemplateResponse(
            "404.html", {"request": request}, status_code=404
        )
    return JSONResponse(status_code=404, content={"detail": getattr(exc, "detail", "Not Found")})


app.mount("/static", StaticFiles(directory="static"), name="static")

# Serve agent binary downloads — create dir if missing so the app doesn't crash
_downloads_dir = pathlib.Path("downloads")
_downloads_dir.mkdir(exist_ok=True)
app.mount("/downloads", StaticFiles(directory="downloads"), name="downloads")

# Public routes — no dashboard auth required
app.include_router(auth_router_module.router)
app.include_router(collector.router)     # POST /ingest/log — X-Agent-Key only
app.include_router(agents.router)        # agent registration, heartbeat, install scripts

# Protected HTML dashboard routes — unauthenticated browser → 302 /login
app.include_router(dashboard.router, dependencies=[Depends(require_html_auth)])
# ST-012: Rules page restricted to admin role only
app.include_router(rules.router, dependencies=[Depends(require_admin_html)])
# Audit Trail — per-route admin deps (mixed HTML page + JSON/CSV endpoints)
app.include_router(audit.router)
# Notifications — per-route admin deps (mixed HTML page + JSON endpoints)
app.include_router(notifications.router)

# Protected JSON API routes — unauthenticated request → 401
# api_metrics: POST /api/metrics is agent-key protected (per-route), other endpoints need session
app.include_router(api_metrics.router)
app.include_router(soar.router, dependencies=[Depends(require_api_auth)])
app.include_router(ai_triage.router, dependencies=[Depends(require_api_auth)])
# ST-012: Settings and system health rules restricted to admin role
app.include_router(settings.router, dependencies=[Depends(require_admin_auth)])
app.include_router(system_health_rules.router, dependencies=[Depends(require_admin_auth)])


def seed_health_rules():
    database = db.SessionLocal()
    try:
        existing = database.query(models.SystemHealthRule).count()
        if existing == 0:
            print("Seeding default System Health Rules...")
            default_rules = [
                models.SystemHealthRule(
                    rule_id="metric_high_cpu",
                    rule_name="High CPU Usage",
                    metric_name="cpu",
                    threshold_value=80.0,
                    operator=">",
                    severity="MEDIUM"
                ),
                models.SystemHealthRule(
                    rule_id="metric_high_ram",
                    rule_name="High RAM Usage",
                    metric_name="ram",
                    threshold_value=85.0,
                    operator=">",
                    severity="MEDIUM"
                ),
                models.SystemHealthRule(
                    rule_id="metric_high_network_in",
                    rule_name="High Network Ingress",
                    metric_name="net_in",
                    threshold_value=100000000.0,
                    operator=">",
                    severity="LOW"
                ),
                models.SystemHealthRule(
                    rule_id="metric_high_network_out",
                    rule_name="High Network Egress",
                    metric_name="net_out",
                    threshold_value=100000000.0,
                    operator=">",
                    severity="LOW"
                ),
            ]
            database.add_all(default_rules)
            database.commit()
    finally:
        database.close()


@app.on_event("startup")
async def startup_event():
    # Purge expired server sessions on startup to keep the table tidy.
    from .auth.session_store import purge_expired_sessions
    _purge_db = db.SessionLocal()
    try:
        purge_expired_sessions(_purge_db)
    finally:
        _purge_db.close()
    print("API Started - Real-time Ingestion Enabled")
    seed_health_rules()


@app.get("/", include_in_schema=False)
def root_redirect():
    """Land users on the dashboard; unauthenticated browsers bounce to /login."""
    return RedirectResponse(url="/dashboard", status_code=302)


@app.get("/health")
def health_check():
    return {"status": "ok"}


from .detection.engine.detection_engine import RuleEngine


@app.get("/logs/recent", response_model=List[models.LogOut], dependencies=[Depends(require_api_auth)])
def get_recent_logs(limit: int = 50, db: Session = Depends(db.get_db)):
    logs = db.query(models.Log).order_by(models.Log.timestamp.desc()).limit(limit).all()
    return logs
