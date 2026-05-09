import os

from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session
from sqlalchemy import text
from starlette.middleware.sessions import SessionMiddleware
from typing import List
from . import models, db
from .routers import dashboard, api_metrics, rules, collector, agents, system_health_rules, soar, settings, ai_triage
from .routers import auth as auth_router_module
from .auth.dependencies import require_html_auth, require_api_auth
from .auth.exceptions import LoginRequiredException
import pathlib


def run_startup_migrations():
    """Add lifecycle columns to agent_records if they don't exist yet. PostgreSQL only."""
    db_url = str(db.engine.url)
    if not (db_url.startswith("postgresql") or db_url.startswith("postgres")):
        return
    migrations = [
        "ALTER TABLE agent_records ADD COLUMN IF NOT EXISTS is_deleted BOOLEAN NOT NULL DEFAULT FALSE",
        "ALTER TABLE agent_records ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMP",
        "ALTER TABLE agent_records ADD COLUMN IF NOT EXISTS deleted_reason VARCHAR",
        "ALTER TABLE agent_records ADD COLUMN IF NOT EXISTS lifecycle_status VARCHAR DEFAULT 'pending_registration'",
        # Backfill: existing active agents should be active_inventory, not pending_registration
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
    ]
    with db.engine.connect() as conn:
        for sql in migrations:
            conn.execute(text(sql))
        conn.commit()


run_startup_migrations()

# Create tables
models.Base.metadata.create_all(bind=db.engine)

import asyncio
# from .services.opensearch_poller import poll_opensearch_loop

app = FastAPI(title="SIEM Ingestion API")

app.add_middleware(
    SessionMiddleware,
    secret_key=os.getenv("SESSION_SECRET_KEY", "change-me-in-production"),
    session_cookie="session",
    same_site="lax",
    https_only=False,
)


@app.exception_handler(LoginRequiredException)
async def _login_redirect(request: Request, exc: LoginRequiredException):
    return RedirectResponse(url="/login", status_code=302)


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
app.include_router(rules.router, dependencies=[Depends(require_html_auth)])

# Protected JSON API routes — unauthenticated request → 401
# api_metrics includes POST /api/metrics (agent ingestion, must stay open) so auth is per-route there
app.include_router(api_metrics.router)
app.include_router(soar.router, dependencies=[Depends(require_api_auth)])
app.include_router(ai_triage.router, dependencies=[Depends(require_api_auth)])
app.include_router(settings.router, dependencies=[Depends(require_api_auth)])
app.include_router(system_health_rules.router, dependencies=[Depends(require_api_auth)])

def seed_health_rules():
    database = db.SessionLocal()
    try:
        existing = database.query(models.SystemHealthRule).count()
        if existing == 0:
            print("🌱 Seeding default System Health Rules...")
            rules = [
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
                    threshold_value=100000000.0, # 100MB/s
                    operator=">",
                    severity="LOW"
                ),
                models.SystemHealthRule(
                    rule_id="metric_high_network_out",
                    rule_name="High Network Egress",
                    metric_name="net_out",
                    threshold_value=100000000.0, # 100MB/s
                    operator=">",
                    severity="LOW"
                ),
            ]
            database.add_all(rules)
            database.commit()
    finally:
        database.close()

@app.on_event("startup")
async def startup_event():
    print("API Started - Real-time Ingestion Enabled")
    seed_health_rules()
@app.get("/health")
def health_check():
    return {"status": "ok"}

from .detection.engine.detection_engine import RuleEngine

# Old ingest logic moved to collector.py router

@app.get("/logs/recent", response_model=List[models.LogOut], dependencies=[Depends(require_api_auth)])
def get_recent_logs(limit: int = 50, db: Session = Depends(db.get_db)):
    logs = db.query(models.Log).order_by(models.Log.timestamp.desc()).limit(limit).all()
    return logs
