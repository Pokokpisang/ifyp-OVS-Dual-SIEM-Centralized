from fastapi import FastAPI, Depends, HTTPException
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session
from typing import List
from . import models, db
from .routers import dashboard, api_metrics, rules, collector, agents, system_health_rules, soar
import pathlib

# Create tables
models.Base.metadata.create_all(bind=db.engine)

import asyncio
# from .services.opensearch_poller import poll_opensearch_loop

app = FastAPI(title="SIEM Ingestion API")

app.mount("/static", StaticFiles(directory="static"), name="static")

# Serve agent binary downloads — create dir if missing so the app doesn't crash
_downloads_dir = pathlib.Path("downloads")
_downloads_dir.mkdir(exist_ok=True)
app.mount("/downloads", StaticFiles(directory="downloads"), name="downloads")

app.include_router(dashboard.router)
app.include_router(api_metrics.router)
app.include_router(rules.router)
app.include_router(collector.router)
app.include_router(agents.router)
app.include_router(system_health_rules.router)
app.include_router(soar.router)

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

@app.get("/logs/recent", response_model=List[models.LogOut])
def get_recent_logs(limit: int = 50, db: Session = Depends(db.get_db)):
    logs = db.query(models.Log).order_by(models.Log.timestamp.desc()).limit(limit).all()
    return logs
