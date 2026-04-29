from fastapi import FastAPI, Depends, HTTPException
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session
from typing import List
from . import models, db
from .routers import dashboard, api_metrics, rules, collector, agents
import pathlib

# Create tables
models.Base.metadata.create_all(bind=db.engine)

import asyncio
# from .services.opensearch_poller import poll_opensearch_loop

app = FastAPI(title="SIEM Ingestion API")

# poller_task = None

@app.on_event("startup")
async def startup_event():
    print("API Started - Real-time Ingestion Enabled")
    # OpenSearch poller disabled in favor of real-time collector.py logic
    pass

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
@app.get("/health")
def health_check():
    return {"status": "ok"}

from .detection.engine.detection_engine import RuleEngine

# Old ingest logic moved to collector.py router

@app.get("/logs/recent", response_model=List[models.LogOut])
def get_recent_logs(limit: int = 50, db: Session = Depends(db.get_db)):
    logs = db.query(models.Log).order_by(models.Log.timestamp.desc()).limit(limit).all()
    return logs
