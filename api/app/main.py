from fastapi import FastAPI, Depends, HTTPException
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session
from typing import List
from . import models, db
from .routers import dashboard, api_metrics, rules

# Create tables
models.Base.metadata.create_all(bind=db.engine)

app = FastAPI(title="SIEM Ingestion API")

app.mount("/static", StaticFiles(directory="static"), name="static")

app.include_router(dashboard.router)
app.include_router(api_metrics.router)
app.include_router(rules.router)

@app.get("/health")
def health_check():
    return {"status": "ok"}

from .services.rule_engine import RuleEngine

@app.post("/ingest/log")
def ingest_log(log: models.LogCreate, db: Session = Depends(db.get_db)):
    db_log = models.Log(**log.model_dump())
    db.add(db_log)
    db.commit()
    db.refresh(db_log)
    
    # Run Rule Engine
    engine = RuleEngine(db)
    engine.evaluate(db_log)
    
    return {"status": "ok", "id": db_log.id}

@app.get("/logs/recent", response_model=List[models.LogOut])
def get_recent_logs(limit: int = 50, db: Session = Depends(db.get_db)):
    logs = db.query(models.Log).order_by(models.Log.timestamp.desc()).limit(limit).all()
    return logs
