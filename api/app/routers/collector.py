from fastapi import APIRouter, BackgroundTasks, Request, Depends
from pydantic import BaseModel, ConfigDict
from typing import Any, Dict, Optional
from sqlalchemy.orm import Session
from datetime import datetime, timezone
import httpx
import os
import json
from .. import db, models
from ..services.rule_engine import RuleEngine

router = APIRouter()

DATA_PREPPER_URL = os.getenv("DATA_PREPPER_URL", "http://data-prepper:2021/log/ingest")

class AgentLog(BaseModel):
    model_config = ConfigDict(extra="allow")

async def process_log_for_alerts(payload: dict):
    """Background task to run rule evaluation immediately."""
    db_session = db.SessionLocal()
    try:
        engine = RuleEngine(db_session)
        engine.evaluate_raw(payload)
    except Exception as e:
        print(f"Error in real-time rule evaluation: {e}")
    finally:
        db_session.close()

async def forward_to_data_prepper(payload: dict):
    async with httpx.AsyncClient() as client:
        try:
            # Data prepper http source accepts arrays of JSONs
            response = await client.post(DATA_PREPPER_URL, json=[payload])
            response.raise_for_status()
        except Exception as e:
            print(f"Failed to forward log to Data Prepper: {e}")

@router.post("/ingest/log")
async def collect_agent_logs(request: Request, background_tasks: BackgroundTasks, database: Session = Depends(db.get_db)):
    # 1. Read Raw JSON
    try:
        payload = await request.json()
    except json.JSONDecodeError:
        return {"status": "error", "message": "Invalid JSON"}

    # Add metadata if needed (for example agent_id if present in headers, or timestamp)
    # Override timestamp with server ingestion time so Data Prepper @timestamp stays current
    ingestion_time = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    payload["timestamp"] = ingestion_time
    payload["agent_received_at"] = ingestion_time
    # 2. Save to PostgreSQL (for Dashboard / System Logs UI)
    try:
        # Use server ingestion time or the one provided by agent if reliable
        # For now, we use the normalized ingestion_time we just created
        new_log = models.Log(
            timestamp=datetime.now(timezone.utc),
            host=payload.get("host") or payload.get("hostname", "unknown"),
            log_type=payload.get("log_type", "unknown"),
            file_path=payload.get("file_path", "unknown"),
            message=payload.get("message", "")
        )
        database.add(new_log)
        database.commit()
    except Exception as e:
        print(f"Failed to save log to database: {e}")
    
    # 3. Offload tasks to background
    background_tasks.add_task(forward_to_data_prepper, payload)
    background_tasks.add_task(process_log_for_alerts, payload)
    
    return {"status": "accepted"}
