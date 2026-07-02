from fastapi import APIRouter, BackgroundTasks, HTTPException, Request, Depends, Header
from pydantic import BaseModel, ConfigDict
from typing import Optional
from sqlalchemy.orm import Session
from datetime import datetime, timezone
import httpx
import os
import json
from .. import db, models
from ..detection.engine.detection_engine import RuleEngine
from ..services.agent_service import update_last_seen, get_agent_metadata_by_key

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
async def collect_agent_logs(
    request: Request, 
    background_tasks: BackgroundTasks, 
    database: Session = Depends(db.get_db),
    x_agent_key: Optional[str] = Header(None, alias="X-Agent-Key")
):
    # 0. Authenticate — reject requests from unknown or missing agent keys
    if not x_agent_key:
        raise HTTPException(status_code=401, detail="X-Agent-Key header is required.")
    agent_meta = get_agent_metadata_by_key(agent_key=x_agent_key, db=database)
    if agent_meta is None:
        raise HTTPException(status_code=401, detail="Invalid or unregistered agent key.")
    update_last_seen(agent_key=x_agent_key, db=database)

    # 1. Read Raw JSON
    try:
        payload = await request.json()
    except json.JSONDecodeError:
        return {"status": "error", "message": "Invalid JSON"}

    # Add metadata
    ingestion_time = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    payload["timestamp"] = ingestion_time
    payload["agent_received_at"] = ingestion_time
    
    # Enrichment with Agent Identity (v2.0.0 Requirement)
    payload["agent_id"] = agent_meta["agent_id"]
    payload["hostname"] = agent_meta["hostname"]
    payload["ip_address"] = agent_meta["ip_address"]
    payload["os_type"] = agent_meta["os_type"]
    payload["distribution"] = agent_meta["distribution"]
    payload["agent_name"] = agent_meta["agent_name"]

    # ECS compatibility fields
    payload["host"] = {
        "name": agent_meta["hostname"],
        "ip": agent_meta["ip_address"],
        "os": {
            "type": agent_meta["os_type"].lower(),
            "name": agent_meta["distribution"]
        }
    }
    payload["agent"] = {
        "id": agent_meta["agent_id"],
        "name": agent_meta["agent_name"]
    }
    # 2. Save to PostgreSQL (for Dashboard / System Logs UI)
    try:
        # Use server ingestion time or the one provided by agent if reliable
        # For now, we use the normalized ingestion_time we just created
        new_log = models.Log(
            timestamp=datetime.now(timezone.utc),
            host=payload.get("host") if isinstance(payload.get("host"), str) else payload.get("hostname", "unknown"),
            agent_id=payload.get("agent_id"),
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
