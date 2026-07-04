from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from .. import db
from ..auth.csrf import verify_json_csrf
from ..services import audit_service
from ..services.alert_service import get_actor_username
from ..services.settings_service import (
    _SOAR_MODE_LABELS,
    _VALID_SOAR_MODES,
    get_soar_execution_mode,
    set_setting,
)

router = APIRouter(prefix="/api", tags=["settings"])


class SOARSettingsUpdate(BaseModel):
    soar_execution_mode: str
    updated_by: Optional[str] = "admin"


@router.get("/settings/soar")
def get_soar_settings(database: Session = Depends(db.get_db)):
    mode = get_soar_execution_mode(database)
    return {
        "soar_execution_mode": mode,
        "label": _SOAR_MODE_LABELS[mode],
        "simulation_only": True,
        "real_actions_enabled": False,
    }


@router.post("/settings/soar", dependencies=[Depends(verify_json_csrf)])
def update_soar_settings(request: Request, body: SOARSettingsUpdate, database: Session = Depends(db.get_db)):
    if body.soar_execution_mode not in _VALID_SOAR_MODES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid mode '{body.soar_execution_mode}'. Allowed: {sorted(_VALID_SOAR_MODES)}",
        )
    # Actor from the authenticated session, not the request body (ST-027).
    actor = get_actor_username(request)
    previous_mode = get_soar_execution_mode(database)
    set_setting(
        database,
        key="soar_execution_mode",
        value=body.soar_execution_mode,
        description="SOAR execution mode: manual | automatic",
        updated_by=actor,
    )
    audit_service.record_audit_event(
        database,
        actor=actor,
        action=audit_service.SYSTEM_CONFIG_CHANGED,
        object_type="system",
        object_id="soar_execution_mode",
        source_ip=audit_service.client_ip(request),
        details={"setting": "soar_execution_mode", "from": previous_mode, "to": body.soar_execution_mode},
        commit=True,
    )
    return {
        "success": True,
        "soar_execution_mode": body.soar_execution_mode,
        "label": _SOAR_MODE_LABELS[body.soar_execution_mode],
    }
