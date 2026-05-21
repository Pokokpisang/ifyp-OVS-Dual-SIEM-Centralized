from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from .. import db
from ..auth.csrf import verify_json_csrf
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
def update_soar_settings(body: SOARSettingsUpdate, database: Session = Depends(db.get_db)):
    if body.soar_execution_mode not in _VALID_SOAR_MODES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid mode '{body.soar_execution_mode}'. Allowed: {sorted(_VALID_SOAR_MODES)}",
        )
    set_setting(
        database,
        key="soar_execution_mode",
        value=body.soar_execution_mode,
        description="SOAR execution mode: manual | automatic",
        updated_by=body.updated_by or "admin",
    )
    return {
        "success": True,
        "soar_execution_mode": body.soar_execution_mode,
        "label": _SOAR_MODE_LABELS[body.soar_execution_mode],
    }
