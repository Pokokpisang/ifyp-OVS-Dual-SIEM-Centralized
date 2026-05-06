from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from .. import db
from ..soar.response_service import get_history, get_recommendations, run_action
from ..soar.schemas import SOARRunRequest

router = APIRouter(prefix="/api", tags=["soar"])


@router.get("/alerts/{alert_id}/soar/recommendations")
def soar_recommendations(alert_id: int, database: Session = Depends(db.get_db)):
    recs = get_recommendations(alert_id, database)
    return {"recommendations": [r.model_dump() for r in recs]}


@router.post("/alerts/{alert_id}/soar/run")
def soar_run(
    alert_id: int,
    body: SOARRunRequest,
    database: Session = Depends(db.get_db),
):
    result = run_action(
        alert_id=alert_id,
        playbook_id=body.playbook_id,
        action_id=body.action_id,
        db=database,
        executed_by=body.executed_by or "analyst",
    )
    return result.model_dump()


@router.get("/alerts/{alert_id}/soar/history")
def soar_history(alert_id: int, database: Session = Depends(db.get_db)):
    return {"history": get_history(alert_id, database)}
