from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from .. import db
from ..soar.response_service import (
    approve_action,
    get_history,
    get_recommendations,
    reject_action,
    run_action,
)
from ..soar.schemas import SOARApproveRequest, SOARRejectRequest, SOARRunRequest

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


@router.post("/alerts/{alert_id}/soar/executions/{execution_id}/approve")
def soar_approve(
    alert_id: int,
    execution_id: int,
    body: SOARApproveRequest,
    database: Session = Depends(db.get_db),
):
    result = approve_action(
        alert_id=alert_id,
        execution_id=execution_id,
        db=database,
        approved_by=body.approved_by or "analyst",
    )
    return result.model_dump()


@router.post("/alerts/{alert_id}/soar/executions/{execution_id}/reject")
def soar_reject(
    alert_id: int,
    execution_id: int,
    body: SOARRejectRequest,
    database: Session = Depends(db.get_db),
):
    return reject_action(
        alert_id=alert_id,
        execution_id=execution_id,
        db=database,
        rejected_by=body.rejected_by or "analyst",
    )


@router.get("/alerts/{alert_id}/soar/history")
def soar_history(alert_id: int, database: Session = Depends(db.get_db)):
    return {"history": get_history(alert_id, database)}
