from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from .. import db
from ..auth.csrf import verify_json_csrf
from ..auth.dependencies import require_admin_auth, require_analyst_auth
from ..soar.response_service import (
    approve_action,
    get_history,
    get_recommendations,
    reject_action,
    run_action,
)
from ..soar.schemas import SOARApproveRequest, SOARRejectRequest, SOARRunRequest
from ..services.alert_service import get_actor_username

router = APIRouter(prefix="/api", tags=["soar"])


@router.get("/alerts/{alert_id}/soar/recommendations")
def soar_recommendations(alert_id: int, database: Session = Depends(db.get_db)):
    recs = get_recommendations(alert_id, database)
    return {"recommendations": [r.model_dump() for r in recs]}


@router.post(
    "/alerts/{alert_id}/soar/run",
    dependencies=[Depends(require_analyst_auth), Depends(verify_json_csrf)],
)
def soar_run(
    request: Request,
    alert_id: int,
    body: SOARRunRequest,
    database: Session = Depends(db.get_db),
):
    # ST-027: Read actor identity from authenticated session, not request body.
    actor = get_actor_username(request, default="analyst")
    result = run_action(
        alert_id=alert_id,
        playbook_id=body.playbook_id,
        action_id=body.action_id,
        db=database,
        executed_by=actor,
    )
    return result.model_dump()


@router.post(
    "/alerts/{alert_id}/soar/executions/{execution_id}/approve",
    dependencies=[Depends(require_admin_auth), Depends(verify_json_csrf)],
)
def soar_approve(
    request: Request,
    alert_id: int,
    execution_id: int,
    body: SOARApproveRequest,
    database: Session = Depends(db.get_db),
):
    # ST-027: Read actor identity from authenticated session.
    actor = get_actor_username(request, default="analyst")
    result = approve_action(
        alert_id=alert_id,
        execution_id=execution_id,
        db=database,
        approved_by=actor,
    )
    return result.model_dump()


@router.post(
    "/alerts/{alert_id}/soar/executions/{execution_id}/reject",
    dependencies=[Depends(require_admin_auth), Depends(verify_json_csrf)],
)
def soar_reject(
    request: Request,
    alert_id: int,
    execution_id: int,
    body: SOARRejectRequest,
    database: Session = Depends(db.get_db),
):
    # ST-027: Read actor identity from authenticated session.
    actor = get_actor_username(request, default="analyst")
    return reject_action(
        alert_id=alert_id,
        execution_id=execution_id,
        db=database,
        rejected_by=actor,
    )


@router.get("/alerts/{alert_id}/soar/history")
def soar_history(alert_id: int, database: Session = Depends(db.get_db)):
    return {"history": get_history(alert_id, database)}
