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
from ..services import audit_service
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
        source_ip=audit_service.client_ip(request),
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
        source_ip=audit_service.client_ip(request),
        decision_note=body.note,
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
        source_ip=audit_service.client_ip(request),
        decision_note=body.note,
    )


@router.get("/alerts/{alert_id}/soar/history")
def soar_history(alert_id: int, database: Session = Depends(db.get_db)):
    return {"history": get_history(alert_id, database)}


@router.get("/soar/pending", dependencies=[Depends(require_analyst_auth)])
def soar_pending(database: Session = Depends(db.get_db)):
    """Cross-alert queue of executions awaiting admin approval."""
    from .. import models

    rows = (
        database.query(models.SOARActionExecution, models.Alert)
        .join(models.Alert, models.Alert.id == models.SOARActionExecution.alert_id)
        .filter(models.SOARActionExecution.status == "pending_approval")
        .order_by(models.SOARActionExecution.id.desc())
        .limit(100)
        .all()
    )
    pending = []
    for exec_record, alert in rows:
        pending.append({
            "execution_id": exec_record.id,
            "alert_id": alert.id,
            "alert_title": alert.title,
            "alert_severity": alert.severity,
            "alert_host": alert.host,
            "playbook_id": exec_record.playbook_id,
            "playbook_name": exec_record.playbook_name,
            "action_id": exec_record.action_id,
            "action_name": exec_record.action_name,
            "action_type": exec_record.action_type,
            "target": exec_record.target,
            "mode": exec_record.mode,
            "requested_by": exec_record.executed_by,
            "requested_at": exec_record.executed_at.strftime("%Y-%m-%d %H:%M:%S") if exec_record.executed_at else None,
        })
    return {"pending": pending, "total": len(pending)}


@router.get("/soar/playbooks", dependencies=[Depends(require_analyst_auth)])
def soar_playbooks():
    """Loaded YAML playbook catalog (read-only; playbooks are files on disk)."""
    from ..soar.playbook_loader import PlaybookLoader

    playbooks = PlaybookLoader().load_all_playbooks()
    return {"playbooks": [{
        "id": p.id,
        "name": p.name,
        "description": p.description,
        "enabled": p.enabled,
        "mode": "simulation",
        "action_count": len(p.actions),
        "approval_required_count": sum(1 for a in p.actions if a.requires_approval),
        "auto_run_count": sum(1 for a in p.actions if a.automation.auto_run_allowed),
        "actions": [{
            "id": a.id, "name": a.name, "type": a.type,
            "requires_approval": a.requires_approval,
            "auto_run_allowed": a.automation.auto_run_allowed,
            "rollback_supported": a.rollback_supported,
        } for a in p.actions],
    } for p in playbooks], "simulation_only": True}
