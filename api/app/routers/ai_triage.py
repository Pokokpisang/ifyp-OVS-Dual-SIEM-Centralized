import json
import os

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import desc, func
from sqlalchemy.orm import Session

from .. import db, models
from ..ai_triage.triage_service import run_triage_for_alert
from ..auth.csrf import verify_json_csrf
from ..auth.dependencies import require_analyst_auth
from ..services import audit_service
from ..services.alert_service import get_actor_username

router = APIRouter(prefix="/api", tags=["ai-triage"])


def triage_config_status() -> dict:
    enabled = os.getenv("AI_TRIAGE_ENABLED", "false").lower() == "true"
    return {
        "enabled": enabled,
        "provider_configured": bool(os.getenv("GEMINI_API_KEY")),
        "model_name": os.getenv("GEMINI_MODEL", "gemini-2.5-flash"),
    }


def _row_to_dict(row: models.AIAlertTriage) -> dict:
    return {
        "id": row.id,
        "alert_id": row.alert_id,
        "provider": row.provider,
        "model_name": row.model_name,
        "triage_status": row.triage_status,
        "summary": row.summary,
        "priority": row.priority,
        "confidence": row.confidence,
        "false_positive_likelihood": row.false_positive_likelihood,
        "key_reasons": json.loads(row.key_reasons_json) if row.key_reasons_json else [],
        "recommended_next_steps": (
            json.loads(row.recommended_next_steps_json)
            if row.recommended_next_steps_json else []
        ),
        "soar_recommendation": (
            json.loads(row.soar_recommendation_json)
            if row.soar_recommendation_json else None
        ),
        "error_message": row.error_message,
        "created_at": row.created_at.strftime("%Y-%m-%d %H:%M:%S") if row.created_at else None,
    }


@router.post("/alerts/{alert_id}/ai-triage", dependencies=[Depends(verify_json_csrf)])
async def trigger_ai_triage(alert_id: int, request: Request, database: Session = Depends(db.get_db)):
    """Run AI triage for an alert. Advisory only — no system actions are taken."""
    row = await run_triage_for_alert(alert_id, database)
    # Audit the request only — never the prompt, raw logs, or AI response text.
    audit_service.record_audit_event(
        database,
        actor=get_actor_username(request),
        action=audit_service.AI_TRIAGE_REQUESTED,
        object_type="alert",
        object_id=alert_id,
        source_ip=audit_service.client_ip(request),
        details={"provider": row.provider, "triage_status": row.triage_status},
        commit=True,
    )
    return _row_to_dict(row)


@router.get("/alerts/{alert_id}/ai-triage/latest")
def get_latest_triage(alert_id: int, database: Session = Depends(db.get_db)):
    """Return the most recent AI triage result. Returns {triage: null} if none exists."""
    alert = database.query(models.Alert).filter(models.Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    row = (
        database.query(models.AIAlertTriage)
        .filter(models.AIAlertTriage.alert_id == alert_id)
        .order_by(models.AIAlertTriage.created_at.desc())
        .first()
    )
    return {"triage": _row_to_dict(row) if row else None}


@router.get("/ai-triage/results", dependencies=[Depends(require_analyst_auth)])
def list_triage_results(
    triage_status: str = Query("", description="Filter by triage_status; empty = all"),
    priority: str = Query(""),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    database: Session = Depends(db.get_db),
):
    """Cross-alert AI triage history (newest first). Advisory data only."""
    q = (
        database.query(models.AIAlertTriage, models.Alert)
        .join(models.Alert, models.Alert.id == models.AIAlertTriage.alert_id)
    )
    if triage_status:
        q = q.filter(models.AIAlertTriage.triage_status == triage_status)
    if priority:
        q = q.filter(models.AIAlertTriage.priority == priority)

    total = q.with_entities(func.count(models.AIAlertTriage.id)).scalar() or 0
    rows = (
        q.order_by(desc(models.AIAlertTriage.created_at), desc(models.AIAlertTriage.id))
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    status_counts = dict(
        database.query(models.AIAlertTriage.triage_status, func.count(models.AIAlertTriage.id))
        .group_by(models.AIAlertTriage.triage_status)
        .all()
    )

    results = []
    for triage, alert in rows:
        item = _row_to_dict(triage)
        item.update({
            "alert_title": alert.title,
            "alert_severity": alert.severity,
            "alert_host": alert.host,
        })
        results.append(item)

    return {
        "results": results,
        "total": total,
        "page": page,
        "page_count": max((total + page_size - 1) // page_size, 1),
        "status_counts": status_counts,
        "config": triage_config_status(),
    }
