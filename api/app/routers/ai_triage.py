import json

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from .. import db, models
from ..ai_triage.triage_service import run_triage_for_alert
from ..auth.csrf import verify_json_csrf
from ..services import audit_service
from ..services.alert_service import get_actor_username

router = APIRouter(prefix="/api", tags=["ai-triage"])


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
