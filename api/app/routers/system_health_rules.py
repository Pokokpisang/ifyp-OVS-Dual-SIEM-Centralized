from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from .. import models, db
from ..auth.csrf import verify_json_csrf
from ..services import audit_service
from ..services.alert_service import get_actor_username
from typing import List

router = APIRouter(prefix="/api")

@router.get("/system-health-rules", response_model=List[models.SystemHealthRuleOut])
def get_system_health_rules(db: Session = Depends(db.get_db)):
    return db.query(models.SystemHealthRule).order_by(models.SystemHealthRule.rule_id).all()

@router.put("/system-health-rules/{rule_id}/toggle", dependencies=[Depends(verify_json_csrf)])
def toggle_system_health_rule(rule_id: str, request: Request, db: Session = Depends(db.get_db)):
    rule = db.query(models.SystemHealthRule).filter(models.SystemHealthRule.rule_id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")

    previous = rule.enabled
    rule.enabled = not rule.enabled
    audit_service.record_audit_event(
        db,
        actor=get_actor_username(request),
        action=audit_service.SYSTEM_CONFIG_CHANGED,
        object_type="system",
        object_id=rule_id,
        source_ip=audit_service.client_ip(request),
        details={"setting": f"health_rule.{rule_id}.enabled", "from": previous, "to": rule.enabled},
    )
    db.commit()
    return {"status": "ok", "enabled": rule.enabled}

@router.put("/system-health-rules/{rule_id}", dependencies=[Depends(verify_json_csrf)])
def update_system_health_rule(rule_id: str, payload: models.SystemHealthRuleUpdate, request: Request, db: Session = Depends(db.get_db)):
    rule = db.query(models.SystemHealthRule).filter(models.SystemHealthRule.rule_id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")

    changes = {}
    if payload.enabled is not None and payload.enabled != rule.enabled:
        changes["enabled"] = f"{rule.enabled} → {payload.enabled}"
        rule.enabled = payload.enabled
    if payload.threshold_value is not None and payload.threshold_value != rule.threshold_value:
        changes["threshold_value"] = f"{rule.threshold_value} → {payload.threshold_value}"
        rule.threshold_value = payload.threshold_value
    if payload.severity is not None and payload.severity != rule.severity:
        changes["severity"] = f"{rule.severity} → {payload.severity}"
        rule.severity = payload.severity

    if changes:
        audit_service.record_audit_event(
            db,
            actor=get_actor_username(request),
            action=audit_service.SYSTEM_CONFIG_CHANGED,
            object_type="system",
            object_id=rule_id,
            source_ip=audit_service.client_ip(request),
            details={"setting": f"health_rule.{rule_id}", **changes},
        )
    db.commit()
    return {"status": "ok"}
