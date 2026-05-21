from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from .. import models, db
from ..auth.csrf import verify_json_csrf
from typing import List

router = APIRouter(prefix="/api")

@router.get("/system-health-rules", response_model=List[models.SystemHealthRuleOut])
def get_system_health_rules(db: Session = Depends(db.get_db)):
    return db.query(models.SystemHealthRule).all()

@router.put("/system-health-rules/{rule_id}/toggle", dependencies=[Depends(verify_json_csrf)])
def toggle_system_health_rule(rule_id: str, db: Session = Depends(db.get_db)):
    rule = db.query(models.SystemHealthRule).filter(models.SystemHealthRule.rule_id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    
    rule.enabled = not rule.enabled
    db.commit()
    return {"status": "ok", "enabled": rule.enabled}

@router.put("/system-health-rules/{rule_id}", dependencies=[Depends(verify_json_csrf)])
def update_system_health_rule(rule_id: str, payload: models.SystemHealthRuleUpdate, db: Session = Depends(db.get_db)):
    rule = db.query(models.SystemHealthRule).filter(models.SystemHealthRule.rule_id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    
    if payload.enabled is not None:
        rule.enabled = payload.enabled
    if payload.threshold_value is not None:
        rule.threshold_value = payload.threshold_value
    if payload.severity is not None:
        rule.severity = payload.severity
        
    db.commit()
    return {"status": "ok"}
