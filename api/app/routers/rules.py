from fastapi import APIRouter, Depends, Request, Form
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session
from sqlalchemy import desc
from datetime import datetime
import json
from typing import Optional
from .. import models, db

router = APIRouter()
templates = Jinja2Templates(directory="templates")

# --- UI Routes ---

@router.get("/rules", response_class=HTMLResponse)
def view_rules(request: Request, db: Session = Depends(db.get_db)):
    rules = db.query(models.DetectionRule).order_by(models.DetectionRule.id).all()
    # Ensure default rule exists (simple seed check)
    if not rules:
        logic = {
            "keywords": ["curl", "wget", "base64", "nc", "python", "bash -i", "sh -c", "chmod +x"],
            "patterns": [
                {"name": "download_pipe_shell", "all_of": ["curl|wget", "| sh| | bash|chmod +x"], "severity": "HIGH"},
                {"name": "suspicious_downloader", "all_of": ["curl|wget", ".sh|http://|https://"], "severity": "MED"},
                {"name": "base64_decode_exec", "all_of": ["base64", "bash|sh|python"], "severity": "HIGH"},
                {"name": "netcat_shell", "all_of": ["nc", "-e|bash -i|python -c"], "severity": "HIGH"}
            ]
        }
        default_rule = models.DetectionRule(
            name="T1059 Suspicious Command Execution",
            rule_type="server",
            enabled=True,
            severity_default="MED",
            mitre_technique_id="T1059",
            mitre_technique_name="Command and Scripting Interpreter",
            log_type_scope="auditd",
            logic_json=json.dumps(logic)
        )
        db.add(default_rule)
        db.commit()
        rules = [default_rule]

    return templates.TemplateResponse("rules.html", {"request": request, "rules": rules})

@router.get("/rules/new", response_class=HTMLResponse)
def new_rule(request: Request):
    class DummyRule:
        id = ""
        name = ""
        rule_type = "agent"
        severity_default = "MED"
        log_type_scope = "auditd"
        logic_json = '{\n  "keywords": [],\n  "patterns": []\n}'
    
    return templates.TemplateResponse("rule_edit.html", {"request": request, "rule": DummyRule()})

@router.get("/rules/{id}", response_class=HTMLResponse)
def edit_rule(id: int, request: Request, db: Session = Depends(db.get_db)):
    rule = db.query(models.DetectionRule).filter(models.DetectionRule.id == id).first()
    return templates.TemplateResponse("rule_edit.html", {"request": request, "rule": rule})

# --- JSON/Action Routes ---

@router.post("/api/rules/{id}/toggle")
def toggle_rule(id: int, db: Session = Depends(db.get_db)):
    rule = db.query(models.DetectionRule).filter(models.DetectionRule.id == id).first()
    if rule:
        rule.enabled = not rule.enabled
        rule.updated_at_utc = datetime.utcnow()
        
        # Audit
        audit = models.ActivityAudit(
            actor="admin",
            action="RULE_ENABLED" if rule.enabled else "RULE_DISABLED",
            object_type="rule",
            object_id=str(rule.id)
        )
        db.add(audit)
        db.commit()
    return {"status": "ok", "enabled": rule.enabled}

@router.post("/rules/save")
def save_rule(
    name: str = Form(...),
    rule_type: str = Form(...),
    severity: str = Form(...),
    logic: str = Form(...),
    id: Optional[str] = Form(None),
    db: Session = Depends(db.get_db)
):
    if id and id.strip():
        rule = db.query(models.DetectionRule).filter(models.DetectionRule.id == int(id)).first()
        if rule:
            rule.name = name
            rule.rule_type = rule_type
            rule.severity_default = severity
            rule.logic_json = logic
            rule.updated_at_utc = datetime.utcnow()
            
            audit = models.ActivityAudit(
                actor="admin",
                action="RULE_UPDATED",
                object_type="rule",
                object_id=str(rule.id),
                details=f"Updated logic"
            )
            db.add(audit)
    else:
        rule = models.DetectionRule(
            name=name,
            rule_type=rule_type,
            enabled=True,
            severity_default=severity,
            mitre_technique_id="Custom",
            mitre_technique_name="Custom User Rule",
            log_type_scope="syslog",
            logic_json=logic
        )
        db.add(rule)
        db.commit()
        
        audit = models.ActivityAudit(
            actor="admin",
            action="RULE_CREATED",
            object_type="rule",
            object_id=str(rule.id),
            details=f"Created custom rule"
        )
        db.add(audit)

    db.commit()
    return RedirectResponse(url="/rules", status_code=303)

@router.get("/api/agent/rules")
def get_agent_rules(db: Session = Depends(db.get_db)):
    rules = db.query(models.DetectionRule).filter(
        models.DetectionRule.rule_type == "agent",
        models.DetectionRule.enabled == True
    ).all()
    
    agent_rules = []
    for r in rules:
        try:
            logic = json.loads(r.logic_json)
            # Send a structured representation down to the agent
            # version is currently just mapped to id for uniqueness or we could use updated_at timestamp
            agent_rules.append({
                "id": r.id,
                "name": r.name,
                "version": int(r.updated_at_utc.timestamp()),
                "keywords": logic.get("keywords", []),
                "patterns": logic.get("patterns", [])
            })
        except BaseException:
            pass

    return agent_rules
