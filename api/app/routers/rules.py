from fastapi import APIRouter, Depends, Request, Form
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session
from sqlalchemy import desc
from datetime import datetime
import json
from typing import Optional
from .. import models, db
from ..detection.engine.detection_engine import RuleEngine
from ..detection.engine.rule_loader import RuleLoader

router = APIRouter()
templates = Jinja2Templates(directory="templates")

# --- UI Routes ---

_SEED_RULES = [
    {
        "mitre_technique_id": "T1059",
        "name": "T1059 Suspicious Command Execution",
        "rule_type": "server",
        "severity_default": "MED",
        "mitre_technique_name": "Command and Scripting Interpreter",
        "log_type_scope": "auditd",
        "logic": {
            "match": {
                "keywords_any": ["base64", "nc", "bash -i", "sh -c", "chmod +x"],
                "patterns_any": [
                    {"name": "download_pipe_sh", "all_of": ["curl|wget", " sh"], "severity": "HIGH"},
                    {"name": "download_pipe_bash", "all_of": ["curl|wget", " bash"], "severity": "HIGH"},
                    {"name": "suspicious_downloader_sh", "all_of": ["curl|wget", ".sh"], "severity": "HIGH"},
                    {"name": "suspicious_downloader_out", "all_of": ["curl|wget", "http", "-o|-O|--output"], "severity": "MED"},
                    {"name": "base64_decode_exec", "all_of": ["base64", "bash|sh|python"], "severity": "HIGH"},
                    {"name": "netcat_shell", "all_of": ["nc", "-e|bash -i|python -c"], "severity": "HIGH"},
                ],
            },
            "exclude": {
                "keywords_any": [
                    "localhost", "127.0.0.1", "/api/agent/rules", "/api/ingest",
                    "healthcheck", "pg_isready", "antigravity", "cpuUsage.sh",
                    "/usr/share/antigravity/",
                ]
            },
            "alert": {"message": "Suspicious command execution detected.", "severity": "MED"},
        },
    },
    {
        "mitre_technique_id": "T1110",
        "name": "T1110 SSH Brute Force Authentication Failures",
        "rule_type": "server",
        "severity_default": "LOW",
        "mitre_technique_name": "Brute Force",
        "log_type_scope": "auth",
        "logic": {
            "match": {
                "keywords_any": ["Failed password", "authentication failure", "Invalid user"],
                "patterns_any": [
                    {"name": "ssh_failed_password", "all_of": ["Failed password"], "severity": "LOW"},
                    {"name": "ssh_invalid_user", "all_of": ["Invalid user"], "severity": "LOW"},
                ],
            },
            "exclude": {"keywords_any": []},
            "alert": {
                "message": "SSH authentication failure — possible brute force. Detected by YAML engine (linux_t1110_ssh_bruteforce).",
                "severity": "LOW",
            },
        },
    },
]


def _seed_rules(db_session: Session) -> None:
    """Ensure all canonical seed rules exist in the DB (idempotent)."""
    existing_ids = {
        r.mitre_technique_id
        for r in db_session.query(models.DetectionRule.mitre_technique_id).all()
    }
    for spec in _SEED_RULES:
        if spec["mitre_technique_id"] not in existing_ids:
            db_session.add(models.DetectionRule(
                name=spec["name"],
                rule_type=spec["rule_type"],
                enabled=True,
                severity_default=spec["severity_default"],
                mitre_technique_id=spec["mitre_technique_id"],
                mitre_technique_name=spec["mitre_technique_name"],
                log_type_scope=spec["log_type_scope"],
                logic_json=json.dumps(spec["logic"]),
            ))
    db_session.commit()


@router.get("/rules", response_class=HTMLResponse)
def view_rules(request: Request, db: Session = Depends(db.get_db)):
    _seed_rules(db)
    rules = db.query(models.DetectionRule).order_by(models.DetectionRule.id).all()
    loader = RuleLoader()
    yaml_rules = loader.load_rules_from_directory(loader.rules_path, include_disabled=True)
    yaml_rules.sort(key=lambda r: (r.mitre.get("tactic", {}).get("id", ""), r.id))
    return templates.TemplateResponse("rules.html", {"request": request, "rules": rules, "yaml_rules": yaml_rules})

@router.get("/rules/new", response_class=HTMLResponse)
def new_rule(request: Request):
    class DummyRule:
        id = ""
        name = ""
        rule_type = "server"
        severity_default = "MED"
        log_type_scope = "auditd"
        logic_json = '{\n  "match": {\n    "keywords_any": [],\n    "keywords_all": [],\n    "patterns_any": []\n  },\n  "exclude": {\n    "keywords_any": [],\n    "keywords_all": []\n  },\n  "alert": {\n    "message": "",\n    "severity": "MED"\n  }\n}'
    
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
            raw_logic = json.loads(r.logic_json)
            logic = RuleEngine.normalize_logic(raw_logic)
            agent_rules.append({
                "id": r.id,
                "name": r.name,
                "version": int(r.updated_at_utc.timestamp()),
                "match": logic["match"],
                "exclude": logic["exclude"]
            })
        except BaseException:
            pass

    return agent_rules
