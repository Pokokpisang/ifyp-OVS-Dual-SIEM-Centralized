"""
routers/rules.py — detection rules + MITRE coverage.

Routes
------
GET /rules                                   Legacy redirect → /detection/rules
GET /detection/rules                         HTML rules table (analyst+; toggle admin-only)
GET /detection/mitre                         HTML MITRE coverage matrix (analyst+)
GET /api/detection/rules                     JSON rules + stats + override state (analyst+)
PUT /api/detection/rules/{rule_id}/toggle    Runtime enable/disable (admin, audited)
GET /api/detection/mitre-coverage            Coverage aggregation (analyst+)

Rules are YAML files (detection-as-code) — there are no create/edit
endpoints. The toggle writes a runtime override that can only DISABLE a
file-enabled rule; the YAML `enabled` flag stays authoritative.
"""
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import func
from sqlalchemy.orm import Session

from .. import db, models
from ..auth.csrf import verify_json_csrf
from ..auth.dependencies import require_admin_auth, require_analyst_html, require_analyst_auth
from ..detection.engine.rule_loader import RuleLoader
from ..services import audit_service
from ..services.alert_service import get_actor_username
from ..services.rule_override_service import get_disabled_rule_ids, invalidate_cache, set_rule_enabled

router = APIRouter()
templates = Jinja2Templates(directory="templates")

# Canonical ATT&CK Enterprise tactic order for the coverage matrix.
_TACTIC_ORDER = [
    "TA0043", "TA0042", "TA0001", "TA0002", "TA0003", "TA0004", "TA0005",
    "TA0006", "TA0007", "TA0008", "TA0009", "TA0011", "TA0010", "TA0040",
]


def _load_rules():
    loader = RuleLoader()
    rules = loader.load_rules_from_directory(loader.rules_path, include_disabled=True)
    rules.sort(key=lambda r: (r.mitre.get("tactic", {}).get("id", ""), r.id))
    return rules, loader.errors


def _alert_stats(database: Session, days: int = 30) -> dict:
    """rule_id -> {count, last} over the window."""
    since = datetime.utcnow() - timedelta(days=days)
    rows = (
        database.query(
            models.Alert.rule_id,
            func.count(models.Alert.id),
            func.max(models.Alert.timestamp),
        )
        .filter(models.Alert.rule_id != None, models.Alert.timestamp >= since)  # noqa: E711
        .group_by(models.Alert.rule_id)
        .all()
    )
    return {r[0]: {"count": r[1], "last": r[2]} for r in rows}


def _rules_view(database: Session) -> tuple:
    rules, errors = _load_rules()
    disabled_ids = get_disabled_rule_ids(database)
    stats = _alert_stats(database)
    view = []
    for rule in rules:
        stat = stats.get(rule.id, {})
        override_disabled = rule.id in disabled_ids
        view.append({
            "rule": rule,
            "alert_count_30d": stat.get("count", 0),
            "last_alert": stat.get("last"),
            "override_disabled": override_disabled,
            "effective_enabled": rule.enabled and not override_disabled,
        })
    return view, errors


@router.get("/rules", include_in_schema=False)
def redirect_rules():
    """Legacy path — detection rules moved under /detection/rules."""
    return RedirectResponse(url="/detection/rules", status_code=302)


@router.get(
    "/detection/rules",
    response_class=HTMLResponse,
    dependencies=[Depends(require_analyst_html)],
)
def view_rules(request: Request, database: Session = Depends(db.get_db)):
    rules_view, errors = _rules_view(database)
    user_role = (getattr(request.state, "user", None) or {}).get("role", "client")
    return templates.TemplateResponse("rules.html", {
        "request": request,
        "rules_view": rules_view,
        "loader_errors": errors,
        "is_admin": user_role == "admin",
    })


@router.get("/api/detection/rules", dependencies=[Depends(require_analyst_auth)])
def api_list_rules(database: Session = Depends(db.get_db)):
    rules_view, errors = _rules_view(database)
    return {
        "rules": [{
            "id": row["rule"].id,
            "name": row["rule"].name,
            "severity": row["rule"].severity.value,
            "risk_score": row["rule"].risk_score,
            "platform": row["rule"].platform,
            "mitre": row["rule"].mitre,
            "file_enabled": row["rule"].enabled,
            "override_disabled": row["override_disabled"],
            "effective_enabled": row["effective_enabled"],
            "alert_count_30d": row["alert_count_30d"],
            "last_alert": row["last_alert"].strftime("%Y-%m-%d %H:%M:%S") if row["last_alert"] else None,
        } for row in rules_view],
        "loader_errors": errors,
    }


@router.put(
    "/api/detection/rules/{rule_id}/toggle",
    dependencies=[Depends(require_admin_auth), Depends(verify_json_csrf)],
)
def toggle_rule(rule_id: str, request: Request, database: Session = Depends(db.get_db)):
    rules, _ = _load_rules()
    rule = next((r for r in rules if r.id == rule_id), None)
    if rule is None:
        raise HTTPException(status_code=404, detail="Rule not found")
    if not rule.enabled:
        raise HTTPException(
            status_code=400,
            detail="Rule is disabled in its YAML file — edit the file to enable it (detection-as-code).",
        )

    currently_disabled = rule_id in get_disabled_rule_ids(database)
    new_enabled = currently_disabled  # flip
    actor = get_actor_username(request)
    set_rule_enabled(database, rule_id, new_enabled, updated_by=actor)
    audit_service.record_audit_event(
        database,
        actor=actor,
        action=audit_service.DETECTION_RULE_TOGGLED,
        object_type="detection_rule",
        object_id=rule_id,
        source_ip=audit_service.client_ip(request),
        details={
            "rule_name": rule.name,
            "from": "disabled" if currently_disabled else "enabled",
            "to": "enabled" if new_enabled else "disabled",
        },
    )
    database.commit()
    invalidate_cache()
    return {"status": "ok", "rule_id": rule_id, "effective_enabled": new_enabled}


def _coverage(database: Session) -> dict:
    rules, _ = _load_rules()
    disabled_ids = get_disabled_rule_ids(database)
    tactics: dict = {}
    for rule in rules:
        tactic = rule.mitre.get("tactic") or {}
        tech = rule.mitre.get("subtechnique") or rule.mitre.get("technique") or {}
        t_id, t_name = tactic.get("id", "unknown"), tactic.get("name", "Unknown")
        bucket = tactics.setdefault(t_id, {"id": t_id, "name": t_name, "techniques": {}})
        tech_id = tech.get("id", "—")
        entry = bucket["techniques"].setdefault(tech_id, {
            "id": tech_id, "name": tech.get("name", ""), "rules": 0, "enabled_rules": 0,
        })
        entry["rules"] += 1
        if rule.enabled and rule.id not in disabled_ids:
            entry["enabled_rules"] += 1

    ordered = sorted(
        tactics.values(),
        key=lambda t: _TACTIC_ORDER.index(t["id"]) if t["id"] in _TACTIC_ORDER else 99,
    )
    for t in ordered:
        t["techniques"] = sorted(t["techniques"].values(), key=lambda x: x["id"])
    return {
        "tactics": ordered,
        "total_rules": len(rules),
        "total_techniques": sum(len(t["techniques"]) for t in ordered),
        "covered_tactics": len(ordered),
        "tactic_universe": len(_TACTIC_ORDER),
    }


@router.get("/api/detection/mitre-coverage", dependencies=[Depends(require_analyst_auth)])
def api_mitre_coverage(database: Session = Depends(db.get_db)):
    return _coverage(database)


@router.get(
    "/detection/mitre",
    response_class=HTMLResponse,
    dependencies=[Depends(require_analyst_html)],
)
def view_mitre_coverage(request: Request, database: Session = Depends(db.get_db)):
    return templates.TemplateResponse("mitre_coverage.html", {
        "request": request,
        "coverage": _coverage(database),
    })
