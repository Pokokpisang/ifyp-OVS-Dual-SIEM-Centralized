"""
routers/clients.py — tenant (client) management, SOC side.

Routes
------
GET    /clients                          HTML list (analyst+ read)
GET    /clients/{id}                     HTML detail (analyst+ read)
GET    /api/clients                      List + rollups (analyst+)
POST   /api/clients                      Create (admin)
PUT    /api/clients/{id}                 Update fields (admin)
DELETE /api/clients/{id}                 Delete; agents become unassigned (admin)
POST   /api/clients/{id}/api-key         Issue/rotate portal API key (admin) — raw key returned ONCE
DELETE /api/clients/{id}/api-key         Revoke portal API key (admin)
PUT    /api/clients/{id}/agents          Assign agents (admin)
DELETE /api/clients/{id}/agents/{agent_id}  Unassign one agent (admin)

Every mutation is audited. The raw API key is never stored, logged, or
audited — only the fact of rotation.
"""
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from sqlalchemy.orm import Session

from .. import db, models
from ..auth.csrf import verify_json_csrf
from ..auth.dependencies import require_admin_auth, require_analyst_auth, require_analyst_html
from ..services import audit_service, client_service
from ..services.agent_service import compute_agent_status
from ..services.alert_service import get_actor_username

router = APIRouter()
templates = Jinja2Templates(directory="templates")


class ClientCreate(BaseModel):
    name: str
    org_type: str = "Hosting Provider"
    contact_name: str = ""
    contact_email: str = ""
    status: str = "active"


class ClientUpdate(BaseModel):
    name: Optional[str] = None
    org_type: Optional[str] = None
    contact_name: Optional[str] = None
    contact_email: Optional[str] = None
    status: Optional[str] = None


class AgentAssignment(BaseModel):
    agent_ids: List[str]


def _audit(database: Session, request: Request, action: str, client: models.Client, details: dict):
    audit_service.record_audit_event(
        database,
        actor=get_actor_username(request),
        action=action,
        object_type="client",
        object_id=client.id,
        source_ip=audit_service.client_ip(request),
        details={"client": client.name, **details},
    )


# ---------------------------------------------------------------------------
# HTML pages
# ---------------------------------------------------------------------------

@router.get("/clients", response_class=HTMLResponse, dependencies=[Depends(require_analyst_html)])
def view_clients(request: Request, database: Session = Depends(db.get_db)):
    user_role = (getattr(request.state, "user", None) or {}).get("role", "client")
    return templates.TemplateResponse("clients.html", {
        "request": request,
        "is_admin": user_role == "admin",
        "org_types": client_service.ORG_TYPES,
        "statuses": client_service.STATUSES,
    })


@router.get("/clients/{client_id}", response_class=HTMLResponse, dependencies=[Depends(require_analyst_html)])
def view_client_detail(client_id: int, request: Request, database: Session = Depends(db.get_db)):
    try:
        client = client_service.get_client(database, client_id)
    except client_service.ClientServiceError:
        raise HTTPException(status_code=404, detail="Client not found")

    agents = client_service.client_agents(database, client_id)
    agent_rows = [{
        "agent_id": a.agent_id,
        "agent_name": a.agent_name,
        "hostname": a.hostname,
        "ip_address": a.ip_address,
        "status": compute_agent_status(a),
        "last_seen": a.last_seen.strftime("%Y-%m-%d %H:%M") if a.last_seen else "never",
    } for a in agents]

    alerts = (
        client_service.client_alerts_query(database, client_id)
        .order_by(models.Alert.timestamp.desc())
        .limit(25)
        .all()
    )
    unassigned = (
        database.query(models.AgentRecord)
        .filter(models.AgentRecord.client_id == None,  # noqa: E711
                models.AgentRecord.is_deleted == False)  # noqa: E712
        .order_by(models.AgentRecord.agent_name)
        .all()
    )
    user_role = (getattr(request.state, "user", None) or {}).get("role", "client")
    return templates.TemplateResponse("client_detail.html", {
        "request": request,
        "client": client_service.client_rollup(database, client),
        "agents": agent_rows,
        "alerts": alerts,
        "unassigned_agents": [{"agent_id": a.agent_id, "agent_name": a.agent_name} for a in unassigned],
        "is_admin": user_role == "admin",
        "org_types": client_service.ORG_TYPES,
        "statuses": client_service.STATUSES,
    })


# ---------------------------------------------------------------------------
# JSON API
# ---------------------------------------------------------------------------

@router.get("/api/clients", dependencies=[Depends(require_analyst_auth)])
def api_list_clients(database: Session = Depends(db.get_db)):
    return {"clients": [client_service.client_rollup(database, c)
                        for c in client_service.list_clients(database)]}


@router.post("/api/clients", dependencies=[Depends(require_admin_auth), Depends(verify_json_csrf)])
def api_create_client(body: ClientCreate, request: Request, database: Session = Depends(db.get_db)):
    try:
        client = client_service.create_client(
            database, name=body.name, org_type=body.org_type,
            contact_name=body.contact_name, contact_email=body.contact_email,
            status=body.status,
        )
    except client_service.ClientServiceError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    _audit(database, request, audit_service.CLIENT_CREATED, client,
           {"org_type": client.org_type, "status": client.status})
    database.commit()
    return {"status": "ok", "client": client_service.client_rollup(database, client)}


@router.put("/api/clients/{client_id}", dependencies=[Depends(require_admin_auth), Depends(verify_json_csrf)])
def api_update_client(client_id: int, body: ClientUpdate, request: Request, database: Session = Depends(db.get_db)):
    try:
        client, changes = client_service.update_client(database, client_id, **body.model_dump())
    except client_service.ClientServiceError as exc:
        raise HTTPException(status_code=400 if "not found" not in str(exc) else 404, detail=str(exc))
    if changes:
        _audit(database, request, audit_service.CLIENT_UPDATED, client, changes)
    database.commit()
    return {"status": "ok", "client": client_service.client_rollup(database, client)}


@router.delete("/api/clients/{client_id}", dependencies=[Depends(require_admin_auth), Depends(verify_json_csrf)])
def api_delete_client(client_id: int, request: Request, database: Session = Depends(db.get_db)):
    try:
        client = client_service.delete_client(database, client_id)
    except client_service.ClientServiceError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    _audit(database, request, audit_service.CLIENT_DELETED, client,
           {"note": "agents unassigned, data retained"})
    database.commit()
    return {"status": "ok"}


@router.post("/api/clients/{client_id}/api-key", dependencies=[Depends(require_admin_auth), Depends(verify_json_csrf)])
def api_issue_key(client_id: int, request: Request, database: Session = Depends(db.get_db)):
    try:
        client, raw_key = client_service.issue_api_key(database, client_id)
    except client_service.ClientServiceError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    _audit(database, request, audit_service.CLIENT_KEY_ROTATED, client,
           {"key_visible": "false", "portal_api_key": "__SENSITIVE__"})
    database.commit()
    # Raw key in the response body ONLY — shown once, never persisted.
    return {"status": "ok", "api_key": raw_key,
            "note": "Store this key now — it cannot be retrieved again."}


@router.delete("/api/clients/{client_id}/api-key", dependencies=[Depends(require_admin_auth), Depends(verify_json_csrf)])
def api_revoke_key(client_id: int, request: Request, database: Session = Depends(db.get_db)):
    try:
        client = client_service.revoke_api_key(database, client_id)
    except client_service.ClientServiceError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    _audit(database, request, audit_service.CLIENT_KEY_REVOKED, client, {})
    database.commit()
    return {"status": "ok"}


@router.put("/api/clients/{client_id}/agents", dependencies=[Depends(require_admin_auth), Depends(verify_json_csrf)])
def api_assign_agents(client_id: int, body: AgentAssignment, request: Request, database: Session = Depends(db.get_db)):
    try:
        client = client_service.get_client(database, client_id)
    except client_service.ClientServiceError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    assigned = client_service.assign_agents(database, client_id, body.agent_ids)
    if assigned:
        _audit(database, request, audit_service.CLIENT_AGENTS_CHANGED, client,
               {"assigned": ", ".join(assigned[:10]), "count": len(assigned)})
    database.commit()
    return {"status": "ok", "assigned": assigned}


@router.delete("/api/clients/{client_id}/agents/{agent_id}", dependencies=[Depends(require_admin_auth), Depends(verify_json_csrf)])
def api_unassign_agent(client_id: int, agent_id: str, request: Request, database: Session = Depends(db.get_db)):
    try:
        client = client_service.get_client(database, client_id)
    except client_service.ClientServiceError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    if not client_service.unassign_agent(database, agent_id):
        raise HTTPException(status_code=404, detail="Agent not found")
    _audit(database, request, audit_service.CLIENT_AGENTS_CHANGED, client,
           {"unassigned": agent_id})
    database.commit()
    return {"status": "ok"}
