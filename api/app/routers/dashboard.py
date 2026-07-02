from fastapi import APIRouter, Request, Depends, Query, HTTPException, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from sqlalchemy import desc
from .. import models, db
import math
import os
from ..auth.csrf import verify_form_csrf
from ..auth.dependencies import require_admin_auth
from ..services.agent_service import (
    create_agent, compute_agent_status,
    get_agent_by_id, delete_agent_by_id, purge_agent_by_id,
    get_latest_agent_metrics, get_recent_agent_alerts, get_recent_agent_logs,
)
from ..services.server_address import get_server_address, normalize_server_url, validate_server_address
from ..services import audit_service, dashboard_service
from ..services.alert_service import get_actor_username

router = APIRouter()
templates = Jinja2Templates(directory="templates")

@router.get("/dashboard")
def view_dashboard(request: Request, db: Session = Depends(db.get_db)):
    # Get list of hosts for dropdown
    hosts = db.query(models.Metric.host).distinct().all()
    host_list = [h[0] for h in hosts]
    return templates.TemplateResponse("dashboard.html", {"request": request, "hosts": host_list})
@router.get("/system-health-rules", response_class=HTMLResponse)
def view_system_health_rules(request: Request, db: Session = Depends(db.get_db)):
    rules = db.query(models.SystemHealthRule).all()
    return templates.TemplateResponse("system_health_rules.html", {"request": request, "rules": rules})

@router.get("/alerts", response_class=HTMLResponse)
def view_alerts(
    request: Request,
    page: int = 1,
    severity: str = "",
    source: str = "",
    host: str = "",
    read_status: str = "all",
    db: Session = Depends(db.get_db)
):
    limit = 50
    offset = (page - 1) * limit

    query = db.query(models.Alert)

    if severity:
        query = query.filter(models.Alert.severity == severity)
    if source:
        query = query.filter(models.Alert.source == source)
    if host:
        query = query.filter(models.Alert.host == host)
    if read_status == "unread":
        query = query.filter(models.Alert.is_read == False)
    elif read_status == "read":
        query = query.filter(models.Alert.is_read == True)

    total_count = query.count()
    alerts = query.order_by(desc(models.Alert.timestamp)).offset(offset).limit(limit).all()

    # Get unique values for filters
    hosts = [r[0] for r in db.query(models.Alert.host).distinct().all()]
    sources = [r[0] for r in db.query(models.Alert.source).distinct().all()]
    severities = ["HIGH", "MED", "LOW"]

    total_pages = math.ceil(total_count / limit)

    return templates.TemplateResponse("alerts.html", {
        "request": request,
        "alerts": alerts,
        "page": page,
        "total_pages": total_pages,
        "total_count": total_count,
        "current_severity": severity,
        "current_source": source,
        "current_host": host,
        "current_read_status": read_status,
        "hosts": hosts,
        "sources": sources,
        "severities": severities
    })

@router.get("/logs")
def view_logs(
    request: Request, 
    page: int = 1, 
    q: str = "", 
    host: str = "", 
    log_type: str = "",
    db: Session = Depends(db.get_db)
):
    page_size = 50
    query = db.query(models.Log)
    
    if q:
        query = query.filter(models.Log.message.ilike(f"%{q}%"))
    if host:
        query = query.filter(models.Log.host == host)
    if log_type:
        query = query.filter(models.Log.log_type == log_type)
        
    total_count = query.count()
    total_pages = math.ceil(total_count / page_size)
    
    logs = query.order_by(desc(models.Log.timestamp)) \
                .offset((page - 1) * page_size) \
                .limit(page_size) \
                .all()
                
    # Get filter options
    hosts = [h[0] for h in db.query(models.Log.host).distinct().all()]
    types = [t[0] for t in db.query(models.Log.log_type).distinct().all()]

    return templates.TemplateResponse("logs.html", {
        "request": request, 
        "logs": logs,
        "page": page,
        "total_pages": total_pages,
        "total_count": total_count,
        "q": q,
        "current_host": host,
        "current_type": log_type,
        "hosts": hosts,
        "types": types
    })

# ---------------------------------------------------------------------------
# GET /agents — Agent list (merges AgentRecord with metric data)
# ---------------------------------------------------------------------------
@router.get("/agents")
def view_agents(
    request: Request,
    page: int = 1,
    q: str = "",
    status_filter: str = "All",
    database: Session = Depends(db.get_db)
):
    ctx = dashboard_service.build_agents_view(
        database, q=q, status_filter=status_filter, page=page
    )
    return templates.TemplateResponse("agents.html", {"request": request, **ctx})


# ---------------------------------------------------------------------------
# GET /agents/new — Render agent creation form
# ---------------------------------------------------------------------------
@router.get("/agents/new", response_class=HTMLResponse)
def view_agents_new(request: Request, database: Session = Depends(db.get_db)):
    raw_server = get_server_address(request)
    port = int(os.getenv("SIEM_API_PORT", "8000"))
    normalized = normalize_server_url(raw_server, port)
    _, warning = validate_server_address(normalized)

    return templates.TemplateResponse("agents_new.html", {
        "request": request,
        "siem_server_address": normalized,
        "siem_port": port,
        "localhost_warning": warning,
        "install_command": None,
        "created_agent": None,
    })


# ---------------------------------------------------------------------------
# POST /agents/new — Create agent record, display install command
# ---------------------------------------------------------------------------
@router.post("/agents/new", response_class=HTMLResponse)
def submit_agents_new(
    request: Request,
    agent_name: str = Form(...),
    group: str = Form("Default Group"),
    tags: str = Form(""),
    distribution: str = Form("Ubuntu"),
    architecture: str = Form("x86_64"),
    enable_logs: bool = Form(False),
    enable_fim: bool = Form(False),
    enable_metrics: bool = Form(False),
    database: Session = Depends(db.get_db),
):
    from ..services.installer_service import get_install_command
    import traceback

    try:
        raw_server = get_server_address(request)
        port = int(os.getenv("SIEM_API_PORT", "8000"))
        normalized = normalize_server_url(raw_server, port)
        _, warning = validate_server_address(normalized)

        print(f"DEBUG: Registering agent {agent_name} with logs={enable_logs}, fim={enable_fim}, metrics={enable_metrics}")

        agent, raw_token = create_agent(
            agent_name=agent_name,
            group=group,
            tags=tags,
            os_type="Linux",
            distribution=distribution,
            architecture=architecture,
            enable_logs=enable_logs,
            enable_fim=enable_fim,
            enable_metrics=enable_metrics,
            db=database,
        )

        install_cmd = get_install_command(
            server=normalized,
            port=port,
            token=raw_token,
            name=agent_name,
            enable_logs=enable_logs,
            enable_fim=enable_fim,
            enable_metrics=enable_metrics,
        )

        return templates.TemplateResponse("agents_new.html", {
            "request": request,
            "siem_server_address": normalized,
            "siem_port": port,
            "localhost_warning": warning,
            "install_command": install_cmd,
            "created_agent": {
                "agent_name": agent.agent_name,
                "agent_id": agent.agent_id,
                "token_expires_in": "1 hour",
            },
        })
    except Exception as e:
        print("ERROR in submit_agents_new:")
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/alerts/{alert_id}/investigation", response_class=HTMLResponse)
def view_investigation(alert_id: int, request: Request, db: Session = Depends(db.get_db)):
    """HTML page for a single alert investigation."""
    alert = db.query(models.Alert).filter(models.Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert #{alert_id} not found")

    assessment = db.query(models.AlertAssessment).filter(
        models.AlertAssessment.alert_id == alert_id
    ).first()

    user_role = (getattr(request.state, "user", None) or {}).get("role", "client")
    return templates.TemplateResponse("alert_investigation.html", {
        "request": request,
        "alert": alert,
        "assessment": assessment,
        "user_role": user_role,
    })


@router.get("/agents/history", response_class=HTMLResponse)
def view_agents_history(
    request: Request,
    page: int = 1,
    q: str = "",
    lifecycle_filter: str = "all",
    database: Session = Depends(db.get_db),
):
    ctx = dashboard_service.build_agents_history_view(
        database, q=q, lifecycle_filter=lifecycle_filter, page=page
    )
    return templates.TemplateResponse("agents_history.html", {"request": request, **ctx})


@router.get("/network", response_class=HTMLResponse)
def view_network(request: Request, database: Session = Depends(db.get_db)):
    """Network Investigation page — agent network status, suspicious activity, SOAR actions."""
    ctx = dashboard_service.build_network_view(database)
    return templates.TemplateResponse("network_investigation.html", {"request": request, **ctx})


@router.get("/soar/settings", response_class=HTMLResponse)
def view_soar_settings(request: Request):
    return templates.TemplateResponse("soar_settings.html", {"request": request})


@router.get("/soar/history", response_class=HTMLResponse)
def view_soar_history(
    request: Request,
    status: str | None = None,
    mode: str | None = None,
    action_type: str | None = None,
    alert_id: int | None = None,
    database: Session = Depends(db.get_db),
):
    ctx = dashboard_service.build_soar_history_view(
        database, status=status, mode=mode, action_type=action_type, alert_id=alert_id
    )
    return templates.TemplateResponse("soar_history.html", {"request": request, **ctx})


@router.get("/agents/{agent_id}", response_class=HTMLResponse)
def get_agent_detail(
    request: Request,
    agent_id: str,
    reinstall: bool = Query(False),
    database: Session = Depends(db.get_db),
):
    from ..services.agent_service import regenerate_agent_token
    from ..services.installer_service import get_reinstall_command

    agent = get_agent_by_id(agent_id, database)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    status = compute_agent_status(agent)

    # Data matched by hostname (fallback to agent_name if hostname not yet filled)
    host_id = agent.hostname or agent.agent_name
    metrics = get_latest_agent_metrics(host_id, database)
    alerts = get_recent_agent_alerts(host_id, database, limit=5)
    logs = get_recent_agent_logs(host_id, database, limit=20)

    reinstall_cmd = None
    if reinstall:
        new_token = regenerate_agent_token(agent_id, database)
        # Audit the key rotation — never store the new token/key itself.
        audit_service.record_audit_event(
            database,
            actor=get_actor_username(request),
            action=audit_service.AGENT_KEY_ROTATED,
            object_type="agent",
            object_id=agent_id,
            details={"agent_id": agent_id},
            commit=True,
        )
        raw_server = get_server_address(request)
        port = int(os.getenv("SIEM_API_PORT", "8000"))
        normalized = normalize_server_url(raw_server, port)

        reinstall_cmd = get_reinstall_command(
            server=normalized,
            port=port,
            token=new_token,
            name=agent.agent_name,
            enable_logs=agent.enable_logs,
            enable_fim=agent.enable_fim,
            enable_metrics=agent.enable_metrics,
        )

    # Standalone uninstall command
    raw_server = get_server_address(request)
    port = int(os.getenv("SIEM_API_PORT", "8000"))
    normalized = normalize_server_url(raw_server, port)
    uninstall_cmd = f"curl -s {normalized}/uninstall.sh | sudo bash"

    return templates.TemplateResponse("agents_detail.html", {
        "request": request,
        "agent": agent,
        "status": status,
        "metrics": metrics,
        "alerts": alerts,
        "logs": logs,
        "reinstall_command": reinstall_cmd,
        "uninstall_command": uninstall_cmd,
    })


@router.post(
    "/agents/{agent_id}/delete",
    dependencies=[Depends(require_admin_auth), Depends(verify_form_csrf)],
)
def delete_agent(
    agent_id: str,
    reason: str = Form(""),
    database: Session = Depends(db.get_db),
):
    success = delete_agent_by_id(agent_id, database, reason=reason or None)
    if not success:
        raise HTTPException(status_code=404, detail="Agent not found")
    return RedirectResponse(url="/agents", status_code=303)


@router.post(
    "/agents/{agent_id}/purge",
    dependencies=[Depends(require_admin_auth), Depends(verify_form_csrf)],
)
def purge_agent(
    agent_id: str,
    database: Session = Depends(db.get_db),
):
    environment = os.getenv("ENVIRONMENT", "development")
    debug = os.getenv("DEBUG", "false").lower()
    if environment == "production" or debug != "true":
        raise HTTPException(
            status_code=403,
            detail="Hard purge is only available in development environments with DEBUG=true.",
        )
    success = purge_agent_by_id(agent_id, database)
    if not success:
        raise HTTPException(status_code=404, detail="Agent not found")
    return RedirectResponse(url="/agents", status_code=303)
