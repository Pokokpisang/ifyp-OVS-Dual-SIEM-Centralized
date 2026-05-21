from fastapi import APIRouter, Request, Depends, Query, HTTPException, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from sqlalchemy import desc
from .. import models, db
import math
import os
from datetime import datetime, timedelta
from ..auth.csrf import verify_form_csrf
from ..auth.dependencies import require_admin_auth
from ..services.agent_service import (
    create_agent, list_agents, compute_agent_status,
    get_agent_by_id, delete_agent_by_id, purge_agent_by_id,
    get_latest_agent_metrics, get_recent_agent_alerts, get_recent_agent_logs,
    get_all_agents_for_history,
)
from ..services.server_address import get_server_address, normalize_server_url, validate_server_address

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
    # --- AgentRecord-registered agents (active inventory only — excludes deleted/retired/test) ---
    registered = list_agents(database, include_deleted=False)

    # --- Legacy metric-only agents (appear via /ingest metrics without registration) ---
    hosts_with_metrics = {h[0] for h in database.query(models.Metric.host).distinct().all()}
    registered_hostnames = {a["hostname"] for a in registered if a["hostname"] != "—"}

    now = datetime.utcnow()
    agents: list[dict] = list(registered)  # start with registered agents

    for host in hosts_with_metrics - registered_hostnames:
        latest = (
            database.query(models.Metric)
            .filter(models.Metric.host == host)
            .order_by(desc(models.Metric.timestamp))
            .first()
        )
        if not latest:
            continue
        is_offline = (now - latest.timestamp) > timedelta(minutes=5)
        is_high_load = float(latest.cpu_percent) > 85.0
        status = "offline" if is_offline else ("HIGH LOAD" if is_high_load else "active")
        agents.append({
            "id": None,
            "agent_id": host,
            "agent_name": host,
            "group": "—",
            "tags": "",
            "os_type": "Linux",
            "distribution": "—",
            "architecture": "—",
            "status": status,
            "hostname": host,
            "ip_address": "—",
            "last_seen": latest.timestamp.strftime("%Y-%m-%d %H:%M UTC"),
            "created_at": "—",
            "cpu": round(float(latest.cpu_percent), 1),
            "ram": round(float(latest.ram_percent), 1),
        })

    # Inject cpu/ram for registered agents that also have metrics
    for a in agents:
        if "cpu" not in a:
            host = a.get("hostname", "")
            latest = (
                database.query(models.Metric)
                .filter(models.Metric.host == host)
                .order_by(desc(models.Metric.timestamp))
                .first()
            )
            a["cpu"] = round(float(latest.cpu_percent), 1) if latest else 0
            a["ram"] = round(float(latest.ram_percent), 1) if latest else 0

    # Filtering
    if q:
        agents = [a for a in agents if q.lower() in a["agent_name"].lower() or q.lower() in a["hostname"].lower()]
    if status_filter != "All":
        agents = [a for a in agents if a["status"].lower() == status_filter.lower()]

    # Summary counts
    total_online = sum(1 for a in agents if a["status"] in ("active", "HIGH LOAD"))
    total_offline = sum(1 for a in agents if a["status"] == "offline")
    total_pending = sum(1 for a in agents if a["status"] == "pending")
    total_high_load = sum(1 for a in agents if a["status"] == "HIGH LOAD")

    # Pagination
    limit = 20
    total_count = len(agents)
    total_pages = max(math.ceil(total_count / limit), 1)
    offset = (page - 1) * limit
    paginated = agents[offset:offset + limit]

    return templates.TemplateResponse("agents.html", {
        "request": request,
        "agents": paginated,
        "page": page,
        "total_count": total_count,
        "total_pages": total_pages,
        "q": q,
        "status_filter": status_filter,
        "summary": {
            "total": total_count,
            "online": total_online,
            "offline": total_offline,
            "high_load": total_high_load,
            "pending": total_pending,
        },
    })


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

    return templates.TemplateResponse("alert_investigation.html", {
        "request": request,
        "alert": alert,
        "assessment": assessment,
    })


@router.get("/agents/history", response_class=HTMLResponse)
def view_agents_history(
    request: Request,
    page: int = 1,
    q: str = "",
    lifecycle_filter: str = "all",
    database: Session = Depends(db.get_db),
):
    agents = get_all_agents_for_history(database, q=q, lifecycle_filter=lifecycle_filter)

    # Inject cpu/ram metrics for display
    for a in agents:
        host = a.get("hostname", "")
        if host and host != "—":
            latest = (
                database.query(models.Metric)
                .filter(models.Metric.host == host)
                .order_by(desc(models.Metric.timestamp))
                .first()
            )
            a["cpu"] = round(float(latest.cpu_percent), 1) if latest else 0
            a["ram"] = round(float(latest.ram_percent), 1) if latest else 0
        else:
            a["cpu"] = 0
            a["ram"] = 0

    limit = 20
    total_count = len(agents)
    total_pages = max(math.ceil(total_count / limit), 1)
    offset = (page - 1) * limit
    paginated = agents[offset:offset + limit]

    return templates.TemplateResponse("agents_history.html", {
        "request": request,
        "agents": paginated,
        "page": page,
        "total_count": total_count,
        "total_pages": total_pages,
        "q": q,
        "lifecycle_filter": lifecycle_filter,
    })


@router.get("/network", response_class=HTMLResponse)
def view_network(request: Request, database: Session = Depends(db.get_db)):
    """Network Investigation page — agent network status, suspicious activity, SOAR actions."""
    registered = list_agents(database, include_deleted=False)

    # Build agent list with real status and metrics
    now = datetime.utcnow()
    agent_rows = []
    for a in registered:
        host = a.get("hostname") or a.get("agent_name", "")
        latest = (
            database.query(models.Metric)
            .filter(models.Metric.host == host)
            .order_by(desc(models.Metric.timestamp))
            .first()
        ) if host else None
        is_offline = (now - latest.timestamp) > timedelta(minutes=5) if latest else True
        net_in = int(float(latest.net_in_bytes)) if latest else 0
        net_out = int(float(latest.net_out_bytes)) if latest else 0
        agent_rows.append({
            "name": a.get("agent_name", "—"),
            "host": a.get("ip_address", "—"),
            "status": a.get("status", "offline"),
            "last_seen": a.get("last_seen", "—"),
            "net_in": net_in,
            "net_out": net_out,
            "risk": "low",  # TODO: derive from alert severity when network alert model exists
        })

    # Recent alerts for alert-chip linking
    recent_alerts = (
        database.query(models.Alert)
        .order_by(desc(models.Alert.timestamp))
        .limit(20)
        .all()
    )
    alert_map = {a.id: {"id": a.id, "title": a.title, "severity": a.severity} for a in recent_alerts}

    # Counts for metric cards
    total_agents = len(agent_rows)
    online_agents = sum(1 for a in agent_rows if a["status"] in ("active", "HIGH LOAD"))

    return templates.TemplateResponse("network_investigation.html", {
        "request": request,
        "agent_rows": agent_rows,
        "alert_map": alert_map,
        "total_agents": total_agents,
        "online_agents": online_agents,
    })


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
    q = database.query(models.SOARActionExecution)

    if status:
        q = q.filter(models.SOARActionExecution.status == status)
    if mode:
        q = q.filter(models.SOARActionExecution.mode == mode)
    if action_type:
        q = q.filter(models.SOARActionExecution.action_type == action_type)
    if alert_id:
        q = q.filter(models.SOARActionExecution.alert_id == alert_id)

    records = q.order_by(models.SOARActionExecution.id.desc()).limit(100).all()

    # Summary counts (unfiltered)
    all_rows = database.query(models.SOARActionExecution)
    total = all_rows.count()
    pending = all_rows.filter(models.SOARActionExecution.status == "pending_approval").count()
    executed = all_rows.filter(models.SOARActionExecution.status.in_(["executed", "success"])).count()
    failed = all_rows.filter(models.SOARActionExecution.status == "failed").count()
    rejected = all_rows.filter(models.SOARActionExecution.status == "rejected").count()

    # Distinct filter options
    statuses = [r[0] for r in database.query(models.SOARActionExecution.status).distinct().all() if r[0]]
    modes = [r[0] for r in database.query(models.SOARActionExecution.mode).distinct().all() if r[0]]
    action_types = [r[0] for r in database.query(models.SOARActionExecution.action_type).distinct().all() if r[0]]

    return templates.TemplateResponse(
        "soar_history.html",
        {
            "request": request,
            "records": records,
            "filters": {
                "status": status or "",
                "mode": mode or "",
                "action_type": action_type or "",
                "alert_id": alert_id or "",
            },
            "summary": {
                "total": total,
                "pending": pending,
                "executed": executed,
                "failed": failed,
                "rejected": rejected,
            },
            "filter_options": {
                "statuses": statuses,
                "modes": modes,
                "action_types": action_types,
            },
        },
    )


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
