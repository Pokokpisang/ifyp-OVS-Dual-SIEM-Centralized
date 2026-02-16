from fastapi import APIRouter, Request, Depends, Query
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from sqlalchemy import desc
from .. import models, db
import math

router = APIRouter()
templates = Jinja2Templates(directory="templates")

@router.get("/dashboard")
def view_dashboard(request: Request, db: Session = Depends(db.get_db)):
    # Get list of hosts for dropdown
    hosts = db.query(models.Metric.host).distinct().all()
    host_list = [h[0] for h in hosts]
    return templates.TemplateResponse("dashboard.html", {"request": request, "hosts": host_list})

@router.get("/alerts", response_class=HTMLResponse)
def view_alerts(
    request: Request,
    page: int = 1,
    severity: str = "",
    source: str = "",
    host: str = "",
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
