from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import desc, func
from .. import models, db
from ..auth.csrf import verify_json_csrf
from ..auth.dependencies import require_api_auth, require_agent_key
from ..services.metric_service import compute_metrics_summary, evaluate_health_rules
from ..services import investigation_service
from datetime import datetime, timedelta

router = APIRouter(prefix="/api")


@router.post("/metrics")
def ingest_metric(
    metric: models.MetricCreate,
    db: Session = Depends(db.get_db),
    agent_meta: dict = Depends(require_agent_key),
):
    db_metric = models.Metric(
        timestamp=metric.timestamp,
        host=metric.host,
        cpu_percent=str(metric.cpu_percent),
        ram_percent=str(metric.ram_percent),
        net_in_bytes=str(metric.net_in_bytes),
        net_out_bytes=str(metric.net_out_bytes)
    )
    db.add(db_metric)
    db.commit()

    # System-health rule alerting is owned by metric_service.
    evaluate_health_rules(db, metric, agent_meta)

    return {"status": "ok"}

@router.get("/metrics/summary", dependencies=[Depends(require_api_auth)])
def get_metrics_summary(host: str = Query(None), db: Session = Depends(db.get_db)):
    return compute_metrics_summary(db, host=host)

@router.get("/metrics/timeseries", dependencies=[Depends(require_api_auth)])
def get_metrics_timeseries(host: str = Query(None), minutes: int = 10, db: Session = Depends(db.get_db)):
    since = datetime.utcnow() - timedelta(minutes=minutes)
    query = db.query(models.Metric).filter(models.Metric.timestamp > since)
    if host:
        query = query.filter(models.Metric.host == host)
    
    data = query.order_by(models.Metric.timestamp.asc()).all()
    
    result = {
        "labels": [],
        "cpu": [],
        "ram": [],
        "net_in": [],
        "net_out": []
    }
    
    last_in = 0.0
    last_out = 0.0
    last_ts = None

    for m in data:
        result["labels"].append(m.timestamp.isoformat())
        result["cpu"].append(float(m.cpu_percent))
        result["ram"].append(float(m.ram_percent))
        
        # Rate calculation for charts
        current_in = float(m.net_in_bytes)
        current_out = float(m.net_out_bytes)
        rate_in = 0.0
        rate_out = 0.0
        
        if last_ts:
            td = (m.timestamp - last_ts).total_seconds()
            if td > 0:
                 rate_in = (current_in - last_in) / td
                 rate_out = (current_out - last_out) / td
        
        result["net_in"].append(max(0, rate_in))
        result["net_out"].append(max(0, rate_out))
        
        last_in = current_in
        last_out = current_out
        last_ts = m.timestamp
        
    return result

@router.get("/alerts/recent", dependencies=[Depends(require_api_auth)])
def get_recent_alerts(limit: int = 20, host: str = Query(None), db: Session = Depends(db.get_db)):
    query = db.query(models.Alert)
    if host:
        query = query.filter(models.Alert.host == host)
    return query.order_by(desc(models.Alert.timestamp)).limit(limit).all()

@router.get("/alerts/threats", dependencies=[Depends(require_api_auth)])
def get_threat_alerts(limit: int = 30, host: str = Query(None), db: Session = Depends(db.get_db)):
    """Returns MITRE-tagged threat alerts (T1059 etc.) for the dedicated threat panel."""
    query = db.query(models.Alert).filter(models.Alert.source.like("T%"))
    if host:
        query = query.filter(models.Alert.host == host)
    mitre_alerts = query.order_by(desc(models.Alert.timestamp)).limit(limit).all()
    return [
        {
            "id": a.id,
            "timestamp": a.timestamp.isoformat(),
            "host": a.host,
            "severity": a.severity,
            "title": a.title,
            "description": a.description,
            "mitre_id": a.source,
            "is_read": a.is_read
        }
        for a in mitre_alerts
    ]

@router.put("/alerts/{alert_id}/read", dependencies=[Depends(require_api_auth), Depends(verify_json_csrf)])
def mark_alert_read(alert_id: int, db: Session = Depends(db.get_db)):
    alert = db.query(models.Alert).filter(models.Alert.id == alert_id).first()
    if alert:
        alert.is_read = True
        db.commit()
    return {"status": "ok"}

@router.post("/alerts/mark-all-read", dependencies=[Depends(require_api_auth), Depends(verify_json_csrf)])
def mark_all_read(db: Session = Depends(db.get_db)):
    db.query(models.Alert).filter(models.Alert.is_read == False).update({models.Alert.is_read: True})
    db.commit()
    return {"status": "ok"}

@router.get("/alerts/stats", dependencies=[Depends(require_api_auth)])
def get_alert_stats(host: str = Query(None), db: Session = Depends(db.get_db)):
    """Returns aggregated alert counts for dashboard KPI cards."""
    def _base():
        q = db.query(func.count(models.Alert.id))
        if host:
            q = q.filter(models.Alert.host == host)
        return q

    total = _base().scalar() or 0
    high = _base().filter(
        models.Alert.severity.in_(["HIGH", "CRITICAL", "high", "critical"])
    ).scalar() or 0
    mitre = _base().filter(models.Alert.source.like("T%")).scalar() or 0
    last_24h = _base().filter(
        models.Alert.timestamp > datetime.utcnow() - timedelta(hours=24)
    ).scalar() or 0
    unread_mitre = _base().filter(
        models.Alert.source.like("T%"),
        models.Alert.is_read == False
    ).scalar() or 0
    unread_high = _base().filter(
        models.Alert.severity.in_(["HIGH", "CRITICAL", "high", "critical"]),
        models.Alert.is_read == False
    ).scalar() or 0
    return {
        "total": total,
        "high_severity": high,
        "unread_high": unread_high,
        "mitre_detections": mitre,
        "unread_mitre": unread_mitre,
        "last_24h": last_24h,
    }


# ---------------------------------------------------------------------------
# Alert Investigation — data endpoint
# ---------------------------------------------------------------------------

@router.get("/alerts/{alert_id}/investigation", dependencies=[Depends(require_api_auth)])
def get_investigation_data(alert_id: int, db: Session = Depends(db.get_db)):
    """Return all data needed by the Alert Investigation page as JSON."""
    return investigation_service.get_investigation_data(db, alert_id)


# ---------------------------------------------------------------------------
# Alert Investigation — assessment upsert endpoint (refinement 8: validated)
# ---------------------------------------------------------------------------

_ALLOWED_STATUSES = {"New", "Investigating", "Resolved", "False Positive"}

from pydantic import BaseModel as _BaseModel

class AssessmentIn(_BaseModel):
    status: str
    analyst_notes: str = ""

@router.put("/alerts/{alert_id}/assessment", dependencies=[Depends(require_api_auth), Depends(verify_json_csrf)])
def save_assessment(alert_id: int, payload: AssessmentIn, db: Session = Depends(db.get_db)):
    # Validate alert exists
    alert = db.query(models.Alert).filter(models.Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    # Validate status (refinement 8)
    if payload.status not in _ALLOWED_STATUSES:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid status. Must be one of: {', '.join(sorted(_ALLOWED_STATUSES))}"
        )

    assessment = db.query(models.AlertAssessment).filter(
        models.AlertAssessment.alert_id == alert_id
    ).first()

    if assessment:
        assessment.status = payload.status
        assessment.analyst_notes = payload.analyst_notes
        assessment.updated_at = datetime.utcnow()
    else:
        assessment = models.AlertAssessment(
            alert_id=alert_id,
            status=payload.status,
            analyst_notes=payload.analyst_notes,
        )
        db.add(assessment)

    db.commit()
    return {"status": "ok", "assessment_status": assessment.status}
