from fastapi import APIRouter, Depends, Query, HTTPException, Header
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from sqlalchemy import desc, func
from .. import models, db
from ..auth.dependencies import require_api_auth
from typing import List, Literal, Optional
from datetime import datetime, timedelta
import re
import json
from ..services.agent_service import update_last_seen, get_agent_metadata_by_key

router = APIRouter(prefix="/api")

# ---------------------------------------------------------------------------
# Shared helper: extract first IPv4 address from arbitrary text
# ---------------------------------------------------------------------------

_IP_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

def extract_ip_from_text(text: str) -> Optional[str]:
    """Return the first IPv4 address found in *text*, or None."""
    if not text:
        return None
    m = _IP_RE.search(text)
    return m.group(0) if m else None


@router.post("/metrics")
def ingest_metric(
    metric: models.MetricCreate, 
    db: Session = Depends(db.get_db),
    x_agent_key: Optional[str] = Header(None, alias="X-Agent-Key")
):
    # 0. Update Last Seen if key provided
    agent_meta = None
    if x_agent_key:
        update_last_seen(agent_key=x_agent_key, db=db)
        agent_meta = get_agent_metadata_by_key(agent_key=x_agent_key, db=db)

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
    
    # --- System Health Rules Alerting ---
    health_rules = db.query(models.SystemHealthRule).filter(models.SystemHealthRule.enabled == True).all()
    
    for rule in health_rules:
        # 1. Determine observed value
        observed_value = 0.0
        unit = "%"
        if rule.metric_name == "cpu":
            observed_value = float(metric.cpu_percent)
        elif rule.metric_name == "ram":
            observed_value = float(metric.ram_percent)
        elif rule.metric_name == "net_in":
            # For network, we might need to calculate rate, but user suggested thresholds > 100MB/s
            # We'll use the raw value for now or calculate rate if possible.
            # Given the requirement "threshold display 100MB/s", let's try to get the rate.
            summary = get_metrics_summary(host=metric.host, db=db)
            observed_value = summary.get("net_in_rate", 0.0)
            unit = "B/s"
        elif rule.metric_name == "net_out":
            summary = get_metrics_summary(host=metric.host, db=db)
            observed_value = summary.get("net_out_rate", 0.0)
            unit = "B/s"
            
        # 2. Check threshold
        is_triggered = False
        if rule.operator == ">":
            is_triggered = observed_value > rule.threshold_value
        elif rule.operator == "<":
            is_triggered = observed_value < rule.threshold_value
            
        if is_triggered:
            # 3. Check Cooldown (5 minutes)
            cooldown_period = datetime.utcnow() - timedelta(minutes=5)
            recent_alert = db.query(models.Alert).filter(
                models.Alert.host == metric.host,
                models.Alert.rule_id == rule.rule_id,
                models.Alert.timestamp > cooldown_period
            ).first()
            
            if not recent_alert:
                # 4. Create Alert
                metadata = {
                    "engine": rule.detection_engine,
                    "metric": rule.metric_name,
                    "threshold": rule.threshold_value,
                    "observed_value": round(observed_value, 2),
                    "unit": unit
                }
                
                alert = models.Alert(
                    timestamp=datetime.utcnow(),
                    host=metric.host,
                    severity=rule.severity,
                    title=rule.rule_name,
                    description=f"{rule.rule_name}: {rule.metric_name} {rule.operator} {rule.threshold_value}{unit} (Observed: {round(observed_value, 2)}{unit})",
                    source=None, # Not MITRE
                    agent_id=agent_meta["agent_id"] if agent_meta else None,
                    rule_id=rule.rule_id,
                    rule_name=rule.rule_name,
                    risk_score=20,
                    mitre_tactic=None,
                    mitre_technique=None,
                    detection_engine=rule.detection_engine,
                    detection_metadata=json.dumps(metadata)
                )
                db.add(alert)
                
                # Update last_triggered
                rule.last_triggered = datetime.utcnow()
                db.commit()

    return {"status": "ok"}

@router.get("/metrics/summary", dependencies=[Depends(require_api_auth)])
def get_metrics_summary(host: str = Query(None), db: Session = Depends(db.get_db)):
    # Get latest metric
    query = db.query(models.Metric)
    if host:
        query = query.filter(models.Metric.host == host)
    latest = query.order_by(desc(models.Metric.timestamp)).first()
    
    if not latest:
        return {}
        
    # Calculate Net Rate (Current - Previous)
    # Find previous metric
    prev = db.query(models.Metric).filter(
        models.Metric.host == latest.host,
        models.Metric.timestamp < latest.timestamp
    ).order_by(desc(models.Metric.timestamp)).first()
    
    net_in_rate = 0.0
    net_out_rate = 0.0
    
    if prev:
        time_diff = (latest.timestamp - prev.timestamp).total_seconds()
        if time_diff > 0:
            net_in_rate = (float(latest.net_in_bytes) - float(prev.net_in_bytes)) / time_diff
            net_out_rate = (float(latest.net_out_bytes) - float(prev.net_out_bytes)) / time_diff
            
    return {
        "cpu_percent": float(latest.cpu_percent),
        "ram_percent": float(latest.ram_percent),
        "net_in_rate": max(0, net_in_rate), # Avoid negative if restart
        "net_out_rate": max(0, net_out_rate)
    }

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
def get_threat_alerts(limit: int = 30, db: Session = Depends(db.get_db)):
    """Returns MITRE-tagged threat alerts (T1059 etc.) for the dedicated threat panel."""
    mitre_alerts = db.query(models.Alert).filter(
        models.Alert.source.like("T%")
    ).order_by(desc(models.Alert.timestamp)).limit(limit).all()
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

@router.put("/alerts/{alert_id}/read", dependencies=[Depends(require_api_auth)])
def mark_alert_read(alert_id: int, db: Session = Depends(db.get_db)):
    alert = db.query(models.Alert).filter(models.Alert.id == alert_id).first()
    if alert:
        alert.is_read = True
        db.commit()
    return {"status": "ok"}

@router.post("/alerts/mark-all-read", dependencies=[Depends(require_api_auth)])
def mark_all_read(db: Session = Depends(db.get_db)):
    db.query(models.Alert).filter(models.Alert.is_read == False).update({models.Alert.is_read: True})
    db.commit()
    return {"status": "ok"}

@router.get("/alerts/stats", dependencies=[Depends(require_api_auth)])
def get_alert_stats(db: Session = Depends(db.get_db)):
    """Returns aggregated alert counts for dashboard KPI cards."""
    from sqlalchemy import func
    total = db.query(func.count(models.Alert.id)).scalar() or 0
    high = db.query(func.count(models.Alert.id)).filter(
        models.Alert.severity.in_(["HIGH", "CRITICAL", "high", "critical"])
    ).scalar() or 0
    mitre = db.query(func.count(models.Alert.id)).filter(
        models.Alert.source.like("T%")
    ).scalar() or 0
    last_24h = db.query(func.count(models.Alert.id)).filter(
        models.Alert.timestamp > datetime.utcnow() - timedelta(hours=24)
    ).scalar() or 0
    unread_mitre = db.query(func.count(models.Alert.id)).filter(
        models.Alert.source.like("T%"),
        models.Alert.is_read == False
    ).scalar() or 0
    unread_high = db.query(func.count(models.Alert.id)).filter(
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
    # 1. Load alert (validate)
    alert = db.query(models.Alert).filter(models.Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    from ..soar.response_service import auto_run_for_alert
    auto_run_for_alert(alert_id, db, executed_by="system:auto")

    # 2. Load analyst assessment (may not exist yet)
    assessment = db.query(models.AlertAssessment).filter(
        models.AlertAssessment.alert_id == alert_id
    ).first()

    # 3. Determine MITRE technique & rule name (refinements 4 & 5)
    source = alert.source or ""
    mitre_technique = source if (source and source.upper().startswith("T")) else "Not mapped"
    rule_name = alert.title or "Unknown"  # no separate rule_name field — use title

    # 4. Extract source IP from description then from related logs (refinement 1)
    source_ip = extract_ip_from_text(alert.description or "")

    # 5. Correlated events — host + ±10 min window (refinement 2)
    window_start = alert.timestamp - timedelta(minutes=10)
    window_end   = alert.timestamp + timedelta(minutes=10)

    corr_query = db.query(models.Log).filter(
        models.Log.host == alert.host,
        models.Log.timestamp >= window_start,
        models.Log.timestamp <= window_end,
    )
    correlated_logs = corr_query.order_by(models.Log.timestamp.asc()).limit(20).all()

    # If we still have no IP, try to extract one from the correlated log messages
    if not source_ip:
        for log in correlated_logs:
            ip = extract_ip_from_text(log.message or "")
            if ip:
                source_ip = ip
                break

    # Also filter correlated events by source IP if available
    if source_ip:
        ip_logs = db.query(models.Log).filter(
            models.Log.message.contains(source_ip),
            models.Log.timestamp >= window_start,
            models.Log.timestamp <= window_end,
        ).order_by(models.Log.timestamp.asc()).limit(10).all()
        # Merge deduplicating by id
        existing_ids = {l.id for l in correlated_logs}
        correlated_logs = correlated_logs + [l for l in ip_logs if l.id not in existing_ids]
        correlated_logs.sort(key=lambda l: l.timestamp)

    # 6. Build timeline from alert + correlated events
    timeline = []
    for log in correlated_logs:
        timeline.append({
            "ts": log.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "label": (log.message or "")[:120],
            "is_alert": False,
        })
    alert_desc_full_timeline = alert.description or 'No description'
    timeline_desc = alert_desc_full_timeline.split("\n\nRAW_LOG: ")[0]

    # Insert the alert itself as the highlighted event
    timeline.append({
        "ts": alert.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        "label": f"Detection Rule triggered: {rule_name}\nDescription: {timeline_desc}",
        "is_alert": True,
    })
    # Inject SOAR execution events into timeline
    soar_events = db.query(models.SOARActionExecution).filter(
        models.SOARActionExecution.alert_id == alert_id
    ).all()
    for evt in soar_events:
        timeline.append({
            "ts": evt.executed_at.strftime("%Y-%m-%d %H:%M:%S") if evt.executed_at else "PENDING",
            "label": (
                f"SOAR: {evt.action_name} on {evt.target or 'N/A'} — {evt.status}\n"
                f"Executed by: {evt.executed_by or 'analyst'}"
            ),
            "is_alert": False,
            "is_soar": True,
        })

    # Add pending analyst step
    timeline.append({
        "ts": "PENDING",
        "label": "Waiting for analyst action...",
        "is_alert": False,
        "is_pending": True,
    })
    timeline.sort(key=lambda x: (x["ts"] == "PENDING", x["ts"]))

    # 7. Endpoint health from metrics table (refinement 6)
    latest_metric = db.query(models.Metric).filter(
        models.Metric.host == alert.host
    ).order_by(desc(models.Metric.timestamp)).first()

    if latest_metric:
        endpoint_health = {
            "available": True,
            "cpu": round(float(latest_metric.cpu_percent), 1),
            "ram": round(float(latest_metric.ram_percent), 1),
            "net_in":  str(latest_metric.net_in_bytes),
            "net_out": str(latest_metric.net_out_bytes),
            "last_seen": latest_metric.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        }
    else:
        endpoint_health = {"available": False}

    # 8. Source intelligence counts (refinement 3)
    if source_ip:
        alert_count_label = "Alerts from Same Source IP"
        alert_count = db.query(func.count(models.Alert.id)).filter(
            models.Alert.description.contains(source_ip)
        ).scalar() or 0
    else:
        alert_count_label = "Alerts from Same Host"
        alert_count = db.query(func.count(models.Alert.id)).filter(
            models.Alert.host == alert.host
        ).scalar() or 0

    correlated_events_data = [
        {
            "ts": l.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "host": l.host,
            "message": (l.message or "")[:300],
            "log_type": l.log_type,
            "is_alert": False,
        }
        for l in correlated_logs
    ]
    alert_desc_full = alert.description or ""
    if "\n\nRAW_LOG: " in alert_desc_full:
        alert_desc, raw_log_msg = alert_desc_full.split("\n\nRAW_LOG: ", 1)
    else:
        alert_desc = alert_desc_full
        raw_log_msg = alert_desc_full

    correlated_events_data.append({
        "ts": alert.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        "host": alert.host,
        "message": raw_log_msg,
        "log_type": "ALERT",
        "is_alert": True,
    })
    correlated_events_data.sort(key=lambda x: x["ts"])

    return {
        "alert": {
            "id": alert.id,
            "title": alert.title,
            "severity": (alert.severity or "").upper(),
            "host": alert.host,
            "timestamp": alert.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "description": alert_desc,
            "source": source,
            "is_read": alert.is_read,
            # v2.0.0 Fields
            "rule_id": alert.rule_id,
            "rule_name": alert.rule_name,
            "risk_score": alert.risk_score,
            "mitre_tactic": alert.mitre_tactic,
            "mitre_technique": alert.mitre_technique,
            "detection_engine": alert.detection_engine,
            "detection_metadata": json.loads(alert.detection_metadata) if alert.detection_metadata else {},
        },
        "rule_name": alert.rule_name or rule_name,
        "mitre_technique": alert.mitre_technique or mitre_technique,
        "source_ip": source_ip,
        "assessment": {
            "status": assessment.status if assessment else "New",
            "analyst_notes": assessment.analyst_notes if assessment else "",
            "updated_at": assessment.updated_at.strftime("%Y-%m-%d %H:%M:%S") if assessment else None,
        },
        "correlated_events": correlated_events_data,
        "timeline": timeline,
        "endpoint_health": endpoint_health,
        "source_intel": {
            "source_ip": source_ip,
            "geolocation": "Not available",
            "asn": "Not available",
            "alert_count": alert_count,
            "alert_count_label": alert_count_label,
        },
    }


# ---------------------------------------------------------------------------
# Alert Investigation — assessment upsert endpoint (refinement 8: validated)
# ---------------------------------------------------------------------------

_ALLOWED_STATUSES = {"New", "Investigating", "Resolved", "False Positive"}

from pydantic import BaseModel as _BaseModel

class AssessmentIn(_BaseModel):
    status: str
    analyst_notes: str = ""

@router.put("/alerts/{alert_id}/assessment", dependencies=[Depends(require_api_auth)])
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
