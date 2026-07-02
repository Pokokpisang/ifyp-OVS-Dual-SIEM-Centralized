"""
investigation_service — assembles the Alert Investigation page payload.

Extracted from routers/api_metrics.get_investigation_data so the route stays a
thin handler. This module is strictly read-only: every function only queries and
never commits; the DB session is owned by the caller (the route dependency).

SOAR auto-run is intentionally NOT triggered here — it already fires once at
alert-creation time (services/alert_service.create_alert). Opening the
investigation page is a pure read and has no side effects.
"""
import json
import re
from datetime import timedelta
from typing import List, Optional, Tuple

from fastapi import HTTPException
from sqlalchemy import desc, func
from sqlalchemy.orm import Session

from .. import models

# First IPv4 address found in arbitrary text.
_IP_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')


def extract_ip_from_text(text: str) -> Optional[str]:
    """Return the first IPv4 address found in *text*, or None."""
    if not text:
        return None
    m = _IP_RE.search(text)
    return m.group(0) if m else None


def get_related_logs(
    db: Session, alert: models.Alert, source_ip: Optional[str]
) -> Tuple[List[models.Log], Optional[str]]:
    """Return correlated logs (host ±10 min window, merged with source-IP hits)
    and the resolved source_ip (which may be discovered from the logs).

    Read-only.
    """
    window_start = alert.timestamp - timedelta(minutes=10)
    window_end = alert.timestamp + timedelta(minutes=10)

    correlated_logs = (
        db.query(models.Log)
        .filter(
            models.Log.host == alert.host,
            models.Log.timestamp >= window_start,
            models.Log.timestamp <= window_end,
        )
        .order_by(models.Log.timestamp.asc())
        .limit(20)
        .all()
    )

    # If we still have no IP, try to extract one from the correlated log messages
    if not source_ip:
        for log in correlated_logs:
            ip = extract_ip_from_text(log.message or "")
            if ip:
                source_ip = ip
                break

    # Also filter correlated events by source IP if available
    if source_ip:
        ip_logs = (
            db.query(models.Log)
            .filter(
                models.Log.message.contains(source_ip),
                models.Log.timestamp >= window_start,
                models.Log.timestamp <= window_end,
            )
            .order_by(models.Log.timestamp.asc())
            .limit(10)
            .all()
        )
        existing_ids = {l.id for l in correlated_logs}
        correlated_logs = correlated_logs + [l for l in ip_logs if l.id not in existing_ids]
        correlated_logs.sort(key=lambda l: l.timestamp)

    return correlated_logs, source_ip


def build_alert_timeline(
    db: Session,
    alert: models.Alert,
    correlated_logs: List[models.Log],
    rule_name: str,
) -> List[dict]:
    """Build the investigation timeline from correlated logs, the alert itself,
    SOAR execution events, and a trailing pending step. Read-only.

    The PENDING step is always sorted last — the frontend relies on this order.
    """
    timeline = []
    for log in correlated_logs:
        timeline.append({
            "ts": log.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "label": (log.message or "")[:120],
            "is_alert": False,
        })

    alert_desc_full_timeline = alert.description or 'No description'
    timeline_desc = alert_desc_full_timeline.split("\n\nRAW_LOG: ")[0]

    timeline.append({
        "ts": alert.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        "label": f"Detection Rule triggered: {rule_name}\nDescription: {timeline_desc}",
        "is_alert": True,
    })

    soar_events = db.query(models.SOARActionExecution).filter(
        models.SOARActionExecution.alert_id == alert.id
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

    timeline.append({
        "ts": "PENDING",
        "label": "Waiting for analyst action...",
        "is_alert": False,
        "is_pending": True,
    })
    timeline.sort(key=lambda x: (x["ts"] == "PENDING", x["ts"]))
    return timeline


def get_endpoint_health(db: Session, host: str) -> dict:
    """Latest CPU/RAM/network sample for the host, or {'available': False}. Read-only."""
    latest_metric = (
        db.query(models.Metric)
        .filter(models.Metric.host == host)
        .order_by(desc(models.Metric.timestamp))
        .first()
    )
    if latest_metric:
        return {
            "available": True,
            "cpu": round(float(latest_metric.cpu_percent), 1),
            "ram": round(float(latest_metric.ram_percent), 1),
            "net_in": str(latest_metric.net_in_bytes),
            "net_out": str(latest_metric.net_out_bytes),
            "last_seen": latest_metric.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        }
    return {"available": False}


def get_source_intel(db: Session, source_ip: Optional[str], host: str) -> dict:
    """Source-intelligence block: alert counts by source IP (if known) else by
    host, plus placeholder geo/asn fields. Read-only."""
    if source_ip:
        alert_count_label = "Alerts from Same Source IP"
        alert_count = db.query(func.count(models.Alert.id)).filter(
            models.Alert.description.contains(source_ip)
        ).scalar() or 0
    else:
        alert_count_label = "Alerts from Same Host"
        alert_count = db.query(func.count(models.Alert.id)).filter(
            models.Alert.host == host
        ).scalar() or 0

    return {
        "source_ip": source_ip,
        "geolocation": "Not available",
        "asn": "Not available",
        "alert_count": alert_count,
        "alert_count_label": alert_count_label,
    }


def get_investigation_data(db: Session, alert_id: int) -> dict:
    """Return all data needed by the Alert Investigation page as JSON.

    Strictly read-only. Raises HTTPException(404) if the alert does not exist.
    """
    # 1. Load alert (validate)
    alert = db.query(models.Alert).filter(models.Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

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
    correlated_logs, source_ip = get_related_logs(db, alert, source_ip)

    # 6. Build timeline from alert + correlated events
    timeline = build_alert_timeline(db, alert, correlated_logs, rule_name)

    # 7. Endpoint health from metrics table (refinement 6)
    endpoint_health = get_endpoint_health(db, alert.host)

    # 8. Source intelligence counts (refinement 3)
    source_intel = get_source_intel(db, source_ip, alert.host)

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
        "source_intel": source_intel,
    }
