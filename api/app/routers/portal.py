"""
routers/portal.py — READ-ONLY tenant-scoped API for the client portal.

The client portal runs in a SEPARATE environment and authenticates with a
per-client API key (``X-Client-Key``, issued by SOC admins at /clients/{id}).

Hard rules for this surface — do not relax them:
- GET only. No mutation endpoint may ever live under /api/portal/.
- Every query derives its scope from client_service (client_agents /
  client_alerts_query) — the fail-closed tenant choke point.
- Portal-safe serializers only: no rule internals (detection_metadata,
  dedup_key), no SOAR data, no agent keys/tokens, no other tenants' data,
  no internal agent UUIDs.
- Rate-limited per source IP.
"""
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import func
from sqlalchemy.orm import Session

from .. import db, models
from ..auth.dependencies import require_client_key
from ..services import client_service
from ..services.agent_service import compute_agent_status
from .auth import limiter

router = APIRouter(prefix="/api/portal", tags=["portal"])

_RATE = "120/minute"


def _agent_public(agent: models.AgentRecord) -> dict:
    """Portal-safe agent view — no keys, no tokens, no internal UUID."""
    return {
        "name": agent.agent_name,
        "hostname": agent.hostname,
        "ip_address": agent.ip_address,
        "os": f"{agent.os_type} {agent.distribution}".strip(),
        "status": compute_agent_status(agent),
        "last_seen": agent.last_seen.strftime("%Y-%m-%d %H:%M:%S") if agent.last_seen else None,
        "monitored_since": agent.created_at.strftime("%Y-%m-%d") if agent.created_at else None,
    }


def _alert_public(alert: models.Alert) -> dict:
    """Portal-safe alert view — evidence summary without rule internals."""
    return {
        "id": alert.id,
        "timestamp": alert.timestamp.strftime("%Y-%m-%d %H:%M:%S") if alert.timestamp else None,
        "severity": alert.severity,
        "title": alert.title,
        "description": alert.description,
        "host": alert.host,
        "mitre_tactic": alert.mitre_tactic,
        "mitre_technique": alert.mitre_technique,
        "risk_score": alert.risk_score,
    }


@router.get("/summary")
@limiter.limit(_RATE)
def portal_summary(
    request: Request,
    client: models.Client = Depends(require_client_key),
    database: Session = Depends(db.get_db),
):
    """Overview numbers for the portal dashboard."""
    agents = client_service.client_agents(database, client.id)
    statuses = [compute_agent_status(a) for a in agents]
    alerts_q = client_service.client_alerts_query(database, client.id)
    day_ago = datetime.utcnow() - timedelta(hours=24)

    severity_counts = dict(
        alerts_q.with_entities(models.Alert.severity, func.count(models.Alert.id))
        .group_by(models.Alert.severity).all()
    )
    return {
        "client": {"name": client.name, "status": client.status},
        "agents": {
            "total": len(agents),
            "online": sum(1 for s in statuses if s == "active"),
            "offline": sum(1 for s in statuses if s == "offline"),
            "pending": sum(1 for s in statuses if s == "pending"),
        },
        "alerts": {
            "total": alerts_q.with_entities(func.count(models.Alert.id)).scalar() or 0,
            "open": alerts_q.filter(models.Alert.is_read == False)  # noqa: E712
                    .with_entities(func.count(models.Alert.id)).scalar() or 0,
            "last_24h": alerts_q.filter(models.Alert.timestamp >= day_ago)
                        .with_entities(func.count(models.Alert.id)).scalar() or 0,
            "by_severity": severity_counts,
        },
        "generated_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
    }


@router.get("/agents")
@limiter.limit(_RATE)
def portal_agents(
    request: Request,
    client: models.Client = Depends(require_client_key),
    database: Session = Depends(db.get_db),
):
    """The client's monitored servers."""
    agents = client_service.client_agents(database, client.id)
    return {"agents": [_agent_public(a) for a in agents]}


@router.get("/alerts")
@limiter.limit(_RATE)
def portal_alerts(
    request: Request,
    severity: str = Query(""),
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    client: models.Client = Depends(require_client_key),
    database: Session = Depends(db.get_db),
):
    """Tenant-scoped security events, newest first."""
    q = client_service.client_alerts_query(database, client.id)
    if severity:
        q = q.filter(models.Alert.severity == severity.upper())
    total = q.with_entities(func.count(models.Alert.id)).scalar() or 0
    rows = (
        q.order_by(models.Alert.timestamp.desc(), models.Alert.id.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    return {
        "alerts": [_alert_public(a) for a in rows],
        "total": total,
        "page": page,
        "page_count": max((total + page_size - 1) // page_size, 1),
    }


@router.get("/security-summary")
@limiter.limit(_RATE)
def portal_security_summary(
    request: Request,
    days: int = Query(30, ge=1, le=90),
    client: models.Client = Depends(require_client_key),
    database: Session = Depends(db.get_db),
):
    """Posture rollup for reporting: severity/technique/host breakdowns."""
    since = datetime.utcnow() - timedelta(days=days)
    q = client_service.client_alerts_query(database, client.id).filter(
        models.Alert.timestamp >= since
    )
    by_severity = dict(
        q.with_entities(models.Alert.severity, func.count(models.Alert.id))
        .group_by(models.Alert.severity).all()
    )
    by_technique = [
        {"technique": t or "unmapped", "count": n}
        for t, n in q.with_entities(models.Alert.mitre_technique, func.count(models.Alert.id))
        .group_by(models.Alert.mitre_technique)
        .order_by(func.count(models.Alert.id).desc()).limit(10).all()
    ]
    by_host = [
        {"host": h, "count": n}
        for h, n in q.with_entities(models.Alert.host, func.count(models.Alert.id))
        .group_by(models.Alert.host)
        .order_by(func.count(models.Alert.id).desc()).limit(10).all()
    ]
    return {
        "window_days": days,
        "total_alerts": q.with_entities(func.count(models.Alert.id)).scalar() or 0,
        "by_severity": by_severity,
        "top_techniques": by_technique,
        "top_hosts": by_host,
    }
