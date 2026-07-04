"""
routers/notifications.py — notification channels + delivery log (admin only).

Routes
------
GET    /notifications                          HTML page
GET    /api/notifications/channels             List channels
POST   /api/notifications/channels             Create channel
PUT    /api/notifications/channels/{id}        Update channel (enable/disable, edits)
DELETE /api/notifications/channels/{id}        Delete channel (delivery log survives)
POST   /api/notifications/channels/{id}/test   Send a test notification
GET    /api/notifications/deliveries           Recent delivery log
"""
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from sqlalchemy.orm import Session

from .. import db, models
from ..auth.csrf import verify_json_csrf
from ..auth.dependencies import require_admin_auth, require_admin_html
from ..services import audit_service, notification_service
from ..services.alert_service import get_actor_username

router = APIRouter()
templates = Jinja2Templates(directory="templates")


class ChannelCreate(BaseModel):
    name: str
    channel_type: str
    target: str
    min_severity: str = "HIGH"


class ChannelUpdate(BaseModel):
    name: Optional[str] = None
    target: Optional[str] = None
    min_severity: Optional[str] = None
    enabled: Optional[bool] = None


def _channel_dict(c: models.NotificationChannel) -> dict:
    return {
        "id": c.id,
        "name": c.name,
        "channel_type": c.channel_type,
        "target": c.target,
        "min_severity": c.min_severity,
        "enabled": c.enabled,
        "created_at": str(c.created_at) if c.created_at else None,
    }


def _get_channel(channel_id: int, database: Session) -> models.NotificationChannel:
    channel = database.query(models.NotificationChannel).filter_by(id=channel_id).first()
    if not channel:
        raise HTTPException(status_code=404, detail="Channel not found")
    return channel


@router.get("/notifications", response_class=HTMLResponse, dependencies=[Depends(require_admin_html)])
def view_notifications(request: Request):
    return templates.TemplateResponse("notifications.html", {
        "request": request,
        "smtp_configured": notification_service.smtp_configured(),
    })


@router.get("/api/notifications/channels", dependencies=[Depends(require_admin_auth)])
def list_channels(database: Session = Depends(db.get_db)):
    channels = database.query(models.NotificationChannel).order_by(models.NotificationChannel.id).all()
    return {"channels": [_channel_dict(c) for c in channels],
            "smtp_configured": notification_service.smtp_configured()}


@router.post(
    "/api/notifications/channels",
    dependencies=[Depends(require_admin_auth), Depends(verify_json_csrf)],
)
def create_channel(body: ChannelCreate, request: Request, database: Session = Depends(db.get_db)):
    error = notification_service.validate_channel(body.channel_type, body.target, body.min_severity)
    if error:
        raise HTTPException(status_code=400, detail=error)
    if not body.name.strip():
        raise HTTPException(status_code=400, detail="name is required")

    channel = models.NotificationChannel(
        name=body.name.strip(),
        channel_type=body.channel_type,
        target=body.target.strip(),
        min_severity=body.min_severity,
        enabled=True,
    )
    database.add(channel)
    database.flush()
    audit_service.record_audit_event(
        database,
        actor=get_actor_username(request),
        action=audit_service.NOTIFICATION_CHANNEL_CREATED,
        object_type="notification_channel",
        object_id=channel.id,
        source_ip=audit_service.client_ip(request),
        details={"name": channel.name, "type": channel.channel_type,
                 "target": channel.target, "min_severity": channel.min_severity},
    )
    database.commit()
    return {"status": "ok", "channel": _channel_dict(channel)}


@router.put(
    "/api/notifications/channels/{channel_id}",
    dependencies=[Depends(require_admin_auth), Depends(verify_json_csrf)],
)
def update_channel(channel_id: int, body: ChannelUpdate, request: Request, database: Session = Depends(db.get_db)):
    channel = _get_channel(channel_id, database)

    new_type = channel.channel_type  # type is immutable; recreate to change it
    new_target = body.target.strip() if body.target is not None else channel.target
    new_severity = body.min_severity if body.min_severity is not None else channel.min_severity
    error = notification_service.validate_channel(new_type, new_target, new_severity)
    if error:
        raise HTTPException(status_code=400, detail=error)

    changes = {}
    if body.name is not None and body.name.strip() and body.name.strip() != channel.name:
        changes["name"] = f"{channel.name} → {body.name.strip()}"
        channel.name = body.name.strip()
    if body.target is not None and new_target != channel.target:
        changes["target"] = f"{channel.target} → {new_target}"
        channel.target = new_target
    if body.min_severity is not None and new_severity != channel.min_severity:
        changes["min_severity"] = f"{channel.min_severity} → {new_severity}"
        channel.min_severity = new_severity
    if body.enabled is not None and body.enabled != channel.enabled:
        changes["enabled"] = f"{channel.enabled} → {body.enabled}"
        channel.enabled = body.enabled

    if changes:
        audit_service.record_audit_event(
            database,
            actor=get_actor_username(request),
            action=audit_service.NOTIFICATION_CHANNEL_UPDATED,
            object_type="notification_channel",
            object_id=channel.id,
            source_ip=audit_service.client_ip(request),
            details={"name": channel.name, **changes},
        )
    database.commit()
    return {"status": "ok", "channel": _channel_dict(channel)}


@router.delete(
    "/api/notifications/channels/{channel_id}",
    dependencies=[Depends(require_admin_auth), Depends(verify_json_csrf)],
)
def delete_channel(channel_id: int, request: Request, database: Session = Depends(db.get_db)):
    channel = _get_channel(channel_id, database)
    audit_service.record_audit_event(
        database,
        actor=get_actor_username(request),
        action=audit_service.NOTIFICATION_CHANNEL_DELETED,
        object_type="notification_channel",
        object_id=channel.id,
        source_ip=audit_service.client_ip(request),
        details={"name": channel.name, "type": channel.channel_type, "target": channel.target},
    )
    database.delete(channel)
    database.commit()
    return {"status": "ok"}


@router.post(
    "/api/notifications/channels/{channel_id}/test",
    dependencies=[Depends(require_admin_auth), Depends(verify_json_csrf)],
)
def test_channel(channel_id: int, request: Request, database: Session = Depends(db.get_db)):
    channel = _get_channel(channel_id, database)
    delivery = notification_service.send_test(database, channel)
    audit_service.record_audit_event(
        database,
        actor=get_actor_username(request),
        action=audit_service.NOTIFICATION_TEST_SENT,
        object_type="notification_channel",
        object_id=channel.id,
        source_ip=audit_service.client_ip(request),
        details={"name": channel.name, "status": delivery.status,
                 "error": delivery.error_message or ""},
        commit=True,
    )
    return {
        "status": delivery.status,
        "error_message": delivery.error_message,
    }


@router.get("/api/notifications/deliveries", dependencies=[Depends(require_admin_auth)])
def list_deliveries(limit: int = Query(50, ge=1, le=200), database: Session = Depends(db.get_db)):
    rows = notification_service.list_recent_deliveries(database, limit=limit)
    return {"deliveries": [{
        "id": r.id,
        "created_at": r.created_at.strftime("%Y-%m-%d %H:%M:%S") if r.created_at else None,
        "channel_name": r.channel_name,
        "channel_type": r.channel_type,
        "target": r.target,
        "alert_id": r.alert_id,
        "subject": r.subject,
        "status": r.status,
        "error_message": r.error_message,
    } for r in rows]}
