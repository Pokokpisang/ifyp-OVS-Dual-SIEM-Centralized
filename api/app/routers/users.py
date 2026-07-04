"""
routers/users.py — Users & RBAC management (admin only).

Routes
------
GET    /settings/users        HTML page
GET    /api/users             List DB users + env bootstrap accounts
POST   /api/users             Create user
PUT    /api/users/{id}        Update role / active flag / reset password
DELETE /api/users/{id}        Delete user (sessions revoked)

Role changes, deactivation, and password resets revoke the target's live
sessions (handled in user_service). Every mutation is audited.
"""
import os
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from sqlalchemy.orm import Session

from .. import db, models
from ..auth.csrf import verify_json_csrf
from ..auth.dependencies import require_admin_auth, require_admin_html
from ..auth.user_registry import ROLES
from ..services import audit_service
from ..services.alert_service import get_actor_username
from ..services.user_service import (
    UserServiceError,
    create_user,
    delete_user,
    list_users,
    update_user,
)

router = APIRouter()
templates = Jinja2Templates(directory="templates")


class UserCreate(BaseModel):
    username: str
    password: str
    role: str = "analyst"


class UserUpdate(BaseModel):
    role: Optional[str] = None
    is_active: Optional[bool] = None
    new_password: Optional[str] = None


def _user_dict(u: models.User) -> dict:
    return {
        "id": u.id,
        "username": u.username,
        "role": u.role,
        "is_active": u.is_active,
        "created_at": u.created_at.strftime("%Y-%m-%d %H:%M") if u.created_at else None,
        "last_login": u.last_login.strftime("%Y-%m-%d %H:%M") if u.last_login else None,
    }


def _env_accounts() -> list:
    accounts = []
    if os.getenv("DASHBOARD_USERNAME"):
        accounts.append({"username": os.getenv("DASHBOARD_USERNAME"),
                         "role": os.getenv("DASHBOARD_ROLE", "admin")})
    if os.getenv("CLIENT_USERNAME"):
        accounts.append({"username": os.getenv("CLIENT_USERNAME"),
                         "role": os.getenv("CLIENT_ROLE", "client")})
    return accounts


@router.get("/settings/users", response_class=HTMLResponse, dependencies=[Depends(require_admin_html)])
def view_users(request: Request):
    return templates.TemplateResponse("users.html", {
        "request": request,
        "roles": ROLES,
        "env_accounts": _env_accounts(),
    })


@router.get("/api/users", dependencies=[Depends(require_admin_auth)])
def api_list_users(database: Session = Depends(db.get_db)):
    return {
        "users": [_user_dict(u) for u in list_users(database)],
        "env_accounts": _env_accounts(),
        "roles": list(ROLES),
    }


@router.post("/api/users", dependencies=[Depends(require_admin_auth), Depends(verify_json_csrf)])
def api_create_user(body: UserCreate, request: Request, database: Session = Depends(db.get_db)):
    try:
        user = create_user(database, username=body.username, password=body.password, role=body.role)
    except UserServiceError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    audit_service.record_audit_event(
        database,
        actor=get_actor_username(request),
        action=audit_service.USER_CREATED,
        object_type="user",
        object_id=user.username,
        source_ip=audit_service.client_ip(request),
        details={"username": user.username, "role": user.role},
    )
    database.commit()
    return {"status": "ok", "user": _user_dict(user)}


@router.put("/api/users/{user_id}", dependencies=[Depends(require_admin_auth), Depends(verify_json_csrf)])
def api_update_user(user_id: int, body: UserUpdate, request: Request, database: Session = Depends(db.get_db)):
    actor = get_actor_username(request)
    try:
        user, changes = update_user(
            database, user_id,
            acting_username=actor,
            role=body.role,
            is_active=body.is_active,
            new_password=body.new_password,
        )
    except UserServiceError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if changes:
        audit_service.record_audit_event(
            database,
            actor=actor,
            action=audit_service.USER_UPDATED,
            object_type="user",
            object_id=user.username,
            source_ip=audit_service.client_ip(request),
            details={"username": user.username, **changes},
        )
    database.commit()
    return {"status": "ok", "user": _user_dict(user)}


@router.delete("/api/users/{user_id}", dependencies=[Depends(require_admin_auth), Depends(verify_json_csrf)])
def api_delete_user(user_id: int, request: Request, database: Session = Depends(db.get_db)):
    actor = get_actor_username(request)
    try:
        user = delete_user(database, user_id, acting_username=actor)
    except UserServiceError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    audit_service.record_audit_event(
        database,
        actor=actor,
        action=audit_service.USER_DELETED,
        object_type="user",
        object_id=user.username,
        source_ip=audit_service.client_ip(request),
        details={"username": user.username, "role": user.role},
    )
    database.commit()
    return {"status": "ok"}
