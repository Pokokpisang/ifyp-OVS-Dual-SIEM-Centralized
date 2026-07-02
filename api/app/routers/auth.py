import logging

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from slowapi import Limiter
from slowapi.util import get_remote_address
from sqlalchemy.orm import Session

from .. import db as _db
from ..auth.csrf import verify_form_csrf
from ..auth.custom_rate_limit import client_host_key
from ..auth.session_store import create_session, delete_session
from ..auth.user_registry import authenticate
from ..services.audit_service import (
    LOGIN_FAILURE,
    LOGIN_SUCCESS,
    LOGOUT,
    record_audit_event,
)

router = APIRouter()
templates = Jinja2Templates(directory="templates")
logger = logging.getLogger("ovs.auth")

# ST-040: Use TCP peer address instead of X-Forwarded-For to prevent rate-limit bypass.
limiter = Limiter(key_func=client_host_key)


@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request, "error": None})


@router.post("/login")
@limiter.limit("5/minute")
async def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    database: Session = Depends(_db.get_db),
):
    role = authenticate(username, password)

    if role is not None:
        # Revoke any existing server session before creating a new one.
        old_token = request.session.get("session_token")
        if old_token:
            delete_session(old_token, database)
        request.session.clear()

        raw_token = create_session(username, role, database)
        request.session["session_token"] = raw_token

        logger.info("AUTH_SUCCESS username=%s role=%s ip=%s", username, role, get_remote_address(request))
        record_audit_event(
            database,
            actor=username,
            action=LOGIN_SUCCESS,
            details={"role": role, "ip": get_remote_address(request)},
            commit=True,
        )
        return RedirectResponse(url="/dashboard", status_code=303)

    logger.warning("AUTH_FAILURE username=%s ip=%s", username, get_remote_address(request))
    record_audit_event(
        database,
        actor=username,
        action=LOGIN_FAILURE,
        details={"ip": get_remote_address(request), "reason": "invalid_credentials"},
        commit=True,
    )
    return templates.TemplateResponse(
        "login.html",
        {"request": request, "error": "Invalid credentials."},
        status_code=401,
    )


@router.post("/logout", dependencies=[Depends(verify_form_csrf)])
async def logout(request: Request, database: Session = Depends(_db.get_db)):
    # ST-010: Delete server-side session row so old cookie replays fail immediately.
    raw_token = request.session.get("session_token")
    username = (request.state.user or {}).get("username", "<unknown>") if hasattr(request.state, "user") else "<unknown>"
    if raw_token:
        delete_session(raw_token, database)
    request.session.clear()
    logger.info("AUTH_LOGOUT username=%s ip=%s", username, get_remote_address(request))
    record_audit_event(
        database,
        actor=username,
        action=LOGOUT,
        details={"ip": get_remote_address(request)},
        commit=True,
    )
    return RedirectResponse(url="/login", status_code=303)
