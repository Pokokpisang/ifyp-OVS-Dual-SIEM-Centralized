import base64
import logging
import os

import bcrypt as _bcrypt
from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from slowapi import Limiter
from slowapi.util import get_remote_address

router = APIRouter()
templates = Jinja2Templates(directory="templates")
logger = logging.getLogger("ovs.auth")

# M3: Initialize at module load time to avoid timing variance on the first login request.
_DUMMY_HASH: bytes = _bcrypt.hashpw(b"__dummy__", _bcrypt.gensalt())

limiter = Limiter(key_func=get_remote_address)


@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request, "error": None})


@router.post("/login")
@limiter.limit("5/minute")
async def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
):
    expected_user = os.getenv("DASHBOARD_USERNAME", "")
    hash_b64 = os.getenv("DASHBOARD_PASSWORD_HASH", "")
    try:
        expected_hash = base64.b64decode(hash_b64 + "==").decode("utf-8") if hash_b64 else ""
    except Exception:
        expected_hash = ""

    # M3: Always run checkpw to prevent username-enumeration via timing side-channel.
    check_hash = expected_hash.encode("utf-8") if expected_hash else _DUMMY_HASH
    try:
        password_matches = _bcrypt.checkpw(password.encode("utf-8"), check_hash)
    except Exception:
        password_matches = False

    valid = bool(expected_user) and username == expected_user and password_matches
    if valid:
        # RF-2: Clear any stale session data before writing authenticated state.
        request.session.clear()
        request.session["authenticated"] = True
        logger.info("AUTH_SUCCESS username=%s ip=%s", username, get_remote_address(request))
        return RedirectResponse(url="/dashboard", status_code=303)

    logger.warning("AUTH_FAILURE username=%s ip=%s", username, get_remote_address(request))
    return templates.TemplateResponse(
        "login.html",
        {"request": request, "error": "Invalid credentials."},
        status_code=401,
    )


@router.post("/logout")
async def logout(request: Request):
    username = request.session.get("username", "<unknown>")
    request.session.clear()
    logger.info("AUTH_LOGOUT username=%s ip=%s", username, get_remote_address(request))
    return RedirectResponse(url="/login", status_code=303)
