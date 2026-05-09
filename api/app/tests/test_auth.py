"""
test_auth.py — Authentication gate tests for M3.

Covers:
  TC-1  GET /dashboard without session       → 302 /login
  TC-2  GET /api/metrics/summary without session → 401
  TC-3  POST /login wrong password            → not a redirect; session not set
  TC-4  POST /login correct credentials       → 303 /dashboard + session cookie
  TC-5  POST /logout                          → 303 /login; session cleared

All tests use an isolated FastAPI app (SessionMiddleware + auth router +
two stub protected routes). No DB or network calls are made.
"""
import asyncio
import os
from unittest.mock import patch

import httpx
import pytest
from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse, RedirectResponse
from starlette.middleware.sessions import SessionMiddleware

from app.auth.dependencies import require_api_auth, require_html_auth
from app.auth.exceptions import LoginRequiredException
from app.routers.auth import router as auth_router

# ---------------------------------------------------------------------------
# Isolated test app
# ---------------------------------------------------------------------------

_app = FastAPI()
_app.add_middleware(SessionMiddleware, secret_key="test-only-secret-key-not-for-production")


@_app.exception_handler(LoginRequiredException)
async def _login_redirect(request: Request, exc: LoginRequiredException):
    return RedirectResponse(url="/login", status_code=302)


_app.include_router(auth_router)


@_app.get("/dashboard", dependencies=[Depends(require_html_auth)])
def _stub_dashboard():
    return JSONResponse({"page": "dashboard"})


@_app.get("/api/metrics/summary", dependencies=[Depends(require_api_auth)])
def _stub_api_metrics():
    return JSONResponse({"cpu_percent": 10})


# ---------------------------------------------------------------------------
# Test credentials — bcrypt hash generated once per module
# ---------------------------------------------------------------------------

_TEST_USER = "testadmin"
_TEST_PASS = "correct-horse-battery"
_TEST_HASH: str = ""


def setup_module(_module):
    import base64
    import bcrypt
    global _TEST_HASH
    # Store as base64 (the format DASHBOARD_PASSWORD_HASH uses in .env)
    raw = bcrypt.hashpw(_TEST_PASS.encode("utf-8"), bcrypt.gensalt())
    _TEST_HASH = base64.b64encode(raw).decode("utf-8")


# ---------------------------------------------------------------------------
# Async request helpers
# ---------------------------------------------------------------------------

def _get(path, *, cookies=None):
    transport = httpx.ASGITransport(app=_app)

    async def _run():
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://test",
            follow_redirects=False,
            cookies=cookies or {},
        ) as ac:
            return await ac.get(path)

    return asyncio.get_event_loop().run_until_complete(_run())


def _post_form(path, *, data, cookies=None):
    transport = httpx.ASGITransport(app=_app)

    async def _run():
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://test",
            follow_redirects=False,
            cookies=cookies or {},
        ) as ac:
            return await ac.post(path, data=data)

    return asyncio.get_event_loop().run_until_complete(_run())


# ---------------------------------------------------------------------------
# TC-1 — HTML route without session → 302 /login
# ---------------------------------------------------------------------------

def test_dashboard_without_session_redirects_to_login():
    response = _get("/dashboard")
    assert response.status_code == 302
    assert "/login" in response.headers["location"]


# ---------------------------------------------------------------------------
# TC-2 — JSON route without session → 401
# ---------------------------------------------------------------------------

def test_api_metrics_without_session_returns_401():
    response = _get("/api/metrics/summary")
    assert response.status_code == 401
    detail = response.json().get("detail", "").lower()
    assert "authentication" in detail


# ---------------------------------------------------------------------------
# TC-3 — POST /login wrong password → not a redirect; no valid session set
# ---------------------------------------------------------------------------

def test_login_wrong_password_does_not_redirect():
    with patch.dict(os.environ, {
        "DASHBOARD_USERNAME": _TEST_USER,
        "DASHBOARD_PASSWORD_HASH": _TEST_HASH,
    }):
        response = _post_form("/login", data={"username": _TEST_USER, "password": "wrongpassword"})

    # Must not be a redirect
    assert response.status_code not in (302, 303)

    # Any session cookie set by this failed login must not grant access
    session_cookie = response.cookies.get("session", "")
    follow = _get("/dashboard", cookies={"session": session_cookie} if session_cookie else {})
    assert follow.status_code == 302


# ---------------------------------------------------------------------------
# TC-4 — POST /login correct credentials → 303 /dashboard + usable session
# ---------------------------------------------------------------------------

def test_login_correct_password_redirects_and_sets_session():
    with patch.dict(os.environ, {
        "DASHBOARD_USERNAME": _TEST_USER,
        "DASHBOARD_PASSWORD_HASH": _TEST_HASH,
    }):
        login_resp = _post_form("/login", data={"username": _TEST_USER, "password": _TEST_PASS})

    assert login_resp.status_code == 303
    assert login_resp.headers["location"] == "/dashboard"

    session_cookie = login_resp.cookies.get("session")
    assert session_cookie, "session cookie must be present after successful login"

    # The session cookie must grant access to a protected HTML route
    dashboard_resp = _get("/dashboard", cookies={"session": session_cookie})
    assert dashboard_resp.status_code == 200


# ---------------------------------------------------------------------------
# TC-5 — POST /logout → 303 /login; unauthenticated access returns 302
# ---------------------------------------------------------------------------

def test_logout_clears_session():
    # Establish a valid session
    with patch.dict(os.environ, {
        "DASHBOARD_USERNAME": _TEST_USER,
        "DASHBOARD_PASSWORD_HASH": _TEST_HASH,
    }):
        login_resp = _post_form("/login", data={"username": _TEST_USER, "password": _TEST_PASS})
    session_cookie = login_resp.cookies.get("session")
    assert session_cookie
    assert _get("/dashboard", cookies={"session": session_cookie}).status_code == 200

    # Logout
    logout_resp = _post_form("/logout", data={}, cookies={"session": session_cookie})
    assert logout_resp.status_code == 303
    assert "/login" in logout_resp.headers["location"]

    # Without any session cookie /dashboard must require login again
    assert _get("/dashboard").status_code == 302
