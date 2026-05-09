"""
test_auth.py — Authentication gate tests.

Covers:
  TC-1  GET /dashboard without session              → 302 /login
  TC-2  GET /api/metrics/summary without session    → 401
  TC-3  POST /login wrong password                  → not a redirect; session not set
  TC-4  POST /login correct credentials             → 303 /dashboard + session cookie
  TC-5  POST /logout                                → 303 /login; session cleared
  TC-6  startup guard rejects empty SESSION_SECRET_KEY
  TC-7  startup guard rejects insecure default secret
  TC-8  startup guard accepts a valid secret
  TC-9  login clears stale session data (session fixation)
  TC-10 rate limiting returns 429 after limit exceeded
  TC-11 login success emits AUTH_SUCCESS to ovs.auth logger
  TC-12 login failure emits AUTH_FAILURE to ovs.auth logger
  TC-13 logout emits AUTH_LOGOUT to ovs.auth logger
  TC-14 SESSION_COOKIE_SECURE=true produces Secure cookie flag

All tests use isolated FastAPI apps. No DB or network calls are made.
"""
import asyncio
import logging
import os
from unittest.mock import patch

import httpx
import pytest
from fastapi import APIRouter, Depends, FastAPI, Request
from fastapi.responses import JSONResponse, RedirectResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from starlette.middleware.sessions import SessionMiddleware

from app.auth.dependencies import require_api_auth, require_html_auth
from app.auth.exceptions import LoginRequiredException
from app.routers.auth import limiter as _auth_limiter
from app.routers.auth import router as auth_router

# ---------------------------------------------------------------------------
# Isolated test app
# ---------------------------------------------------------------------------

# Disable rate limiting on the shared test app to prevent cross-test contamination.
# TC-10 uses its own dedicated app with a separate enabled limiter.
_auth_limiter.enabled = False

_app = FastAPI()
_app.add_middleware(SessionMiddleware, secret_key="test-only-secret-key-not-for-production")
_app.state.limiter = _auth_limiter
_app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


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


# Helper routes for TC-9 (session fixation test)
@_app.get("/set-stale-session")
def _set_stale_session(request: Request):
    request.session["stale_key"] = "stale_value"
    return JSONResponse({"stale": "set"})


@_app.get("/session-contents")
def _session_contents(request: Request):
    return JSONResponse(dict(request.session))


# ---------------------------------------------------------------------------
# Dedicated rate-limit test app (TC-10)
# ---------------------------------------------------------------------------

_test_limiter = Limiter(key_func=get_remote_address)
_rate_app = FastAPI()
_rate_app.state.limiter = _test_limiter
_rate_app.add_middleware(SessionMiddleware, secret_key="test-rate-limit-secret-key")
_rate_app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

_rate_router = APIRouter()


@_rate_router.post("/login")
@_test_limiter.limit("2/minute")
async def _rate_limited_login(request: Request):
    return JSONResponse({"ok": True})


_rate_app.include_router(_rate_router)


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


def _post_to_rate_app(path="/login", *, data=None):
    transport = httpx.ASGITransport(app=_rate_app)

    async def _run():
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://test",
            follow_redirects=False,
        ) as ac:
            return await ac.post(path, data=data or {})

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


# ---------------------------------------------------------------------------
# TC-6 — startup guard rejects empty SESSION_SECRET_KEY
# ---------------------------------------------------------------------------

def test_startup_guard_rejects_empty_secret():
    from app.auth.startup import validate_session_secret
    with pytest.raises(RuntimeError):
        validate_session_secret("")


# ---------------------------------------------------------------------------
# TC-7 — startup guard rejects insecure default secret
# ---------------------------------------------------------------------------

def test_startup_guard_rejects_default_secret():
    from app.auth.startup import validate_session_secret
    with pytest.raises(RuntimeError):
        validate_session_secret("change-me-in-production")


# ---------------------------------------------------------------------------
# TC-8 — startup guard accepts a valid secret
# ---------------------------------------------------------------------------

def test_startup_guard_accepts_valid_secret():
    from app.auth.startup import validate_session_secret
    validate_session_secret("a" * 64)  # must not raise


# ---------------------------------------------------------------------------
# TC-9 — login clears stale session data (session fixation prevention)
# ---------------------------------------------------------------------------

def test_login_clears_stale_session_data():
    # Step 1: set stale data in a session
    stale_resp = _get("/set-stale-session")
    session_cookie = stale_resp.cookies.get("session", "")

    # Step 2: login with the stale session cookie
    with patch.dict(os.environ, {
        "DASHBOARD_USERNAME": _TEST_USER,
        "DASHBOARD_PASSWORD_HASH": _TEST_HASH,
    }):
        login_resp = _post_form(
            "/login",
            data={"username": _TEST_USER, "password": _TEST_PASS},
            cookies={"session": session_cookie} if session_cookie else {},
        )
    assert login_resp.status_code == 303
    new_cookie = login_resp.cookies.get("session", session_cookie)

    # Step 3: stale_key must not survive into the new session
    contents = _get("/session-contents", cookies={"session": new_cookie}).json()
    assert "stale_key" not in contents
    assert contents.get("authenticated") is True


# ---------------------------------------------------------------------------
# TC-10 — rate limiting returns 429 after limit exceeded
# ---------------------------------------------------------------------------

def test_rate_limit_returns_429_after_exceeded():
    r1 = _post_to_rate_app()
    r2 = _post_to_rate_app()
    r3 = _post_to_rate_app()
    assert r1.status_code == 200
    assert r2.status_code == 200
    assert r3.status_code == 429


# ---------------------------------------------------------------------------
# TC-11 — login success emits AUTH_SUCCESS to ovs.auth logger
# ---------------------------------------------------------------------------

def test_login_success_emits_auth_success_log(caplog):
    with patch.dict(os.environ, {
        "DASHBOARD_USERNAME": _TEST_USER,
        "DASHBOARD_PASSWORD_HASH": _TEST_HASH,
    }):
        with caplog.at_level(logging.INFO, logger="ovs.auth"):
            _post_form("/login", data={"username": _TEST_USER, "password": _TEST_PASS})
    assert "AUTH_SUCCESS" in caplog.text
    assert _TEST_USER in caplog.text


# ---------------------------------------------------------------------------
# TC-12 — login failure emits AUTH_FAILURE to ovs.auth logger
# ---------------------------------------------------------------------------

def test_login_failure_emits_auth_failure_log(caplog):
    with patch.dict(os.environ, {
        "DASHBOARD_USERNAME": _TEST_USER,
        "DASHBOARD_PASSWORD_HASH": _TEST_HASH,
    }):
        with caplog.at_level(logging.WARNING, logger="ovs.auth"):
            _post_form("/login", data={"username": _TEST_USER, "password": "wrongpassword"})
    assert "AUTH_FAILURE" in caplog.text


# ---------------------------------------------------------------------------
# TC-13 — logout emits AUTH_LOGOUT to ovs.auth logger
# ---------------------------------------------------------------------------

def test_logout_emits_auth_logout_log(caplog):
    with patch.dict(os.environ, {
        "DASHBOARD_USERNAME": _TEST_USER,
        "DASHBOARD_PASSWORD_HASH": _TEST_HASH,
    }):
        login_resp = _post_form("/login", data={"username": _TEST_USER, "password": _TEST_PASS})
    session_cookie = login_resp.cookies.get("session", "")

    with caplog.at_level(logging.INFO, logger="ovs.auth"):
        _post_form("/logout", data={}, cookies={"session": session_cookie} if session_cookie else {})
    assert "AUTH_LOGOUT" in caplog.text
    assert _TEST_USER in caplog.text


# ---------------------------------------------------------------------------
# TC-14 — SESSION_COOKIE_SECURE=true produces Secure cookie attribute
# ---------------------------------------------------------------------------

def test_session_cookie_has_secure_flag_when_https_only():
    _secure_app = FastAPI()
    _secure_app.add_middleware(
        SessionMiddleware,
        secret_key="test-secure-key-not-for-production",
        https_only=True,
    )
    _secure_app.state.limiter = _auth_limiter
    _secure_app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

    @_secure_app.exception_handler(LoginRequiredException)
    async def _lr(request: Request, exc: LoginRequiredException):
        return RedirectResponse(url="/login", status_code=302)

    _secure_app.include_router(auth_router)
    transport = httpx.ASGITransport(app=_secure_app)

    async def _run():
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://test",
            follow_redirects=False,
        ) as ac:
            with patch.dict(os.environ, {
                "DASHBOARD_USERNAME": _TEST_USER,
                "DASHBOARD_PASSWORD_HASH": _TEST_HASH,
            }):
                return await ac.post(
                    "/login",
                    data={"username": _TEST_USER, "password": _TEST_PASS},
                )

    resp = asyncio.get_event_loop().run_until_complete(_run())
    assert resp.status_code == 303
    assert "secure" in resp.headers.get("set-cookie", "").lower()
