"""
test_rbac.py — Role-Based Access Control tests (ST-012, ST-037).

TC-RBAC-1  Unauthenticated request to admin API endpoint → 401
TC-RBAC-2  Client-role user accessing admin-only endpoint → 403
TC-RBAC-3  Admin-role user accessing admin-only endpoint → not 403/401
TC-RBAC-4  Client-role user can access read-only authenticated endpoint
TC-RBAC-5  Client-role user cannot trigger SOAR run (admin-only)
"""
import asyncio
import os

import httpx
from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from starlette.middleware.sessions import SessionMiddleware

from app import db as _db_module
import app.auth.session_middleware as _session_mw_module
from app.auth.dependencies import require_api_auth, require_admin_auth
from app.auth.session_middleware import ServerSessionMiddleware
from app.auth.session_store import create_session
from app.models import Base

# ---------------------------------------------------------------------------
# Isolated test app — patching is done in setup_module before any test runs
# ---------------------------------------------------------------------------

_engine = create_engine(
    "sqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
Base.metadata.create_all(_engine)
_TestSession = sessionmaker(bind=_engine)

_app = FastAPI()
_app.add_middleware(ServerSessionMiddleware)
_app.add_middleware(SessionMiddleware, secret_key="rbac-test-secret-key-not-for-prod")


@_app.get("/api/read-only", dependencies=[Depends(require_api_auth)])
def _read_only():
    return JSONResponse({"ok": True})


@_app.get("/api/admin-only", dependencies=[Depends(require_admin_auth)])
def _admin_only():
    return JSONResponse({"ok": True})


@_app.get("/test/set-session")
def _set_session(token: str, request: Request):
    request.session["session_token"] = token
    return JSONResponse({"ok": True})


def setup_module(_module):
    # Patch global session factories to use this module's in-memory SQLite engine.
    # Done in setup_module (not at import time) so it runs after test_auth.py's
    # setup_module, preventing cross-module global state trampling.
    _db_module.SessionLocal = _TestSession
    _session_mw_module.SessionLocal = _TestSession
    os.environ["CSRF_STRICT_JSON"] = "false"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_session_cookies(username: str, role: str) -> dict:
    """Create a server session in SQLite and return the signed session cookie dict."""
    db = _TestSession()
    raw_token = create_session(username, role, db)
    db.close()
    transport = httpx.ASGITransport(app=_app)

    async def _run():
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            seed = await ac.get(f"/test/set-session?token={raw_token}")
            return dict(seed.cookies)

    return asyncio.get_event_loop().run_until_complete(_run())


def _get_authed(path: str, username: str, role: str) -> httpx.Response:
    cookies = _make_session_cookies(username, role)
    transport = httpx.ASGITransport(app=_app)

    async def _run():
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://test",
        ) as ac:
            # Set cookies on the client instance (not per-request) to avoid deprecation.
            ac.cookies.update(cookies)
            return await ac.get(path)

    return asyncio.get_event_loop().run_until_complete(_run())


# ---------------------------------------------------------------------------
# TC-RBAC-1 — Unauthenticated → 401
# ---------------------------------------------------------------------------

def test_unauthenticated_admin_endpoint_returns_401():
    transport = httpx.ASGITransport(app=_app)

    async def _run():
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            return await ac.get("/api/admin-only")

    resp = asyncio.get_event_loop().run_until_complete(_run())
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# TC-RBAC-2 — Client role on admin endpoint → 403
# ---------------------------------------------------------------------------

def test_client_role_on_admin_endpoint_returns_403():
    resp = _get_authed("/api/admin-only", "client_user", "client")
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# TC-RBAC-3 — Admin role on admin endpoint → success (not 401/403)
# ---------------------------------------------------------------------------

def test_admin_role_on_admin_endpoint_succeeds():
    resp = _get_authed("/api/admin-only", "admin_user", "admin")
    assert resp.status_code not in (401, 403)


# ---------------------------------------------------------------------------
# TC-RBAC-4 — Client role can access read-only endpoint
# ---------------------------------------------------------------------------

def test_client_role_can_access_readonly_endpoint():
    resp = _get_authed("/api/read-only", "client_user", "client")
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# TC-RBAC-5 — Client role cannot trigger SOAR run (admin-only)
# ---------------------------------------------------------------------------

def test_client_role_cannot_trigger_soar_run():
    resp = _get_authed("/api/admin-only", "attacker", "client")
    assert resp.status_code == 403
