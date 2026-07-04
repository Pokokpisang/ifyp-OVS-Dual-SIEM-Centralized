"""
test_soar_audit.py — SOAR audit identity tests (ST-027).

Verifies that run/approve/reject use the authenticated session username,
not a client-supplied 'executed_by'/'approved_by'/'rejected_by' field.

TC-SA-1  POST /api/alerts/{id}/soar/run uses session username in audit log
TC-SA-2  POST /api/alerts/{id}/soar/executions/{id}/approve uses session username
TC-SA-3  POST /api/alerts/{id}/soar/executions/{id}/reject uses session username
"""
import asyncio
import os
from unittest.mock import MagicMock, patch

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from starlette.middleware.sessions import SessionMiddleware

from app import db as _db_module
import app.auth.session_middleware as _session_mw_module
from app.auth.session_middleware import ServerSessionMiddleware
from app.auth.session_store import create_session
from app.models import Base
from app.routers.soar import router as soar_router

_engine = create_engine(
    "sqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
Base.metadata.create_all(_engine)
_TestSession = sessionmaker(bind=_engine)

_app = FastAPI()
_app.add_middleware(ServerSessionMiddleware)
_app.add_middleware(SessionMiddleware, secret_key="soar-audit-test-key-not-for-prod")
_app.include_router(soar_router)
_app.dependency_overrides[_db_module.get_db] = lambda: _TestSession()


@_app.get("/test/set-session")
def _set_session(token: str, request: Request):
    request.session["session_token"] = token
    return JSONResponse({"ok": True})


def setup_module(_module):
    _db_module.SessionLocal = _TestSession
    _session_mw_module.SessionLocal = _TestSession
    os.environ["CSRF_STRICT_JSON"] = "false"


def _make_admin_cookies(username: str = "audit_admin") -> dict:
    db = _TestSession()
    raw_token = create_session(username, "admin", db)
    db.close()
    transport = httpx.ASGITransport(app=_app)

    async def _run():
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            seed = await ac.get(f"/test/set-session?token={raw_token}")
            return dict(seed.cookies)

    return asyncio.get_event_loop().run_until_complete(_run())


def _post_json(path: str, body: dict, cookies: dict) -> httpx.Response:
    transport = httpx.ASGITransport(app=_app)

    async def _run():
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://test",
            follow_redirects=False,
        ) as ac:
            ac.cookies.update(cookies)
            return await ac.post(path, json=body, headers={"origin": "http://test"})

    return asyncio.get_event_loop().run_until_complete(_run())


# ---------------------------------------------------------------------------
# TC-SA-1 — run_action uses session username, not body field
# ---------------------------------------------------------------------------

def test_soar_run_uses_session_username():
    cookies = _make_admin_cookies("session_analyst")
    captured = {}

    def _mock_run_action(alert_id, playbook_id, action_id, db, executed_by, source_ip=None):
        captured["executed_by"] = executed_by
        result = MagicMock()
        result.model_dump.return_value = {"status": "executed", "message": "ok"}
        return result

    with patch("app.routers.soar.run_action", side_effect=_mock_run_action):
        _post_json(
            "/api/alerts/1/soar/run",
            {"playbook_id": "pb1", "action_id": "a1"},
            cookies,
        )

    assert captured.get("executed_by") == "session_analyst"


# ---------------------------------------------------------------------------
# TC-SA-2 — approve_action uses session username, not body field
# ---------------------------------------------------------------------------

def test_soar_approve_uses_session_username():
    cookies = _make_admin_cookies("approve_admin")
    captured = {}

    def _mock_approve(alert_id, execution_id, db, approved_by, source_ip=None):
        captured["approved_by"] = approved_by
        result = MagicMock()
        result.model_dump.return_value = {"status": "approved"}
        return result

    with patch("app.routers.soar.approve_action", side_effect=_mock_approve):
        _post_json(
            "/api/alerts/1/soar/executions/99/approve",
            {},
            cookies,
        )

    assert captured.get("approved_by") == "approve_admin"


# ---------------------------------------------------------------------------
# TC-SA-3 — reject_action uses session username, not body field
# ---------------------------------------------------------------------------

def test_soar_reject_uses_session_username():
    cookies = _make_admin_cookies("reject_admin")
    captured = {}

    def _mock_reject(alert_id, execution_id, db, rejected_by, source_ip=None):
        captured["rejected_by"] = rejected_by
        return {"status": "rejected"}

    with patch("app.routers.soar.reject_action", side_effect=_mock_reject):
        _post_json(
            "/api/alerts/1/soar/executions/99/reject",
            {},
            cookies,
        )

    assert captured.get("rejected_by") == "reject_admin"
