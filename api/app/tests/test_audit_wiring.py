"""
test_audit_wiring.py — proves the router-layer events write ActivityAudit rows
(alert status change, agent registration, agent key rotation, AI-triage request),
and that no secrets land in details.
"""
import asyncio
import json
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import httpx
from fastapi import FastAPI
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import db as _db_module
from app import models
from app.models import Base
from app.services import audit_service

_engine = create_engine(
    "sqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
Base.metadata.create_all(_engine)
_Session = sessionmaker(bind=_engine)


def _override_get_db():
    s = _Session()
    try:
        yield s
    finally:
        s.close()


def _clear():
    s = _Session()
    for m in (models.ActivityAudit, models.AIAlertTriage, models.AlertAssessment, models.Alert):
        s.query(m).delete()
    s.commit()
    s.close()


def _audit(action):
    s = _Session()
    try:
        return s.query(models.ActivityAudit).filter_by(action=action).all()
    finally:
        s.close()


def _seed_alert() -> int:
    from datetime import datetime
    s = _Session()
    a = models.Alert(timestamp=datetime(2026, 1, 1), host="h", severity="high",
                     title="t", description="d", rule_name="r", detection_engine="YAML")
    s.add(a)
    s.commit()
    aid = a.id
    s.close()
    return aid


# ---------------------------------------------------------------------------
# Alert status change → ALERT_STATUS_CHANGED
# ---------------------------------------------------------------------------

def test_alert_status_change_writes_audit():
    from app.routers.api_metrics import router
    from app.auth.dependencies import require_api_auth
    from app.auth.csrf import verify_json_csrf

    _clear()
    alert_id = _seed_alert()

    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[_db_module.get_db] = _override_get_db
    app.dependency_overrides[require_api_auth] = lambda: None
    app.dependency_overrides[verify_json_csrf] = lambda: None

    async def _run():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            return await ac.put(
                f"/api/alerts/{alert_id}/assessment",
                json={"status": "Investigating", "analyst_notes": "secret note stays out of audit"},
            )

    resp = asyncio.get_event_loop().run_until_complete(_run())
    assert resp.status_code == 200

    rows = _audit(audit_service.ALERT_STATUS_CHANGED)
    assert rows, "expected an ALERT_STATUS_CHANGED row"
    details = json.loads(rows[-1].details)
    assert details == {"from": "New", "to": "Investigating"}
    # analyst notes must NOT be in the audit trail
    assert "secret note" not in (rows[-1].details or "")


# ---------------------------------------------------------------------------
# Agent registration → AGENT_REGISTERED (no key stored)
# ---------------------------------------------------------------------------

def test_agent_registration_writes_audit_without_key():
    from app.routers.agents import router

    _clear()
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[_db_module.get_db] = _override_get_db

    async def _run():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            return await ac.post(
                "/api/agents/register",
                headers={"X-Agent-Token": "one-time-token"},
                json={"hostname": "vps-7", "ip_address": "10.0.0.7", "os": "linux", "arch": "x86_64"},
            )

    with patch("app.routers.agents.register_agent", return_value="SUPER-SECRET-AGENT-KEY"):
        resp = asyncio.get_event_loop().run_until_complete(_run())
    assert resp.status_code == 200

    rows = _audit(audit_service.AGENT_REGISTERED)
    assert rows, "expected an AGENT_REGISTERED row"
    row = rows[-1]
    assert row.actor == "agent:vps-7"
    details = json.loads(row.details)
    assert details == {"hostname": "vps-7", "ip": "10.0.0.7", "os": "linux", "arch": "x86_64"}
    assert "SUPER-SECRET-AGENT-KEY" not in (row.details or "")


# ---------------------------------------------------------------------------
# AI triage request → AI_TRIAGE_REQUESTED (no prompt/response stored)
# ---------------------------------------------------------------------------

def test_ai_triage_request_writes_audit():
    from app.routers.ai_triage import router
    from app.auth.csrf import verify_json_csrf

    _clear()
    alert_id = _seed_alert()

    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[_db_module.get_db] = _override_get_db
    app.dependency_overrides[verify_json_csrf] = lambda: None

    async def _run():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            return await ac.post(f"/api/alerts/{alert_id}/ai-triage")

    # AI_TRIAGE_ENABLED defaults to false → run_triage returns a "disabled" row,
    # no external call.
    resp = asyncio.get_event_loop().run_until_complete(_run())
    assert resp.status_code == 200

    rows = _audit(audit_service.AI_TRIAGE_REQUESTED)
    assert rows, "expected an AI_TRIAGE_REQUESTED row"
    details = json.loads(rows[-1].details)
    assert set(details.keys()) == {"provider", "triage_status"}  # nothing else leaks


# ---------------------------------------------------------------------------
# Agent key rotation → AGENT_KEY_ROTATED (new token never stored)
# ---------------------------------------------------------------------------

def test_agent_key_rotation_writes_audit_without_token():
    import app.routers.dashboard as dash

    _clear()
    session = _Session()
    fake_agent = SimpleNamespace(
        hostname="vps-9", agent_name="vps-9",
        enable_logs=True, enable_fim=False, enable_metrics=True,
    )
    request = SimpleNamespace(state=SimpleNamespace(user={"username": "admin"}))

    with (
        patch.object(dash, "get_agent_by_id", return_value=fake_agent),
        patch.object(dash, "compute_agent_status", return_value="online"),
        patch.object(dash, "get_latest_agent_metrics", return_value=None),
        patch.object(dash, "get_recent_agent_alerts", return_value=[]),
        patch.object(dash, "get_recent_agent_logs", return_value=[]),
        patch("app.services.agent_service.regenerate_agent_token", return_value="NEW-SECRET-TOKEN-123"),
        patch.object(dash, "get_server_address", return_value="http://server"),
        patch.object(dash, "normalize_server_url", return_value="http://server:8000"),
        patch("app.services.installer_service.get_reinstall_command", return_value="curl ... | bash"),
        patch.object(dash, "templates", MagicMock()),
    ):
        dash.get_agent_detail(request=request, agent_id="a-9", reinstall=True, database=session)

    session.close()
    rows = _audit(audit_service.AGENT_KEY_ROTATED)
    assert rows, "expected an AGENT_KEY_ROTATED row"
    row = rows[-1]
    assert row.object_id == "a-9"
    assert row.actor == "admin"
    assert "NEW-SECRET-TOKEN-123" not in (row.details or "")
