"""
test_metrics_auth.py — POST /api/metrics X-Agent-Key enforcement (ST-023).

TC-MA-1  Missing X-Agent-Key → 422 (required header absent)
TC-MA-2  Invalid X-Agent-Key → 401
TC-MA-3  Valid X-Agent-Key → 200
"""
import asyncio
from unittest.mock import patch

import httpx
from fastapi import FastAPI
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import db as _db_module
from app.models import Base
from app.routers.api_metrics import router as metrics_router

_engine = create_engine(
    "sqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
Base.metadata.create_all(_engine)
_TestSession = sessionmaker(bind=_engine)
_db_module.SessionLocal = _TestSession


def _override_get_db():
    s = _TestSession()
    try:
        yield s
    finally:
        s.close()


_app = FastAPI()
_app.include_router(metrics_router)
_app.dependency_overrides[_db_module.get_db] = _override_get_db


def _post_metrics(headers: dict) -> httpx.Response:
    transport = httpx.ASGITransport(app=_app)

    async def _run():
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            return await ac.post(
                "/api/metrics",
                json={
                    "timestamp": "2024-01-01T00:00:00",
                    "host": "test-host",
                    "cpu_percent": 10.0,
                    "ram_percent": 20.0,
                    "net_in_bytes": 0,
                    "net_out_bytes": 0,
                },
                headers=headers,
            )

    return asyncio.get_event_loop().run_until_complete(_run())


# TC-MA-1 — Missing header → 422
def test_missing_agent_key_returns_422():
    resp = _post_metrics({})
    assert resp.status_code == 422


# TC-MA-2 — Invalid key → 401
def test_invalid_agent_key_returns_401():
    with patch("app.routers.api_metrics.get_agent_metadata_by_key", return_value=None):
        resp = _post_metrics({"x-agent-key": "bad-key"})
    assert resp.status_code == 401


# TC-MA-3 — Valid key → 200
def test_valid_agent_key_returns_200():
    with (
        patch("app.routers.api_metrics.get_agent_metadata_by_key", return_value={"agent_id": "a1"}),
        patch("app.routers.api_metrics.update_last_seen"),
    ):
        resp = _post_metrics({"x-agent-key": "valid-key-abc"})
    assert resp.status_code == 200
