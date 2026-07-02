"""
test_collector_auth.py — Authentication enforcement tests for POST /ingest/log.

Covers H2 (security hardening): X-Agent-Key must be present and valid.
No real DB or network calls are made — all external dependencies are mocked.

Uses httpx.AsyncClient + ASGITransport (compatible with httpx >= 0.20, tested
against httpx 0.28.x where starlette.testclient.TestClient is not usable).
"""
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from fastapi import FastAPI

from app.routers.collector import router
from app import db

# ---------------------------------------------------------------------------
# Isolated app — only the collector router, no startup migrations
# ---------------------------------------------------------------------------

_app = FastAPI()
_app.include_router(router)


def _mock_db():
    """Yield a MagicMock in place of a real SQLAlchemy session."""
    yield MagicMock()


_app.dependency_overrides[db.get_db] = _mock_db

# ---------------------------------------------------------------------------
# Async request helper — mirrors the asyncio pattern used in existing tests
# ---------------------------------------------------------------------------

def _post(path, *, json=None, headers=None):
    """Send a POST to the isolated test app synchronously."""
    transport = httpx.ASGITransport(app=_app)

    async def _run():
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            return await ac.post(path, json=json, headers=headers or {})

    return asyncio.get_event_loop().run_until_complete(_run())


# ---------------------------------------------------------------------------
# Fixture data
# ---------------------------------------------------------------------------

_VALID_META = {
    "agent_id": "test-agent-uuid",
    "hostname": "test-host",
    "ip_address": "10.0.0.1",
    "os_type": "linux",
    "distribution": "ubuntu",
    "agent_name": "test-agent",
}

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_missing_key_returns_401():
    """No X-Agent-Key header → 401 before any processing occurs."""
    response = _post("/ingest/log", json={"message": "test"})
    assert response.status_code == 401
    assert "required" in response.json()["detail"].lower()


@patch("app.auth.dependencies.get_agent_metadata_by_key", return_value=None)
def test_invalid_key_returns_401(mock_meta):
    """X-Agent-Key present but not found in DB → 401."""
    response = _post(
        "/ingest/log",
        json={"message": "test"},
        headers={"X-Agent-Key": "not-a-real-key"},
    )
    assert response.status_code == 401
    assert "invalid" in response.json()["detail"].lower()
    mock_meta.assert_called_once()


@patch("app.routers.collector.forward_to_data_prepper", new_callable=AsyncMock)
@patch("app.routers.collector.process_log_for_alerts", new_callable=AsyncMock)
@patch("app.auth.dependencies.update_last_seen", return_value=True)
@patch("app.auth.dependencies.get_agent_metadata_by_key", return_value=_VALID_META)
def test_valid_key_accepts_log(mock_meta, mock_update, mock_alerts, mock_forward):
    """Valid registered key → 200 accepted; enrichment and side-effects fire."""
    response = _post(
        "/ingest/log",
        json={"message": "ssh login", "log_type": "auth"},
        headers={"X-Agent-Key": "valid-registered-key"},
    )
    assert response.status_code == 200
    assert response.json() == {"status": "accepted"}
    mock_meta.assert_called_once()
    mock_update.assert_called_once()
