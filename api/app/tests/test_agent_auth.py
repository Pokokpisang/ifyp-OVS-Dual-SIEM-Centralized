"""
test_agent_auth.py — unit tests for the shared ``require_agent_key`` dependency.

The dependency centralises agent authentication for POST /ingest/log and
POST /api/metrics. It authenticates by X-Agent-Key, refreshes last_seen, and
raises 401 uniformly for missing or unrecognised keys.
"""
from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException

from app.auth.dependencies import require_agent_key

_VALID_META = {"agent_id": "a1", "hostname": "h1"}


def test_missing_key_raises_401():
    with pytest.raises(HTTPException) as exc:
        require_agent_key(x_agent_key=None, database=MagicMock())
    assert exc.value.status_code == 401
    assert "required" in exc.value.detail.lower()


@patch("app.auth.dependencies.get_agent_metadata_by_key", return_value=None)
def test_unknown_key_raises_401(mock_meta):
    with pytest.raises(HTTPException) as exc:
        require_agent_key(x_agent_key="nope", database=MagicMock())
    assert exc.value.status_code == 401
    assert "invalid" in exc.value.detail.lower()
    mock_meta.assert_called_once()


@patch("app.auth.dependencies.update_last_seen", return_value=True)
@patch("app.auth.dependencies.get_agent_metadata_by_key", return_value=_VALID_META)
def test_valid_key_returns_meta_and_touches_last_seen(mock_meta, mock_update):
    db = MagicMock()
    result = require_agent_key(x_agent_key="good", database=db)
    assert result == _VALID_META
    mock_meta.assert_called_once_with(agent_key="good", db=db)
    mock_update.assert_called_once_with(agent_key="good", db=db)
