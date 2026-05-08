import asyncio
import json
import os
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from fastapi import HTTPException

from app.ai_triage.schemas import AITriageResult, SOARRecommendationOut
from app.ai_triage.triage_service import run_triage_for_alert

_VALID_RESULT = AITriageResult(
    summary="Suspicious execution detected.",
    priority="high",
    confidence="high",
    false_positive_likelihood="unlikely",
    key_reasons=["curl pipe to bash"],
    recommended_next_steps=["Isolate host"],
    soar_recommendation=SOARRecommendationOut(
        recommended=True,
        action="create_case_note",
        requires_analyst_approval=True,
        reason="Evidence of exploitation.",
    ),
)


def _make_db(alert=None, assessment=None):
    db = MagicMock()
    query_mock = MagicMock()
    query_mock.filter.return_value.first.return_value = alert
    db.query.return_value = query_mock

    def _query_side_effect(model):
        q = MagicMock()
        from app import models
        if model is models.Alert:
            q.filter.return_value.first.return_value = alert
        elif model is models.AlertAssessment:
            q.filter.return_value.first.return_value = assessment
        else:
            q.filter.return_value.first.return_value = None
        return q

    db.query.side_effect = _query_side_effect
    db.add = MagicMock()
    db.commit = MagicMock()
    db.refresh = MagicMock()
    return db


def _make_alert():
    alert = MagicMock()
    alert.id = 42
    alert.title = "T1059 Alert"
    alert.severity = "HIGH"
    alert.host = "test-host"
    alert.timestamp = None
    alert.mitre_tactic = "Execution"
    alert.mitre_technique = "T1059.004"
    alert.detection_engine = "YAML"
    alert.risk_score = 80
    alert.rule_name = "Shell Rule"
    alert.description = "curl bash detected"
    alert.detection_metadata = None
    return alert


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


class TestTriageServiceFlagChecks:
    def test_disabled_flag_returns_disabled_record(self):
        db = _make_db(alert=_make_alert())
        with patch.dict(os.environ, {"AI_TRIAGE_ENABLED": "false", "GEMINI_API_KEY": "key"}):
            _run(run_triage_for_alert(42, db))
        added = db.add.call_args[0][0]
        assert added.triage_status == "disabled"

    def test_missing_api_key_returns_config_error(self):
        db = _make_db(alert=_make_alert())
        with patch.dict(os.environ, {"AI_TRIAGE_ENABLED": "true", "GEMINI_API_KEY": ""}):
            _run(run_triage_for_alert(42, db))
        added = db.add.call_args[0][0]
        assert added.triage_status == "config_error"
        assert "key" in added.error_message.lower()

    def test_alert_not_found_raises_404(self):
        db = _make_db(alert=None)
        with patch.dict(os.environ, {"AI_TRIAGE_ENABLED": "true", "GEMINI_API_KEY": "key"}):
            with pytest.raises(HTTPException) as exc_info:
                _run(run_triage_for_alert(999, db))
        assert exc_info.value.status_code == 404


class TestTriageServiceSuccess:
    def test_success_path_persists_all_fields(self):
        db = _make_db(alert=_make_alert())
        mock_provider = MagicMock()
        mock_provider.provider_name = "gemini"
        mock_provider.model_name = "gemini-2.5-flash"
        mock_provider._api_key = "test-key"
        mock_provider.run_triage = AsyncMock(return_value=(_VALID_RESULT, '{"raw": true}'))

        with patch.dict(os.environ, {"AI_TRIAGE_ENABLED": "true", "GEMINI_API_KEY": "test-key",
                                     "AI_TRIAGE_STORE_RAW_OUTPUT": "true"}):
            with patch("app.ai_triage.triage_service.GeminiProvider", return_value=mock_provider):
                _run(run_triage_for_alert(42, db))

        added = db.add.call_args[0][0]
        assert added.triage_status == "success"
        assert added.summary == "Suspicious execution detected."
        assert added.priority == "high"
        assert added.confidence == "high"
        assert added.false_positive_likelihood == "unlikely"
        assert json.loads(added.key_reasons_json) == ["curl pipe to bash"]
        assert added.raw_output_json is not None

    def test_raw_output_not_stored_when_flag_false(self):
        db = _make_db(alert=_make_alert())
        mock_provider = MagicMock()
        mock_provider.provider_name = "gemini"
        mock_provider.model_name = "gemini-2.5-flash"
        mock_provider._api_key = "test-key"
        mock_provider.run_triage = AsyncMock(return_value=(_VALID_RESULT, '{"raw": true}'))

        with patch.dict(os.environ, {"AI_TRIAGE_ENABLED": "true", "GEMINI_API_KEY": "test-key",
                                     "AI_TRIAGE_STORE_RAW_OUTPUT": "false"}):
            with patch("app.ai_triage.triage_service.GeminiProvider", return_value=mock_provider):
                _run(run_triage_for_alert(42, db))

        added = db.add.call_args[0][0]
        assert added.raw_output_json is None


class TestTriageServiceFailures:
    def test_provider_timeout_persists_failed_with_safe_message(self):
        db = _make_db(alert=_make_alert())
        mock_provider = MagicMock()
        mock_provider.provider_name = "gemini"
        mock_provider.model_name = "gemini-2.5-flash"
        mock_provider._api_key = "test-key"
        mock_provider.run_triage = AsyncMock(
            side_effect=httpx.TimeoutException("timeout")
        )

        with patch.dict(os.environ, {"AI_TRIAGE_ENABLED": "true", "GEMINI_API_KEY": "test-key"}):
            with patch("app.ai_triage.triage_service.GeminiProvider", return_value=mock_provider):
                _run(run_triage_for_alert(42, db))

        added = db.add.call_args[0][0]
        assert added.triage_status == "failed"
        assert "timed out" in added.error_message.lower()
        # Error message must not contain a stack trace or raw exception repr
        assert "TimeoutException" not in added.error_message
        assert "Traceback" not in added.error_message

    def test_invalid_output_persists_invalid_record(self):
        db = _make_db(alert=_make_alert())
        mock_provider = MagicMock()
        mock_provider.provider_name = "gemini"
        mock_provider.model_name = "gemini-2.5-flash"
        mock_provider._api_key = "test-key"
        mock_provider.run_triage = AsyncMock(
            side_effect=ValueError("AI output did not match expected schema")
        )

        with patch.dict(os.environ, {"AI_TRIAGE_ENABLED": "true", "GEMINI_API_KEY": "test-key"}):
            with patch("app.ai_triage.triage_service.GeminiProvider", return_value=mock_provider):
                _run(run_triage_for_alert(42, db))

        added = db.add.call_args[0][0]
        assert added.triage_status == "invalid_output"

    def test_generic_exception_persists_failed(self):
        db = _make_db(alert=_make_alert())
        mock_provider = MagicMock()
        mock_provider.provider_name = "gemini"
        mock_provider.model_name = "gemini-2.5-flash"
        mock_provider._api_key = "test-key"
        mock_provider.run_triage = AsyncMock(
            side_effect=RuntimeError("Gemini API returned status 500")
        )

        with patch.dict(os.environ, {"AI_TRIAGE_ENABLED": "true", "GEMINI_API_KEY": "test-key"}):
            with patch("app.ai_triage.triage_service.GeminiProvider", return_value=mock_provider):
                _run(run_triage_for_alert(42, db))

        added = db.add.call_args[0][0]
        assert added.triage_status == "failed"
