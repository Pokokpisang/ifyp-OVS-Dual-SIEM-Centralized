import asyncio
import json
import os
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from app.ai_triage.providers.gemini_provider import GeminiProvider

_VALID_RESPONSE = {
    "summary": "Suspicious curl-bash pipe detected on test-host.",
    "priority": "high",
    "confidence": "high",
    "false_positive_likelihood": "unlikely",
    "key_reasons": ["curl used to fetch remote script", "piped directly into bash"],
    "recommended_next_steps": ["Isolate host", "Collect process tree"],
    "soar_recommendation": {
        "recommended": True,
        "action": "create_case_note",
        "requires_analyst_approval": True,
        "reason": "Evidence suggests active exploitation attempt.",
    },
}


def _make_mock_response(status_code: int, body: dict) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = body
    return resp


def _gemini_body(text: str) -> dict:
    return {"candidates": [{"content": {"parts": [{"text": text}]}}]}


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


class TestGeminiProviderSuccess:
    def test_successful_response_returns_result(self):
        raw_json = json.dumps(_VALID_RESPONSE)
        mock_resp = _make_mock_response(200, _gemini_body(raw_json))

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_resp)
        mock_ctx = MagicMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_client)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)

        with patch.dict(os.environ, {"GEMINI_API_KEY": "test-key"}):
            with patch("app.ai_triage.providers.gemini_provider.httpx.AsyncClient", return_value=mock_ctx):
                provider = GeminiProvider()
                result, raw = _run(provider.run_triage("test prompt"))

        assert result.priority == "high"
        assert result.confidence == "high"
        assert result.false_positive_likelihood == "unlikely"
        assert len(result.key_reasons) == 2
        assert result.soar_recommendation.requires_analyst_approval is True
        assert raw == raw_json

    def test_soar_requires_analyst_approval_always_true(self):
        response = dict(_VALID_RESPONSE)
        response["soar_recommendation"] = {
            "recommended": True,
            "action": "block_ip",
            "requires_analyst_approval": False,  # Gemini incorrectly says False
            "reason": "Dangerous IP",
        }
        raw_json = json.dumps(response)
        mock_resp = _make_mock_response(200, _gemini_body(raw_json))

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_resp)
        mock_ctx = MagicMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_client)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)

        with patch.dict(os.environ, {"GEMINI_API_KEY": "test-key"}):
            with patch("app.ai_triage.providers.gemini_provider.httpx.AsyncClient", return_value=mock_ctx):
                provider = GeminiProvider()
                result, _ = _run(provider.run_triage("test prompt"))

        assert result.soar_recommendation.requires_analyst_approval is True


class TestGeminiProviderErrors:
    def test_missing_api_key_raises_runtime_error(self):
        with patch.dict(os.environ, {"GEMINI_API_KEY": ""}):
            provider = GeminiProvider()
        with pytest.raises(RuntimeError, match="not configured"):
            _run(provider.run_triage("test prompt"))

    def test_api_key_not_in_runtime_error_message(self):
        with patch.dict(os.environ, {"GEMINI_API_KEY": ""}):
            provider = GeminiProvider()
        try:
            _run(provider.run_triage("test prompt"))
        except RuntimeError as exc:
            assert "test-key" not in str(exc)

    def test_timeout_raises_httpx_timeout(self):
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(side_effect=httpx.TimeoutException("timed out"))
        mock_ctx = MagicMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_client)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)

        with patch.dict(os.environ, {"GEMINI_API_KEY": "test-key"}):
            with patch("app.ai_triage.providers.gemini_provider.httpx.AsyncClient", return_value=mock_ctx):
                provider = GeminiProvider()
                with pytest.raises(httpx.TimeoutException):
                    _run(provider.run_triage("test prompt"))

    def test_non_200_raises_runtime_error(self):
        mock_resp = _make_mock_response(500, {})
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_resp)
        mock_ctx = MagicMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_client)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)

        with patch.dict(os.environ, {"GEMINI_API_KEY": "test-key"}):
            with patch("app.ai_triage.providers.gemini_provider.httpx.AsyncClient", return_value=mock_ctx):
                provider = GeminiProvider()
                with pytest.raises(RuntimeError, match="500"):
                    _run(provider.run_triage("test prompt"))

    def test_non_200_error_message_excludes_api_key(self):
        mock_resp = _make_mock_response(403, {})
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_resp)
        mock_ctx = MagicMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_client)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)

        with patch.dict(os.environ, {"GEMINI_API_KEY": "super-secret-key"}):
            with patch("app.ai_triage.providers.gemini_provider.httpx.AsyncClient", return_value=mock_ctx):
                provider = GeminiProvider()
                try:
                    _run(provider.run_triage("test prompt"))
                except RuntimeError as exc:
                    assert "super-secret-key" not in str(exc)

    def test_invalid_json_raises_value_error(self):
        provider = GeminiProvider.__new__(GeminiProvider)
        provider._api_key = "test-key"
        provider._model = "gemini-2.5-flash"
        provider._timeout = 20
        with pytest.raises(ValueError, match="non-JSON"):
            provider._parse_and_validate("not valid json {{{")

    def test_schema_mismatch_raises_value_error(self):
        provider = GeminiProvider.__new__(GeminiProvider)
        provider._api_key = "test-key"
        provider._model = "gemini-2.5-flash"
        provider._timeout = 20
        incomplete = json.dumps({"priority": "high"})  # missing required fields
        with pytest.raises(ValueError, match="schema"):
            provider._parse_and_validate(incomplete)

    def test_invalid_priority_raises_value_error(self):
        provider = GeminiProvider.__new__(GeminiProvider)
        provider._api_key = "test-key"
        provider._model = "gemini-2.5-flash"
        provider._timeout = 20
        bad = dict(_VALID_RESPONSE, priority="extreme")
        with pytest.raises(ValueError, match="priority"):
            provider._parse_and_validate(json.dumps(bad))

    def test_invalid_confidence_raises_value_error(self):
        provider = GeminiProvider.__new__(GeminiProvider)
        provider._api_key = "test-key"
        provider._model = "gemini-2.5-flash"
        provider._timeout = 20
        bad = dict(_VALID_RESPONSE, confidence="very_high")
        with pytest.raises(ValueError, match="confidence"):
            provider._parse_and_validate(json.dumps(bad))

    def test_invalid_fp_likelihood_raises_value_error(self):
        provider = GeminiProvider.__new__(GeminiProvider)
        provider._api_key = "test-key"
        provider._model = "gemini-2.5-flash"
        provider._timeout = 20
        bad = dict(_VALID_RESPONSE, false_positive_likelihood="never")
        with pytest.raises(ValueError, match="false_positive_likelihood"):
            provider._parse_and_validate(json.dumps(bad))
