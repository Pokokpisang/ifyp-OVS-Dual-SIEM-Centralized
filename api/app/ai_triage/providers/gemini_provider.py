import json
import logging
import os

import httpx
from pydantic import ValidationError

from ..schemas import AITriageResult, SOARRecommendationOut
from .base import BaseTriageProvider

logger = logging.getLogger("ai_triage.gemini")

_GEMINI_BASE = "https://generativelanguage.googleapis.com/v1beta/models"

_VALID_PRIORITIES  = {"low", "medium", "high", "critical"}
_VALID_CONFIDENCES = {"low", "medium", "high"}
_VALID_FP          = {"unlikely", "possible", "likely"}


class GeminiProvider(BaseTriageProvider):

    def __init__(self):
        self._api_key  = os.getenv("GEMINI_API_KEY", "")
        self._model    = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
        self._timeout  = int(os.getenv("AI_TRIAGE_TIMEOUT_SECONDS", "20"))

    @property
    def provider_name(self) -> str:
        return "gemini"

    @property
    def model_name(self) -> str:
        return self._model

    async def run_triage(self, prompt: str) -> tuple[AITriageResult, str]:
        """
        Call Gemini generateContent and return (AITriageResult, raw_json_string).

        Raises:
            RuntimeError  — API key not configured
            httpx.TimeoutException — request timed out (re-raised for service layer)
            ValueError    — response JSON does not match expected schema or enum values
            RuntimeError  — Gemini returned a non-2xx status (safe message, no body leaked)
        """
        if not self._api_key:
            raise RuntimeError("Gemini API key is not configured.")

        url = f"{_GEMINI_BASE}/{self._model}:generateContent"
        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {
                "response_mime_type": "application/json",
                "temperature": 0.1,
            },
        }

        logger.info("ai_triage provider=gemini model=%s sending request", self._model)

        async with httpx.AsyncClient(timeout=self._timeout) as client:
            # API key is a query param — httpx builds the URL internally; we never log it
            resp = await client.post(url, json=payload, params={"key": self._api_key})

        if resp.status_code != 200:
            logger.error(
                "ai_triage provider=gemini status=%d (response body not logged)",
                resp.status_code,
            )
            raise RuntimeError(
                f"Gemini API returned status {resp.status_code}. Please try again later."
            )

        try:
            raw_text = resp.json()["candidates"][0]["content"]["parts"][0]["text"]
        except (KeyError, IndexError, json.JSONDecodeError) as exc:
            raise ValueError(f"Unexpected Gemini response structure: {exc}") from exc

        return self._parse_and_validate(raw_text)

    def _parse_and_validate(self, raw_text: str) -> tuple[AITriageResult, str]:
        try:
            parsed = json.loads(raw_text)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Gemini returned non-JSON output: {exc}") from exc

        try:
            result = AITriageResult(**parsed)
        except (ValidationError, TypeError) as exc:
            raise ValueError(f"AI output did not match expected schema: {exc}") from exc

        # Second-layer enum whitelist — defence against schema bypass
        if result.priority not in _VALID_PRIORITIES:
            raise ValueError(f"AI returned unsupported priority value: {result.priority!r}")
        if result.confidence not in _VALID_CONFIDENCES:
            raise ValueError(f"AI returned unsupported confidence value: {result.confidence!r}")
        if result.false_positive_likelihood not in _VALID_FP:
            raise ValueError(
                f"AI returned unsupported false_positive_likelihood value: "
                f"{result.false_positive_likelihood!r}"
            )

        # Safety override: SOAR approval must always be required
        if result.soar_recommendation is not None:
            result.soar_recommendation.requires_analyst_approval = True

        logger.info("ai_triage provider=gemini status=success priority=%s", result.priority)
        return result, raw_text
