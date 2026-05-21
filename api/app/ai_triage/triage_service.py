import json
import logging
import os

import httpx
from fastapi import HTTPException
from sqlalchemy.orm import Session

from .. import models
from .prompt_builder import build_prompt
from .providers.gemini_provider import GeminiProvider
from .schemas import AITriageResult

logger = logging.getLogger("ai_triage.service")

_AI_TRIAGE_ENABLED   = lambda: os.getenv("AI_TRIAGE_ENABLED", "false").lower() == "true"
_AI_TRIAGE_STORE_RAW = lambda: os.getenv("AI_TRIAGE_STORE_RAW_OUTPUT", "true").lower() == "true"


def _persist(db: Session, **kwargs) -> models.AIAlertTriage:
    row = models.AIAlertTriage(**kwargs)
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


async def run_triage_for_alert(alert_id: int, db: Session) -> models.AIAlertTriage:
    alert = db.query(models.Alert).filter(models.Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    assessment = (
        db.query(models.AlertAssessment)
        .filter(models.AlertAssessment.alert_id == alert_id)
        .first()
    )

    provider = GeminiProvider()
    base = dict(
        alert_id=alert_id,
        provider=provider.provider_name,
        model_name=provider.model_name,
    )

    if not _AI_TRIAGE_ENABLED():
        return _persist(db, **base, triage_status="disabled",
                        error_message="AI triage is disabled (AI_TRIAGE_ENABLED != true).")

    if not provider._api_key:
        return _persist(db, **base, triage_status="config_error",
                        error_message="Gemini API key is not configured.")

    prompt, input_ctx = build_prompt(alert, assessment)
    input_ctx_json = json.dumps(input_ctx)

    triage_status = "success"
    result: AITriageResult | None = None
    raw_output: str | None = None
    error_message: str | None = None

    try:
        result, raw_output = await provider.run_triage(prompt)
    except httpx.TimeoutException:
        triage_status = "failed"
        error_message = "AI triage request timed out. Please try again later."
        logger.warning("ai_triage alert_id=%d status=timeout", alert_id)
    except ValueError as exc:
        triage_status = "invalid_output"
        error_message = str(exc)
        logger.warning("ai_triage alert_id=%d status=invalid_output error=%s", alert_id, exc)
    except Exception as exc:
        triage_status = "failed"
        error_message = str(exc)
        logger.error("ai_triage alert_id=%d status=failed", alert_id, exc_info=False)

    return _persist(
        db,
        **base,
        triage_status=triage_status,
        summary=result.summary if result else None,
        priority=result.priority if result else None,
        confidence=result.confidence if result else None,
        false_positive_likelihood=result.false_positive_likelihood if result else None,
        key_reasons_json=json.dumps(result.key_reasons) if result else None,
        recommended_next_steps_json=json.dumps(result.recommended_next_steps) if result else None,
        soar_recommendation_json=(
            json.dumps(result.soar_recommendation.model_dump())
            if result and result.soar_recommendation else None
        ),
        input_context_json=input_ctx_json,
        raw_output_json=raw_output if _AI_TRIAGE_STORE_RAW() else None,
        error_message=error_message,
    )
