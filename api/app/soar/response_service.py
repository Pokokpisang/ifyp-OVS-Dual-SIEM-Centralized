from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import Any, Dict, List

from fastapi import HTTPException
from sqlalchemy.orm import Session

from .. import models
from .action_executor import execute_action
from .playbook_loader import PlaybookLoader
from .playbook_matcher import _build_alert_context, match
from .schemas import SOARExecutionResult, SOARRecommendation

logger = logging.getLogger("soar.response_service")


def get_recommendations(alert_id: int, db: Session) -> List[SOARRecommendation]:
    alert = db.query(models.Alert).filter(models.Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert #{alert_id} not found")
    playbooks = PlaybookLoader().load_all_playbooks()
    return match(alert, playbooks)


def run_action(
    alert_id: int,
    playbook_id: str,
    action_id: str,
    db: Session,
    executed_by: str = "analyst",
) -> SOARExecutionResult:
    alert = db.query(models.Alert).filter(models.Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert #{alert_id} not found")

    loader = PlaybookLoader()
    playbooks = loader.load_all_playbooks()

    playbook = next((p for p in playbooks if p.id == playbook_id), None)
    if playbook is None:
        raise HTTPException(
            status_code=404,
            detail=f"Playbook '{playbook_id}' not found or is disabled",
        )

    action = next((a for a in playbook.actions if a.id == action_id), None)
    if action is None:
        raise HTTPException(
            status_code=404,
            detail=f"Action '{action_id}' not found in playbook '{playbook_id}'",
        )

    ctx = _build_alert_context(alert)

    recommendations = match(alert, [playbook])
    if not recommendations:
        raise HTTPException(
            status_code=422,
            detail="Playbook conditions no longer match this alert. Action was not executed.",
        )

    result = execute_action(ctx, playbook, action)

    exec_record = models.SOARActionExecution(
        alert_id=alert_id,
        playbook_id=playbook.id,
        playbook_name=playbook.name,
        action_id=action.id,
        action_name=action.name,
        action_type=action.type,
        target=result.target,
        mode=action.mode,
        status="success" if result.success else "failed",
        executed_by=executed_by,
        executed_at=datetime.utcnow(),
        result_message=result.message,
        error_message=result.error,
        rollback_supported=action.rollback_supported,
        rollback_status=None,
        exec_metadata=json.dumps({"match_reasons": [r.match_reasons for r in recommendations]}),
    )
    db.add(exec_record)
    db.commit()

    return result


def get_history(alert_id: int, db: Session) -> List[Dict[str, Any]]:
    rows = (
        db.query(models.SOARActionExecution)
        .filter(models.SOARActionExecution.alert_id == alert_id)
        .order_by(models.SOARActionExecution.executed_at.desc())
        .all()
    )
    return [_row_to_dict(r) for r in rows]


def auto_run_for_alert(
    alert_id: int,
    db: Session,
    executed_by: str = "system:auto",
) -> Dict[str, Any]:
    from ..services.settings_service import get_soar_execution_mode

    mode = get_soar_execution_mode(db)
    if mode != "automatic":
        logger.info(
            f"[SOAR_AUTO] Skipped for alert #{alert_id} — SOAR mode is '{mode}' (not automatic)"
        )
        return {"mode": mode, "executed_count": 0, "skipped_count": 0, "results": []}

    logger.info(f"[SOAR_AUTO] Starting auto-run for alert #{alert_id}")

    try:
        recs = get_recommendations(alert_id, db)
    except Exception as exc:
        logger.error(f"[SOAR_AUTO] Failed to load recommendations for alert #{alert_id}: {exc}", exc_info=True)
        return {"mode": mode, "executed_count": 0, "skipped_count": 0, "results": []}

    executed, skipped, results = 0, 0, []

    for rec in recs:
        action = rec.action

        if action.mode != "simulation":
            logger.debug(f"[SOAR_AUTO] Skipping action '{action.id}' — mode is '{action.mode}' (not simulation)")
            skipped += 1
            continue
        if action.requires_approval:
            logger.debug(f"[SOAR_AUTO] Skipping action '{action.id}' — requires_approval=True")
            skipped += 1
            continue
        if not action.automation.auto_run_allowed:
            logger.debug(f"[SOAR_AUTO] Skipping action '{action.id}' — auto_run_allowed=False")
            skipped += 1
            continue

        already_run = (
            db.query(models.SOARActionExecution)
            .filter_by(
                alert_id=alert_id,
                playbook_id=rec.playbook_id,
                action_id=action.id,
                target=rec.resolved_target,
                status="success",
            )
            .first()
        )
        if already_run:
            logger.info(
                f"[SOAR_AUTO] Skipping action '{action.id}' for alert #{alert_id} "
                f"(playbook={rec.playbook_id}) — duplicate execution already exists"
            )
            skipped += 1
            continue

        try:
            result = run_action(alert_id, rec.playbook_id, action.id, db, executed_by)
            results.append(result.model_dump())
            executed += 1
            logger.info(
                f"[SOAR_AUTO] Completed action '{action.id}' for alert #{alert_id} "
                f"(playbook={rec.playbook_id}, success={result.success})"
            )
        except Exception as exc:
            skipped += 1
            logger.error(
                f"[SOAR_AUTO] Action '{action.id}' failed for alert #{alert_id} "
                f"(playbook={rec.playbook_id}): {exc}",
                exc_info=True,
            )
            results.append({
                "playbook_id": rec.playbook_id,
                "action_id": action.id,
                "success": False,
                "error": str(exc),
            })

    logger.info(
        f"[SOAR_AUTO] Finished for alert #{alert_id} — "
        f"executed={executed}, skipped={skipped}"
    )
    return {
        "mode": "automatic",
        "executed_count": executed,
        "skipped_count": skipped,
        "results": results,
    }


def _row_to_dict(r: models.SOARActionExecution) -> Dict[str, Any]:
    return {
        "id": r.id,
        "alert_id": r.alert_id,
        "playbook_id": r.playbook_id,
        "playbook_name": r.playbook_name,
        "action_id": r.action_id,
        "action_name": r.action_name,
        "action_type": r.action_type,
        "target": r.target,
        "mode": r.mode,
        "status": r.status,
        "executed_by": r.executed_by,
        "executed_at": r.executed_at.strftime("%Y-%m-%d %H:%M:%S") if r.executed_at else None,
        "result_message": r.result_message,
        "error_message": r.error_message,
        "rollback_supported": r.rollback_supported,
        "rollback_status": r.rollback_status,
    }
