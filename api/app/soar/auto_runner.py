from __future__ import annotations

import logging

from sqlalchemy.orm import Session

logger = logging.getLogger("soar.auto_runner")


def trigger_soar_auto_run_for_alert(alert_id: int, db: Session) -> None:
    """
    Safe, fire-and-forget wrapper called immediately after a new Alert row is
    committed by any detection engine.

    Delegates to auto_run_for_alert() in response_service.  All exceptions are
    caught here so that a SOAR failure never propagates to the caller and never
    causes the originating request to fail.
    """
    logger.info(f"[SOAR_AUTO] Triggered for alert #{alert_id}")
    try:
        from .response_service import auto_run_for_alert
        auto_run_for_alert(alert_id, db, executed_by="system:auto")
    except Exception as exc:
        logger.error(
            f"[SOAR_AUTO] Unhandled error during auto-run for alert #{alert_id}: {exc}",
            exc_info=True,
        )
