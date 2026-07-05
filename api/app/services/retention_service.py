"""
retention_service — enforce the data-retention policy that was previously
configuration-only (LOG_RETENTION_DAYS / METRICS_RETENTION_DAYS documented
since v2.9 but never enforced; the Settings page said so honestly).

Policy:
- Logs older than LOG_RETENTION_DAYS and metrics older than
  METRICS_RETENTION_DAYS are deleted by a periodic background sweep
  (main.py, RETENTION_SWEEP_SECONDS, default hourly).
- An unset/blank/invalid/zero value means UNLIMITED retention for that
  data class — the sweep never deletes by surprise.
- Alerts, audit events, and SOAR history are deliberately NOT covered:
  they are the security record.
- A sweep that actually deletes rows writes one audit event with the
  counts (compliance evidence); no-op sweeps stay out of the audit trail.
"""
import logging
import os
from datetime import datetime, timedelta
from typing import Optional

from sqlalchemy.orm import Session

from .. import models
from . import audit_service

logger = logging.getLogger("services.retention")


def _days_from_env(var: str) -> Optional[int]:
    """Retention days for *var*, or None for unlimited (unset/invalid/<=0)."""
    raw = os.getenv(var, "").strip()
    try:
        days = int(raw)
    except ValueError:
        if raw:
            logger.warning("[RETENTION] Ignoring invalid %s=%r", var, raw)
        return None
    return days if days > 0 else None


def get_retention_policy() -> dict:
    """Current policy as shown on the Settings page."""
    return {
        "log_days": _days_from_env("LOG_RETENTION_DAYS"),
        "metrics_days": _days_from_env("METRICS_RETENTION_DAYS"),
    }


def run_retention_sweep(db: Session) -> dict:
    """Delete rows past their retention windows. Returns deletion counts."""
    policy = get_retention_policy()
    now = datetime.utcnow()
    deleted = {"logs": 0, "metrics": 0}

    if policy["log_days"] is not None:
        cutoff = now - timedelta(days=policy["log_days"])
        deleted["logs"] = (
            db.query(models.Log)
            .filter(models.Log.timestamp < cutoff)
            .delete(synchronize_session=False)
        )

    if policy["metrics_days"] is not None:
        cutoff = now - timedelta(days=policy["metrics_days"])
        deleted["metrics"] = (
            db.query(models.Metric)
            .filter(models.Metric.timestamp < cutoff)
            .delete(synchronize_session=False)
        )

    if deleted["logs"] or deleted["metrics"]:
        audit_service.record_audit_event(
            db,
            actor="system:retention",
            action=audit_service.DATA_RETENTION_APPLIED,
            object_type="system",
            object_id="retention_sweep",
            source_ip="system",
            details={
                "logs_deleted": deleted["logs"],
                "metrics_deleted": deleted["metrics"],
                "log_retention_days": policy["log_days"] or "unlimited",
                "metrics_retention_days": policy["metrics_days"] or "unlimited",
            },
        )
        logger.info("[RETENTION] Deleted %d logs, %d metrics", deleted["logs"], deleted["metrics"])
    db.commit()
    return deleted
