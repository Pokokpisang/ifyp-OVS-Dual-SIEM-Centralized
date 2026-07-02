"""
audit_service — the single place that records security-relevant actions taken
*inside* the platform (who did what, when).

Rows are appended to the existing ``models.ActivityAudit`` table. Its ``details``
column is Text (NOT a SQLAlchemy JSON type), so dict details are ``json.dumps``-
encoded here and ``json.loads``-decoded on read.

Callers must pass secret-free details (no passwords, tokens, cookies, CSRF
tokens, API/agent/provider keys). This helper additionally truncates long string
values as a backstop, but it does not attempt to detect or scrub secrets.

The helper never creates a Session — the caller owns the transaction. Use
``commit=False`` (default) to fold the audit row into the caller's existing
commit; use ``commit=True`` only for standalone route events with no pending
commit of their own.
"""
import json
import logging
from typing import Any, Dict, List, Optional

from sqlalchemy import desc
from sqlalchemy.orm import Session

from .. import models

logger = logging.getLogger("services.audit")

# ---------------------------------------------------------------------------
# Action names (stable strings stored in the DB)
# ---------------------------------------------------------------------------
SOAR_APPROVE = "SOAR_APPROVE"
SOAR_REJECT = "SOAR_REJECT"
SOAR_RUN = "SOAR_RUN"
ALERT_STATUS_CHANGED = "ALERT_STATUS_CHANGED"
LOGIN_SUCCESS = "LOGIN_SUCCESS"
LOGIN_FAILURE = "LOGIN_FAILURE"
LOGOUT = "LOGOUT"
AGENT_REGISTERED = "AGENT_REGISTERED"
AGENT_KEY_ROTATED = "AGENT_KEY_ROTATED"
AI_TRIAGE_REQUESTED = "AI_TRIAGE_REQUESTED"

_MAX_VALUE_LEN = 256


def _bounded(value: Any) -> Any:
    """Stringify + truncate long string values; pass through non-strings/None."""
    if isinstance(value, str) and len(value) > _MAX_VALUE_LEN:
        return value[:_MAX_VALUE_LEN] + "…"
    return value


def _sanitize_details(details: Optional[Dict[str, Any]]) -> Optional[str]:
    if not details:
        return None
    bounded = {k: _bounded(v) for k, v in details.items()}
    return json.dumps(bounded)


def record_audit_event(
    db: Session,
    *,
    actor: Optional[str],
    action: str,
    object_type: Optional[str] = None,
    object_id: Optional[Any] = None,
    details: Optional[Dict[str, Any]] = None,
    commit: bool = False,
) -> models.ActivityAudit:
    """Append one ActivityAudit row.

    ``details`` (a dict of already-secret-free values) is JSON-encoded into the
    Text column. ``object_id`` is stringified. The Session is never created here.
    """
    row = models.ActivityAudit(
        actor=_bounded(actor) if actor else "unknown",
        action=action,
        object_type=object_type,
        object_id=str(object_id) if object_id is not None else None,
        details=_sanitize_details(details),
    )
    db.add(row)
    if commit:
        db.commit()
    logger.info("[AUDIT] %s actor=%s object=%s/%s", action, row.actor, object_type, row.object_id)
    return row


def list_audit_events(
    db: Session,
    *,
    limit: int = 100,
    actor: Optional[str] = None,
    action: Optional[str] = None,
    object_type: Optional[str] = None,
    object_id: Optional[Any] = None,
) -> List[models.ActivityAudit]:
    """Return recent audit rows (newest first), optionally filtered. Read-only."""
    query = db.query(models.ActivityAudit)
    if actor is not None:
        query = query.filter(models.ActivityAudit.actor == actor)
    if action is not None:
        query = query.filter(models.ActivityAudit.action == action)
    if object_type is not None:
        query = query.filter(models.ActivityAudit.object_type == object_type)
    if object_id is not None:
        query = query.filter(models.ActivityAudit.object_id == str(object_id))
    return query.order_by(desc(models.ActivityAudit.timestamp_utc)).limit(limit).all()
