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
import re
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

from fastapi import Request
from sqlalchemy import desc, false, func, or_
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
SYSTEM_CONFIG_CHANGED = "SYSTEM_CONFIG_CHANGED"
NOTIFICATION_CHANNEL_CREATED = "NOTIFICATION_CHANNEL_CREATED"
NOTIFICATION_CHANNEL_UPDATED = "NOTIFICATION_CHANNEL_UPDATED"
NOTIFICATION_CHANNEL_DELETED = "NOTIFICATION_CHANNEL_DELETED"
NOTIFICATION_TEST_SENT = "NOTIFICATION_TEST_SENT"
USER_CREATED = "USER_CREATED"
USER_UPDATED = "USER_UPDATED"
USER_DELETED = "USER_DELETED"

# Category shown in the Audit Trail UI, keyed by action.
ACTION_CATEGORIES: Dict[str, str] = {
    LOGIN_SUCCESS: "Authentication",
    LOGIN_FAILURE: "Authentication",
    LOGOUT: "Authentication",
    SOAR_RUN: "SOAR",
    SOAR_APPROVE: "SOAR",
    SOAR_REJECT: "SOAR",
    ALERT_STATUS_CHANGED: "Alert",
    AGENT_REGISTERED: "Agent",
    AGENT_KEY_ROTATED: "Agent",
    AI_TRIAGE_REQUESTED: "AI Triage",
    SYSTEM_CONFIG_CHANGED: "System",
    NOTIFICATION_CHANNEL_CREATED: "System",
    NOTIFICATION_CHANNEL_UPDATED: "System",
    NOTIFICATION_CHANNEL_DELETED: "System",
    NOTIFICATION_TEST_SENT: "System",
    USER_CREATED: "System",
    USER_UPDATED: "System",
    USER_DELETED: "System",
}

# Actions whose records reference secret material (rendered with a
# "sensitive" badge in the UI; the secret itself is never stored).
SENSITIVE_ACTIONS = {AGENT_KEY_ROTATED, AGENT_REGISTERED}

_MAX_VALUE_LEN = 256

# Backstop scrubbing: any detail key containing one of these word segments
# (split on non-alphanumerics: "new_key" → {"new","key"}) has its value
# replaced by the redaction marker. Callers must still not pass secrets.
REDACTED = "__SENSITIVE__"
_SENSITIVE_KEY_SEGMENTS = {"key", "token", "secret", "password", "passwd", "cookie", "authorization", "session", "credential", "credentials"}


def client_ip(request: Optional[Request]) -> Optional[str]:
    """Best-effort requester IP for audit rows."""
    client = getattr(request, "client", None)
    return client.host if client else None


def _bounded(value: Any) -> Any:
    """Stringify + truncate long string values; pass through non-strings/None."""
    if isinstance(value, str) and len(value) > _MAX_VALUE_LEN:
        return value[:_MAX_VALUE_LEN] + "…"
    return value


def _scrub(key: str, value: Any) -> Any:
    segments = re.split(r"[^a-z0-9]+", key.lower())
    if any(seg in _SENSITIVE_KEY_SEGMENTS for seg in segments):
        return REDACTED
    return _bounded(value)


def _sanitize_details(details: Optional[Dict[str, Any]]) -> Optional[str]:
    if not details:
        return None
    return json.dumps({k: _scrub(k, v) for k, v in details.items()})


def record_audit_event(
    db: Session,
    *,
    actor: Optional[str],
    action: str,
    object_type: Optional[str] = None,
    object_id: Optional[Any] = None,
    details: Optional[Dict[str, Any]] = None,
    source_ip: Optional[str] = None,
    commit: bool = False,
) -> models.ActivityAudit:
    """Append one ActivityAudit row.

    ``details`` (a dict of already-secret-free values) is JSON-encoded into the
    Text column. ``object_id`` is stringified. The Session is never created here.
    ``source_ip`` is the requester IP (``client_ip(request)``) or ``"system"``
    for automation-originated events.
    """
    row = models.ActivityAudit(
        actor=_bounded(actor) if actor else "unknown",
        action=action,
        object_type=object_type,
        object_id=str(object_id) if object_id is not None else None,
        source_ip=source_ip,
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


def _read_scrub_details(raw: Optional[str]) -> List[List[str]]:
    """Decode a stored details blob into ordered [key, value] pairs, re-applying
    the key scrub as a backstop for rows written before scrubbing existed."""
    if not raw:
        return []
    try:
        decoded = json.loads(raw)
    except (ValueError, TypeError):
        return [["details", str(_bounded(raw))]]
    if not isinstance(decoded, dict):
        return [["details", str(_bounded(decoded))]]
    return [[k, "" if v is None else str(_scrub(k, v))] for k, v in decoded.items()]


def _derive_result(action: str, details: Dict[str, str]) -> Tuple[str, str]:
    """(label, tone) for the UI Result badge. Tones: ok | info | high | crit | muted."""
    if action == LOGIN_FAILURE:
        return "Failed", "crit"
    if action in (LOGIN_SUCCESS, LOGOUT):
        return "Success", "ok"
    if action == SOAR_RUN:
        return ("Queued", "high") if details.get("status") == "pending_approval" else ("Executed", "ok")
    if action == SOAR_APPROVE:
        return "Approved", "ok"
    if action == SOAR_REJECT:
        return "Rejected", "crit"
    if action == ALERT_STATUS_CHANGED:
        return "Updated", "info"
    if action == AGENT_REGISTERED:
        return "Registered", "ok"
    if action == AGENT_KEY_ROTATED:
        return "Rotated", "info"
    if action == AI_TRIAGE_REQUESTED:
        status = details.get("triage_status", "")
        if status in ("ok", "completed"):
            return "Completed", "ok"
        if status in ("error", "config_error", "disabled"):
            return "Failed", "crit"
        return "Queued", "high"
    if action == SYSTEM_CONFIG_CHANGED:
        return "Updated", "info"
    if action == NOTIFICATION_CHANNEL_CREATED:
        return "Created", "ok"
    if action == NOTIFICATION_CHANNEL_UPDATED:
        return "Updated", "info"
    if action == NOTIFICATION_CHANNEL_DELETED:
        return "Removed", "muted"
    if action == NOTIFICATION_TEST_SENT:
        return ("Success", "ok") if details.get("status") == "sent" else ("Failed", "crit")
    if action == USER_CREATED:
        return "Created", "ok"
    if action == USER_UPDATED:
        return "Updated", "info"
    if action == USER_DELETED:
        return "Removed", "muted"
    return "Recorded", "muted"


def event_to_dict(row: models.ActivityAudit) -> Dict[str, Any]:
    """Serialize one audit row for the UI/export, with read-side redaction."""
    details = _read_scrub_details(row.details)
    details_map = dict(details)
    result, result_tone = _derive_result(row.action, details_map)
    return {
        "id": row.id,
        "timestamp_utc": row.timestamp_utc.strftime("%Y-%m-%d %H:%M:%S") if row.timestamp_utc else None,
        "actor": row.actor,
        "action": row.action,
        "category": ACTION_CATEGORIES.get(row.action, "System"),
        "object_type": row.object_type,
        "object_id": row.object_id,
        "source_ip": row.source_ip,
        "result": result,
        "result_tone": result_tone,
        "sensitive": row.action in SENSITIVE_ACTIONS or any(v == REDACTED for _, v in details),
        "details": details,
    }


def _apply_filters(
    query,
    *,
    category: Optional[str] = None,
    actor: Optional[str] = None,
    object_type: Optional[str] = None,
    object_id: Optional[str] = None,
    q: Optional[str] = None,
    since: Optional[datetime] = None,
):
    A = models.ActivityAudit
    if category:
        actions = [a for a, c in ACTION_CATEGORIES.items() if c == category]
        query = query.filter(A.action.in_(actions)) if actions else query.filter(false())
    if actor:
        query = query.filter(A.actor == actor)
    if object_type:
        query = query.filter(A.object_type == object_type)
    if object_id:
        query = query.filter(A.object_id.ilike(f"%{object_id}%"))
    if q:
        like = f"%{q}%"
        query = query.filter(or_(
            A.actor.ilike(like), A.action.ilike(like), A.object_type.ilike(like),
            A.object_id.ilike(like), A.details.ilike(like), A.source_ip.ilike(like),
        ))
    if since:
        query = query.filter(A.timestamp_utc >= since)
    return query


def range_to_since(range_key: Optional[str]) -> Optional[datetime]:
    """Map the UI date-range key to a cutoff datetime (None = all time)."""
    hours = {"24h": 24, "7d": 24 * 7, "30d": 24 * 30}.get(range_key or "")
    return datetime.utcnow() - timedelta(hours=hours) if hours else None


def query_audit_events(
    db: Session,
    *,
    page: int = 1,
    page_size: int = 12,
    **filters,
) -> Tuple[List[models.ActivityAudit], int]:
    """Server-side filtered + paginated audit rows (newest first) and total count."""
    A = models.ActivityAudit
    base = _apply_filters(db.query(A), **filters)
    total = base.with_entities(func.count(A.id)).scalar() or 0
    page = max(page, 1)
    rows = (
        base.order_by(desc(A.timestamp_utc), desc(A.id))
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    return rows, total


def summarize_audit_events(db: Session, *, since: Optional[datetime] = None) -> Dict[str, int]:
    """Aggregate counts for the Audit Trail KPI row."""
    A = models.ActivityAudit

    def _count(*actions: str) -> int:
        q = db.query(func.count(A.id)).filter(A.action.in_(actions))
        if since:
            q = q.filter(A.timestamp_utc >= since)
        return q.scalar() or 0

    q_total = db.query(func.count(A.id))
    if since:
        q_total = q_total.filter(A.timestamp_utc >= since)
    return {
        "total_events": q_total.scalar() or 0,
        "failed_logins": _count(LOGIN_FAILURE),
        "soar_actions": _count(SOAR_RUN, SOAR_APPROVE, SOAR_REJECT),
        "agent_changes": _count(AGENT_REGISTERED, AGENT_KEY_ROTATED),
        "alert_status_changes": _count(ALERT_STATUS_CHANGED),
        "ai_triage_requests": _count(AI_TRIAGE_REQUESTED),
    }


def list_distinct_actors(db: Session) -> List[str]:
    rows = db.query(models.ActivityAudit.actor).distinct().order_by(models.ActivityAudit.actor).all()
    return [r[0] for r in rows if r[0]]
